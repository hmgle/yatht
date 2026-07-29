from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("tcp_broker_benchmark.py")
SPEC = importlib.util.spec_from_file_location("tcp_broker_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def test_parse_jsonl_preserves_valid_events_and_reports_bad_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.jsonl"
            path.write_bytes(b'{"event":"run_start"}\n{"event":\n\xff\n')

            events, errors = benchmark.parse_jsonl(path)

        self.assertEqual(events, [{"event": "run_start"}])
        self.assertEqual([error["line"] for error in errors], [2, 3])

    def test_streaming_metric_parser_keeps_only_run_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.jsonl"
            path.write_bytes(
                b'{"event":"tcp_setup","outcome":"completed"}\n'
                b'{"event":"run_summary","tcp_active_flows":0}\n'
                b'{"event":\n'
            )

            summaries, errors = benchmark.parse_run_summaries_streaming(path)

        self.assertEqual(
            summaries, [{"event": "run_summary", "tcp_active_flows": 0}]
        )
        self.assertEqual(len(errors), 1)

    def test_tcp_setup_stage_summary_aggregates_completed_flows(self) -> None:
        def completed(index: int) -> dict[str, object]:
            return {
                "event": "tcp_setup",
                "outcome": "completed",
                "queue_wait_ns": 10 * index,
                "handler_ns": 100 * index + 30,
                "fd_inspection_ns": 1,
                "proxy_connect_ns": 2,
                "proxy_handshake_ns": 100 * index,
                "loopback_connect_accept_ns": 5,
                "broker_register_ns": 1,
                "notification_reply_ns": 1,
            }

        events = [
            {"event": "run_start"},
            *[completed(index) for index in range(1, 5)],
            {
                "event": "tcp_setup",
                "outcome": "failed",
                "failure_stage": "proxy_connect",
                "queue_wait_ns": 7,
                "handler_ns": 9,
                "fd_inspection_ns": 1,
                "proxy_connect_ns": None,
                "proxy_handshake_ns": None,
                "loopback_connect_accept_ns": None,
                "broker_register_ns": None,
                "notification_reply_ns": None,
            },
        ]

        summary = benchmark.summarize_tcp_setup_stages(events)

        assert summary is not None
        self.assertEqual(summary["setup_events"], 5)
        self.assertEqual(summary["completed_events"], 4)
        self.assertEqual(summary["failure_stage_counts"], {"proxy_connect": 1})
        self.assertEqual(summary["total"]["sum_ns"], 1220)
        self.assertEqual(summary["handler"]["sum_ns"], 1120)
        handshake = summary["stages"]["proxy_handshake"]
        self.assertEqual(handshake["sum_ns"], 1000)
        self.assertEqual(handshake["mean_ns"], 250)
        self.assertEqual(handshake["p50_ns"], 200)
        self.assertEqual(handshake["p99_ns"], 400)
        self.assertEqual(handshake["max_ns"], 400)
        self.assertEqual(summary["stages"]["queue_wait"]["share_of_total"], 100 / 1220)
        residual = summary["stages"]["handler_residual"]
        self.assertEqual(residual["sum_ns"], 80)
        self.assertEqual(residual["mean_ns"], 20)
        share_total = sum(
            stage["share_of_total"] for stage in summary["stages"].values()
        )
        self.assertAlmostEqual(share_total, 1.0)

    def test_tcp_setup_stage_summary_without_setup_events_is_none(self) -> None:
        self.assertIsNone(
            benchmark.summarize_tcp_setup_stages([{"event": "run_start"}])
        )

    def test_tcp_setup_stage_summary_counts_failures_without_completed_flows(self) -> None:
        summary = benchmark.summarize_tcp_setup_stages(
            [{"event": "tcp_setup", "outcome": "cancelled", "failure_stage": None}]
        )

        self.assertEqual(
            summary,
            {
                "setup_events": 1,
                "completed_events": 0,
                "failure_stage_counts": {"unknown": 1},
            },
        )

    def test_summary_excludes_flows_from_failed_parent_run(self) -> None:
        runs = [
            {
                "scenario": "request",
                "variant": "stable",
                "measurement_kind": "measurement",
                "repetition": 0,
                "ok": False,
                "wall_ns": 10,
                "successful_flows": 1,
            },
            {
                "scenario": "request",
                "variant": "stable",
                "measurement_kind": "measurement",
                "repetition": 1,
                "ok": True,
                "wall_ns": 20,
                "successful_flows": 1,
            },
        ]
        flows = [
            {
                "scenario": "request",
                "variant": "stable",
                "measurement_kind": "measurement",
                "repetition": 0,
                "ok": True,
                "connect_ns": 1,
            },
            {
                "scenario": "request",
                "variant": "stable",
                "measurement_kind": "measurement",
                "repetition": 1,
                "ok": True,
                "connect_ns": 100,
            },
        ]

        summary = benchmark.summarize(runs, flows)

        self.assertEqual(summary[0]["valid_flows"], 1)
        self.assertTrue(summary[0]["valid_flow_count_consistent"])
        self.assertEqual(summary[0]["connect_p50_ns"], 100)

    def test_variant_parser_rejects_empty_and_duplicate_values(self) -> None:
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.comma_variants("")
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.comma_variants("direct,direct")

    def test_data_mover_parser_rejects_inherited_comparisons(self) -> None:
        self.assertEqual(
            benchmark.comma_data_movers("buffered,splice"),
            ["buffered", "splice"],
        )
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.comma_data_movers("inherited,splice")
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.comma_data_movers("unknown")

    def test_execution_order_keeps_stable_movers_adjacent(self) -> None:
        args = benchmark.argparse.Namespace(
            variants=["direct", "stable"],
            stable_data_movers=["buffered", "splice"],
            proxy_session_sources=["inherited"],
        )

        order = benchmark.randomized_execution_order(
            args, benchmark.random.Random(20260726)
        )

        stable_indexes = [
            index
            for index, (variant, _mover, _session) in enumerate(order)
            if variant == "stable"
        ]
        self.assertEqual(stable_indexes[1] - stable_indexes[0], 1)
        self.assertEqual(
            {order[index][1] for index in stable_indexes}, {"buffered", "splice"}
        )

    def test_proxy_session_parser_rejects_inherited_comparisons(self) -> None:
        self.assertEqual(
            benchmark.comma_proxy_sessions("cold,warm-one-shot"),
            ["cold", "warm-one-shot"],
        )
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.comma_proxy_sessions("inherited,cold")
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.comma_proxy_sessions("warm")

    def test_execution_order_keeps_proxy_sessions_adjacent(self) -> None:
        args = benchmark.argparse.Namespace(
            variants=["direct", "stable"],
            stable_data_movers=["buffered"],
            proxy_session_sources=["cold", "warm-one-shot"],
        )

        order = benchmark.randomized_execution_order(
            args, benchmark.random.Random(20260726)
        )

        stable_indexes = [
            index
            for index, (variant, _mover, _session) in enumerate(order)
            if variant == "stable"
        ]
        self.assertEqual(stable_indexes[1] - stable_indexes[0], 1)
        self.assertEqual(
            {order[index][2] for index in stable_indexes},
            {"cold", "warm-one-shot"},
        )

    def test_variant_environment_overrides_only_explicit_stable_movers(self) -> None:
        base = {"SUP_TCP_DATA_MOVER": "splice", "MARKER": "kept"}

        buffered = benchmark.variant_environment("stable", "buffered", base=base)
        inherited = benchmark.variant_environment("stable", "inherited", base=base)
        direct = benchmark.variant_environment("direct", None, base=base)

        self.assertEqual(buffered["SUP_TCP_DATA_MOVER"], "buffered")
        self.assertEqual(inherited["SUP_TCP_DATA_MOVER"], "splice")
        self.assertEqual(direct["SUP_TCP_DATA_MOVER"], "splice")
        self.assertEqual(buffered["MARKER"], "kept")

    def test_variant_environment_overrides_only_explicit_proxy_sessions(self) -> None:
        base = {"SUP_TCP_PROXY_SESSION": "warm-one-shot", "MARKER": "kept"}

        cold = benchmark.variant_environment("stable", None, "cold", base=base)
        inherited = benchmark.variant_environment("stable", None, "inherited", base=base)
        direct = benchmark.variant_environment("direct", None, None, base=base)

        self.assertEqual(cold["SUP_TCP_PROXY_SESSION"], "cold")
        self.assertEqual(inherited["SUP_TCP_PROXY_SESSION"], "warm-one-shot")
        self.assertEqual(direct["SUP_TCP_PROXY_SESSION"], "warm-one-shot")
        self.assertEqual(cold["MARKER"], "kept")

    def test_scenarios_expand_multiple_stream_sizes(self) -> None:
        args = benchmark.argparse.Namespace(
            payload_sizes=[],
            soak_seconds=0,
            soak_profile="smoke",
            connections=1,
            idle_flows=[],
            idle_hold_ms=0,
            stream_flows=2,
            stream_bytes=1024,
            stream_byte_sizes=[1024, 2048],
            stream_directions=["up", "down"],
            slow_flows=0,
            slow_bytes=0,
            slow_rate=0,
            fairness_quiet_flows=0,
            fairness_quiet_payload=0,
            fairness_quiet_iterations=0,
            fairness_hot_bytes=0,
            reset_flows=0,
            reset_request_bytes=0,
            reset_prefix_bytes=0,
            stalled_flows=0,
            stalled_bytes=0,
            stalled_hold_ms=0,
        )

        scenarios = benchmark.scenarios(args)

        self.assertEqual(len(scenarios), 4)
        self.assertEqual({scenario["value"] for scenario in scenarios}, {1024, 2048})
        self.assertEqual(
            {scenario["direction"] for scenario in scenarios}, {"up", "down"}
        )
        self.assertTrue(all("-bytes" in scenario["name"] for scenario in scenarios))

    def test_paired_mover_comparison_uses_pair_local_effects(self) -> None:
        def run(mover: str, repetition: int, wall_ns: int, ok: bool = True) -> dict:
            return {
                "scenario": "stream-down",
                "mode": "stream",
                "variant": "stable",
                "data_mover": mover,
                "measurement_kind": "measurement",
                "repetition": repetition,
                "ok": ok,
                "stream_direction": "down",
                "stream_bytes_per_flow": benchmark.SPLICE_RAMP_BYTES,
                "bytes": 1000,
                "wall_ns": wall_ns,
                "child_cpu_ns": 100 if mover == "buffered" else 50,
            }

        comparisons = benchmark.paired_mover_comparisons(
            [
                run("buffered", 0, 100),
                run("splice", 0, 80),
                run("buffered", 1, 100),
                run("splice", 1, 50, ok=False),
            ]
        )

        summary = comparisons["summaries"][0]
        self.assertEqual(summary["total_pairs"], 2)
        self.assertEqual(summary["valid_pairs"], 1)
        self.assertAlmostEqual(summary["goodput_delta_percent"]["mean"], 25.0)
        self.assertAlmostEqual(
            summary["child_cpu_per_byte_delta_percent"]["mean"], -50.0
        )
        self.assertIsNone(summary["goodput_delta_percent"]["sample_stdev"])

    def test_paired_session_comparison_uses_pair_local_effects(self) -> None:
        def run(session: str, repetition: int, wall_ns: int, ok: bool = True) -> dict:
            return {
                "scenario": "request-1024",
                "mode": "request",
                "variant": "stable",
                "data_mover": "buffered",
                "proxy_session_source": session,
                "measurement_kind": "measurement",
                "repetition": repetition,
                "ok": ok,
                "stream_direction": None,
                "stream_bytes_per_flow": None,
                "successful_flows": 100,
                "wall_ns": wall_ns,
                "bytes": None,
                "child_cpu_ns": None,
            }

        def flow(session: str, repetition: int, connect_ns: int) -> dict:
            return {
                "scenario": "request-1024",
                "variant": "stable",
                "data_mover": "buffered",
                "proxy_session_source": session,
                "measurement_kind": "measurement",
                "repetition": repetition,
                "ok": True,
                "connect_ns": connect_ns,
            }

        comparisons = benchmark.paired_session_comparisons(
            [
                run("cold", 0, 200),
                run("warm-one-shot", 0, 100),
                run("cold", 1, 200),
                run("warm-one-shot", 1, 300, ok=False),
            ],
            [
                flow("cold", 0, 1000),
                flow("warm-one-shot", 0, 500),
            ],
        )

        summary = comparisons["summaries"][0]
        self.assertEqual(summary["total_pairs"], 2)
        self.assertEqual(summary["valid_pairs"], 1)
        self.assertEqual(summary["warm_wins"], 1)
        self.assertAlmostEqual(
            summary["connections_per_second_delta_percent"]["mean"], 100.0
        )
        self.assertAlmostEqual(summary["connect_p50_delta_percent"]["mean"], -50.0)
        self.assertAlmostEqual(summary["connect_p99_delta_percent"]["mean"], -50.0)
        broken_pair = [
            pair for pair in comparisons["pairs"] if pair["repetition"] == 1
        ][0]
        self.assertFalse(broken_pair["pair_ok"])

    @staticmethod
    def warm_gate_summary(
        scenario: str,
        conns_mean: float | None,
        p99_mean: float | None,
        valid_pairs: int = 10,
    ) -> dict:
        def dist(mean: float | None) -> dict:
            return {
                "count": valid_pairs if mean is not None else 0,
                "mean": mean,
                "sample_stdev": None,
                "median": mean,
                "min": mean,
                "max": mean,
            }

        return {
            "scenario": scenario,
            "mode": "request",
            "stream_direction": None,
            "stream_bytes_per_flow": None,
            "total_pairs": valid_pairs,
            "valid_pairs": valid_pairs,
            "warm_wins": valid_pairs // 2,
            "connections_per_second_delta_percent": dist(conns_mean),
            "connect_p50_delta_percent": dist(None),
            "connect_p99_delta_percent": dist(p99_mean),
            "goodput_delta_percent": dist(None),
            "child_cpu_per_byte_delta_percent": dist(None),
        }

    @staticmethod
    def warm_diagnostic_run(
        hits: int = 100,
        stale: int = 0,
        replenish_failures: int = 0,
        reported_source: str = "warm-one-shot",
    ) -> dict:
        return {
            "measurement_kind": "diagnostic",
            "proxy_session_source": "warm-one-shot",
            "metric_summary": {
                "tcp_proxy_session_source": reported_source,
                "tcp_warm_sessions_hit": hits,
                "tcp_warm_sessions_miss": 5,
                "tcp_warm_sessions_stale": stale,
                "tcp_warm_sessions_expired": 0,
                "tcp_warm_replenish_failures": replenish_failures,
            },
        }

    def test_warm_readiness_gate_passes_on_improvement_with_healthy_pool(self) -> None:
        gate = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 25.0, -10.0)]},
            [self.warm_diagnostic_run()],
        )

        self.assertTrue(gate["passed"])
        self.assertEqual(gate["improvements"], 1)
        self.assertEqual(gate["warm_pool_health"]["reasons"], [])

    def test_warm_readiness_gate_requires_an_improvement_point(self) -> None:
        gate = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 5.0, -10.0)]},
            [self.warm_diagnostic_run()],
        )

        self.assertFalse(gate["passed"])
        self.assertEqual(gate["improvements"], 0)

    def test_warm_readiness_gate_rejects_connect_p99_regression(self) -> None:
        gate = benchmark.warm_readiness_gate(
            {
                "summaries": [
                    self.warm_gate_summary("request-0", 25.0, -35.0),
                    self.warm_gate_summary("request-65536", 25.0, 9.0),
                ]
            },
            [self.warm_diagnostic_run()],
        )

        self.assertFalse(gate["passed"])
        regressed = [
            check for check in gate["checks"] if check["scenario"] == "request-65536"
        ][0]
        self.assertFalse(regressed["passed"])

    def test_warm_readiness_gate_rejects_unhealthy_pool(self) -> None:
        stale = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 25.0, -35.0)]},
            [self.warm_diagnostic_run(hits=100, stale=10)],
        )
        failing = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 25.0, -35.0)]},
            [self.warm_diagnostic_run(replenish_failures=1)],
        )
        missing = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 25.0, -35.0)]},
            [],
        )

        self.assertFalse(stale["passed"])
        self.assertFalse(failing["passed"])
        self.assertFalse(missing["passed"])

    def test_warm_readiness_gate_rejects_never_engaged_pool(self) -> None:
        gate = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 25.0, -35.0)]},
            [self.warm_diagnostic_run(hits=0)],
        )

        self.assertFalse(gate["passed"])
        self.assertIn(
            "warm pool never engaged", gate["warm_pool_health"]["reasons"]
        )

    def test_warm_readiness_gate_rejects_wrong_reported_source(self) -> None:
        gate = benchmark.warm_readiness_gate(
            {"summaries": [self.warm_gate_summary("request-1024", 25.0, -35.0)]},
            [self.warm_diagnostic_run(hits=0, reported_source="cold")],
        )

        self.assertFalse(gate["passed"])
        self.assertIn(
            "warm diagnostic reports proxy session source cold",
            gate["warm_pool_health"]["reasons"],
        )

    def test_proxy_rtt_parser_rejects_non_finite_and_negative(self) -> None:
        self.assertEqual(benchmark.proxy_rtt_ms("5"), 5.0)
        self.assertEqual(benchmark.proxy_rtt_ms("0"), 0.0)
        for raw in ("nan", "inf", "-inf", "-1"):
            with self.assertRaises(benchmark.argparse.ArgumentTypeError):
                benchmark.proxy_rtt_ms(raw)

    def test_warm_readiness_gate_requires_ten_valid_pairs(self) -> None:
        gate = benchmark.warm_readiness_gate(
            {
                "summaries": [
                    self.warm_gate_summary("request-1024", 25.0, -35.0, valid_pairs=9)
                ]
            },
            [self.warm_diagnostic_run()],
        )

        self.assertFalse(gate["passed"])
        self.assertIn(
            "requires 10 valid pairs, got 9", gate["checks"][0]["reasons"]
        )

    def test_proxy_rtt_injection_delays_socks5_replies(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5, proxy_rtt_seconds=0.05)
        servers.start()
        try:
            started = time.monotonic()
            with socket.create_connection(
                ("127.0.0.1", servers.proxy_port)
            ) as connection:
                connection.settimeout(5)
                connection.sendall(b"\x05\x01\x00")
                reply = self.recv_exact(connection, 2)
                self.assertEqual(reply, b"\x05\x00")
                greeting_elapsed = time.monotonic() - started
                request = (
                    b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                    + servers.destination_port.to_bytes(2, "big")
                )
                connection.sendall(request)
                self.assertEqual(len(self.recv_exact(connection, 10)), 10)
                total_elapsed = time.monotonic() - started
        finally:
            servers.stop()

        self.assertGreaterEqual(greeting_elapsed, 0.04)
        self.assertGreaterEqual(total_elapsed, 0.09)

    @staticmethod
    def recv_exact(connection: socket.socket, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def test_splice_readiness_gate_reports_ramp_without_thresholding_it(self) -> None:
        summaries = []
        for stream_bytes in (
            benchmark.SPLICE_RAMP_BYTES,
            benchmark.SPLICE_STEADY_BYTES,
        ):
            for direction in benchmark.STREAM_DIRECTION_CODES:
                summaries.append(
                    {
                        "scenario": f"stream-{direction}-{stream_bytes}",
                        "mode": "stream",
                        "stream_direction": direction,
                        "stream_bytes_per_flow": stream_bytes,
                        "total_pairs": 10,
                        "valid_pairs": 10,
                        "splice_wins": 0,
                        "goodput_delta_percent": {
                            "count": 10,
                            "mean": -30.0 if stream_bytes == benchmark.SPLICE_RAMP_BYTES else 0.0,
                            "sample_stdev": 1.0,
                            "median": 0.0,
                            "min": -30.0,
                            "max": 0.0,
                        },
                        "child_cpu_per_byte_delta_percent": {
                            "count": 10,
                            "mean": -20.0,
                            "sample_stdev": 1.0,
                            "median": -20.0,
                            "min": -21.0,
                            "max": -19.0,
                        },
                    }
                )

        gate = benchmark.splice_readiness_gate(
            {"pairs": [], "summaries": summaries}
        )

        self.assertTrue(gate["passed"])
        self.assertTrue(
            all(check["passed"] for check in gate["checks"] if check["stage"] == "ramp")
        )

    def test_splice_readiness_gate_rejects_steady_regression(self) -> None:
        comparisons = {"pairs": [], "summaries": []}
        for stream_bytes in (
            benchmark.SPLICE_RAMP_BYTES,
            benchmark.SPLICE_STEADY_BYTES,
        ):
            for direction in benchmark.STREAM_DIRECTION_CODES:
                comparisons["summaries"].append(
                    {
                        "scenario": f"stream-{direction}-{stream_bytes}",
                        "mode": "stream",
                        "stream_direction": direction,
                        "stream_bytes_per_flow": stream_bytes,
                        "total_pairs": 10,
                        "valid_pairs": 10,
                        "splice_wins": 0,
                        "goodput_delta_percent": {
                            "count": 10,
                            "mean": -6.0,
                            "sample_stdev": 1.0,
                            "median": -6.0,
                            "min": -7.0,
                            "max": -5.0,
                        },
                        "child_cpu_per_byte_delta_percent": {
                            "count": 10,
                            "mean": -10.0,
                            "sample_stdev": 1.0,
                            "median": -10.0,
                            "min": -11.0,
                            "max": -9.0,
                        },
                    }
                )

        gate = benchmark.splice_readiness_gate(comparisons)

        self.assertFalse(gate["passed"])
        self.assertTrue(
            all(
                not check["passed"]
                for check in gate["checks"]
                if check["stage"] == "steady"
            )
        )

    def test_git_commit_parser_normalizes_and_rejects_revisions(self) -> None:
        self.assertEqual(len(benchmark.git_commit("HEAD")), 40)
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.git_commit("definitely-not-a-commit")

    def test_git_commit_resolves_from_repo_root_regardless_of_cwd(self) -> None:
        expected = benchmark.git_commit("HEAD")
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            try:
                self.assertEqual(benchmark.git_commit("HEAD"), expected)
            finally:
                os.chdir(previous)

    def test_missing_process_resources_are_null(self) -> None:
        self.assertIsNone(benchmark.process_resources(2**31 - 1))

    def test_process_exit_races_are_treated_as_missing_samples(self) -> None:
        error = ProcessLookupError(3, "No such process")
        with mock.patch.object(benchmark.Path, "read_text", side_effect=error):
            self.assertIsNone(benchmark.process_resources(123))
            self.assertEqual(benchmark.direct_child_pids(123), [])

    def test_malformed_status_lines_are_treated_as_missing_samples(self) -> None:
        status = "VmRSS:\tgarbage\nVmHWM:\t1 kB\n"
        with (
            mock.patch.object(benchmark.Path, "read_text", return_value=status),
            mock.patch.object(benchmark.Path, "iterdir", return_value=iter([])),
        ):
            self.assertIsNone(benchmark.process_resources(123))

    def test_permission_denied_samples_return_null_and_warn_once(self) -> None:
        error = PermissionError(13, "Permission denied")
        stderr = io.StringIO()
        with (
            mock.patch.object(benchmark.Path, "read_text", side_effect=error),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertIsNone(benchmark.process_resources(424242))
            self.assertIsNone(benchmark.process_resources(424242))
        self.assertEqual(stderr.getvalue().count("cannot sample /proc/424242"), 1)

    def test_flow_ids_must_cover_expected_range(self) -> None:
        valid = [{"flow": 0, "ok": True}, {"flow": 1, "ok": True}]
        wrong_ids = [{"flow": 0, "ok": True}, {"flow": 2, "ok": True}]

        self.assertTrue(benchmark.workload_flows_are_valid(valid, 2))
        self.assertFalse(benchmark.workload_flows_are_valid(wrong_ids, 2))

    def test_server_shutdown_joins_open_connection_handlers(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=1)
        servers.start()
        connection = socket.create_connection(("127.0.0.1", servers.destination_port))
        try:
            deadline = time.monotonic() + 1
            while not servers.connection_tasks and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertTrue(servers.connection_tasks)
            servers.stop()
        finally:
            connection.close()

        self.assertFalse(servers.thread.is_alive())
        self.assertEqual(servers.connection_tasks, set())

    def test_server_root_cause_survives_closed_event_loop(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=1)
        servers.start()
        connection = socket.create_connection(("127.0.0.1", servers.stalled_port))
        try:
            deadline = time.monotonic() + 5
            while servers.thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(servers.thread.is_alive())
            with self.assertRaises(RuntimeError) as cpu_error:
                servers.cpu_ns()
            self.assertIn(
                "stalled run was not prepared", str(cpu_error.exception.__cause__)
            )
            with self.assertRaises(RuntimeError) as stop_error:
                servers.stop()
            self.assertIn(
                "stalled run was not prepared", str(stop_error.exception.__cause__)
            )
        finally:
            connection.close()

    def test_cancelled_cross_thread_call_chains_stored_failure(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=1)
        root_cause = RuntimeError("handler failed")
        servers.error = root_cause
        cancelled: concurrent.futures.Future[int] = concurrent.futures.Future()
        cancelled.cancel()
        coroutine = servers._thread_cpu_ns()
        try:
            with (
                mock.patch.object(
                    benchmark.asyncio,
                    "run_coroutine_threadsafe",
                    return_value=cancelled,
                ),
                self.assertRaises(RuntimeError) as caught,
            ):
                servers._run_on_loop(coroutine, mock.Mock())
        finally:
            coroutine.close()
        self.assertIs(caught.exception.__cause__, root_cause)

    def test_timed_out_cross_thread_call_cancels_future_and_chains_failure(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=1)
        root_cause = RuntimeError("handler failed")
        servers.error = root_cause
        pending: concurrent.futures.Future[int] = concurrent.futures.Future()
        coroutine = servers._thread_cpu_ns()
        try:
            with (
                mock.patch.object(benchmark, "SERVER_CALL_TIMEOUT_SECONDS", 0.01),
                mock.patch.object(
                    benchmark.asyncio,
                    "run_coroutine_threadsafe",
                    return_value=pending,
                ),
                self.assertRaises(RuntimeError) as caught,
            ):
                servers._run_on_loop(coroutine, mock.Mock())
        finally:
            coroutine.close()
        self.assertIs(caught.exception.__cause__, root_cause)
        self.assertTrue(pending.cancelled())

    def test_stalled_server_applies_backpressure_before_release(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=1)
        servers.start()
        servers.prepare_stalled_run()
        connection = socket.create_connection(("127.0.0.1", servers.stalled_port))
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        connection.setblocking(False)
        deadline = time.monotonic() + 1
        while not servers.connection_tasks and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertTrue(servers.connection_tasks)
        accepted = 0
        payload = b"x" * 65536
        try:
            while accepted < 8 * 1024 * 1024:
                try:
                    accepted += connection.send(payload)
                except BlockingIOError:
                    break
            self.assertLess(accepted, 8 * 1024 * 1024)
        finally:
            servers.release_stalled_run()
            connection.close()
            servers.stop()

    def test_stalled_handler_captures_run_before_task_starts(self) -> None:
        async def exercise() -> tuple[list[dict[str, int | bool]], list[object]]:
            class FakeTransport:
                def __init__(self) -> None:
                    self.paused = False
                    self.resumed = False

                def pause_reading(self) -> None:
                    self.paused = True

                def resume_reading(self) -> None:
                    self.resumed = True

            class FakeWriter:
                def __init__(self) -> None:
                    self.transport = FakeTransport()
                    self.closed = False

                def close(self) -> None:
                    self.closed = True

                async def wait_closed(self) -> None:
                    pass

            servers = benchmark.BenchmarkServers(safety_timeout=1)
            old_release = asyncio.Event()
            old_results: list[dict[str, int | bool]] = []
            servers.stalled_release = old_release
            servers.stalled_results = old_results
            reader = asyncio.StreamReader()
            reader.feed_data(bytes([benchmark.STALLED_PAYLOAD_BYTE]))
            reader.feed_eof()
            writer = FakeWriter()
            spawned = []
            servers._spawn_connection = lambda coroutine, _writer: spawned.append(
                coroutine
            )

            servers._spawn_stalled_connection(reader, writer)
            new_results: list[object] = []
            servers.stalled_release = asyncio.Event()
            servers.stalled_results = new_results
            old_release.set()
            await spawned.pop()

            self.assertTrue(writer.transport.paused)
            self.assertTrue(writer.transport.resumed)
            self.assertTrue(writer.closed)
            return old_results, new_results

        old_results, new_results = asyncio.run(exercise())

        self.assertEqual(
            old_results,
            [{"bytes": 1, "content_ok": True, "eof": True}],
        )
        self.assertEqual(new_results, [])

    def test_stalled_undersized_flow_count_classifies_calibration_misses(self) -> None:
        blocked = {"blocked": True, "errno": 0, "accepted_bytes": 8}
        undersized = {"blocked": False, "errno": 0, "accepted_bytes": 8}
        errored = {"blocked": False, "errno": 104, "accepted_bytes": 8}
        partial = {"blocked": False, "errno": 0, "accepted_bytes": 3}

        self.assertEqual(
            benchmark.stalled_undersized_flow_count(
                [blocked, undersized, errored, partial], 8
            ),
            1,
        )
        self.assertEqual(benchmark.stalled_undersized_flow_count([], 8), 0)
        self.assertEqual(benchmark.stalled_undersized_flow_count([blocked], 8), 0)

    def test_stalled_server_quiescence_rejects_unsafe_reuse(self) -> None:
        complete = [{"bytes": 1, "content_ok": True, "eof": True}]
        incomplete = [{"bytes": 1, "content_ok": True, "eof": False}]

        self.assertTrue(benchmark.stalled_server_is_quiescent(False, 1, complete))
        self.assertFalse(benchmark.stalled_server_is_quiescent(True, 1, complete))
        self.assertFalse(benchmark.stalled_server_is_quiescent(False, 1, []))
        self.assertFalse(benchmark.stalled_server_is_quiescent(False, 1, incomplete))

        with self.assertRaisesRegex(RuntimeError, "shared listener"):
            benchmark.require_stalled_server_quiescence(
                {
                    "mode": "stalled",
                    "scenario": "stalled-1-flow",
                    "variant": "stable",
                    "stalled_server_quiescent": False,
                }
            )
        with self.assertRaisesRegex(RuntimeError, "shared listener"):
            benchmark.require_stalled_server_quiescence(
                {
                    "mode": "stalled",
                    "scenario": "stalled-1-flow",
                    "variant": "stable",
                    "stalled_server_quiescent": None,
                }
            )

    def test_stalled_server_verifies_drained_content_and_totals(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stalled_run()
            payload = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 70000
            with socket.create_connection(
                ("127.0.0.1", servers.stalled_port), timeout=5
            ) as connection:
                servers.release_stalled_run()
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(connection.recv(1), b"")
            self.assertEqual(
                servers.stalled_run_results(),
                [{"bytes": len(payload), "content_ok": True, "eof": True}],
            )

            servers.prepare_stalled_run()
            self.assertEqual(servers.stalled_run_results(), [])
        finally:
            servers.stop()

    def test_stalled_server_flags_corrupted_drain(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stalled_run()
            filler = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 1000
            with socket.create_connection(
                ("127.0.0.1", servers.stalled_port), timeout=5
            ) as connection:
                servers.release_stalled_run()
                connection.sendall(filler + b"\x00" + filler)
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(connection.recv(1), b"")
            self.assertEqual(
                servers.stalled_run_results(),
                [{"bytes": 2001, "content_ok": False, "eof": True}],
            )
        finally:
            servers.stop()

    @staticmethod
    def stream_header(direction: str, payload: int, rate: int = 0) -> bytes:
        return benchmark.STREAM_HEADER.pack(
            benchmark.STREAM_MAGIC, ord(direction), payload, rate, 0
        )

    def test_stream_server_upload_verifies_bytes_and_acks(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            payload = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 200000
            with socket.create_connection(
                ("127.0.0.1", servers.stream_port), timeout=5
            ) as connection:
                connection.sendall(self.stream_header("U", len(payload)) + payload)
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(
                    connection.recv(1), bytes([benchmark.STREAM_ACK_BYTE])
                )
                self.assertEqual(connection.recv(1), b"")
            results, complete = servers.stream_run_results(1)
            self.assertTrue(complete)
            self.assertTrue(
                benchmark.stream_result_is_clean(results[0], "up", len(payload))
            )
        finally:
            servers.stop()

    def test_stream_server_download_sends_exact_payload(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            expected = 150000
            with socket.create_connection(
                ("127.0.0.1", servers.stream_port), timeout=5
            ) as connection:
                connection.sendall(self.stream_header("D", expected))
                connection.shutdown(socket.SHUT_WR)
                received = bytearray()
                while chunk := connection.recv(65536):
                    received.extend(chunk)
            self.assertEqual(len(received), expected)
            self.assertEqual(
                received.count(benchmark.STALLED_PAYLOAD_BYTE), expected
            )
            results, complete = servers.stream_run_results(1)
            self.assertTrue(complete)
            self.assertTrue(
                benchmark.stream_result_is_clean(results[0], "down", expected)
            )
        finally:
            servers.stop()

    def test_stream_server_bidi_moves_both_directions(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            expected = 60000
            payload = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * expected
            with socket.create_connection(
                ("127.0.0.1", servers.stream_port), timeout=5
            ) as connection:
                connection.sendall(self.stream_header("B", expected) + payload)
                connection.shutdown(socket.SHUT_WR)
                received = bytearray()
                while chunk := connection.recv(65536):
                    received.extend(chunk)
            self.assertEqual(bytes(received), payload)
            results, complete = servers.stream_run_results(1)
            self.assertTrue(complete)
            self.assertTrue(
                benchmark.stream_result_is_clean(results[0], "bidi", expected)
            )
        finally:
            servers.stop()

    def test_stream_server_aborts_short_or_corrupt_upload(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            payload = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 999 + b"\x00"
            with socket.create_connection(
                ("127.0.0.1", servers.stream_port), timeout=5
            ) as connection:
                connection.sendall(self.stream_header("U", len(payload)) + payload)
                connection.shutdown(socket.SHUT_WR)
                try:
                    tail = connection.recv(1)
                except ConnectionError:
                    tail = b""
                self.assertNotEqual(tail, bytes([benchmark.STREAM_ACK_BYTE]))
            results, complete = servers.stream_run_results(1)
            self.assertTrue(complete)
            self.assertFalse(results[0]["content_ok"])
            self.assertFalse(results[0]["acked"])
            self.assertFalse(
                benchmark.stream_result_is_clean(results[0], "up", len(payload))
            )
        finally:
            servers.stop()

    def test_stream_server_rate_limit_paces_reads(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            payload = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 16384
            started = time.monotonic()
            with socket.create_connection(
                ("127.0.0.1", servers.stream_port), timeout=5
            ) as connection:
                connection.sendall(
                    self.stream_header("U", len(payload), rate=65536) + payload
                )
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(
                    connection.recv(1), bytes([benchmark.STREAM_ACK_BYTE])
                )
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 0.2)
            results, complete = servers.stream_run_results(1)
            self.assertTrue(complete)
            self.assertTrue(
                benchmark.stream_result_is_clean(results[0], "up", len(payload))
            )
        finally:
            servers.stop()

    def test_stream_result_cleanliness_matrix(self) -> None:
        clean_up = {
            "header_ok": True,
            "direction": "U",
            "received": 10,
            "sent": 0,
            "content_ok": True,
            "eof": True,
            "acked": True,
        }
        self.assertTrue(benchmark.stream_result_is_clean(clean_up, "up", 10))
        self.assertFalse(
            benchmark.stream_result_is_clean({**clean_up, "received": 9}, "up", 10)
        )
        self.assertFalse(
            benchmark.stream_result_is_clean({**clean_up, "acked": False}, "up", 10)
        )
        self.assertFalse(
            benchmark.stream_result_is_clean({**clean_up, "direction": "D"}, "up", 10)
        )
        clean_down = {
            "header_ok": True,
            "direction": "D",
            "received": 0,
            "sent": 10,
            "content_ok": True,
            "eof": True,
            "acked": False,
        }
        self.assertTrue(benchmark.stream_result_is_clean(clean_down, "down", 10))
        self.assertFalse(
            benchmark.stream_result_is_clean({**clean_down, "received": 1}, "down", 10)
        )
        clean_bidi = {
            "header_ok": True,
            "direction": "B",
            "received": 10,
            "sent": 10,
            "content_ok": True,
            "eof": True,
            "acked": False,
        }
        self.assertTrue(benchmark.stream_result_is_clean(clean_bidi, "bidi", 10))
        self.assertFalse(
            benchmark.stream_result_is_clean({**clean_bidi, "sent": 9}, "bidi", 10)
        )

    def test_stream_server_quiescence_gate(self) -> None:
        benchmark.require_stream_server_quiescence(
            {"mode": "request", "scenario": "request", "variant": "stable"}
        )
        benchmark.require_stream_server_quiescence(
            {
                "mode": "stream",
                "scenario": "stream-up-1-flows",
                "variant": "stable",
                "stream_server_quiescent": True,
            }
        )
        for value in (False, None):
            with self.assertRaisesRegex(RuntimeError, "stream server"):
                benchmark.require_stream_server_quiescence(
                    {
                        "mode": "stream",
                        "scenario": "stream-up-1-flows",
                        "variant": "stable",
                        "stream_server_quiescent": value,
                    }
                )

    @unittest.skipIf(shutil.which("cc") is None, "cc not available")
    def test_workload_stream_roundtrip_all_directions(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=10)
        servers.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                workload = Path(directory) / "workload"
                benchmark.build_workload("cc", workload)
                flows = 4
                payload = 200000
                for direction in ("up", "down", "bidi"):
                    servers.prepare_stream_run()
                    completed = subprocess.run(
                        [
                            str(workload),
                            "stream",
                            "127.0.0.1",
                            str(servers.stream_port),
                            str(flows),
                            str(payload),
                            direction,
                            "0",
                        ],
                        text=True,
                        capture_output=True,
                        timeout=30,
                    )
                    self.assertEqual(
                        completed.returncode, 0, msg=completed.stderr[-500:]
                    )
                    flow_records, samples, summary = benchmark.parse_workload_output(
                        completed.stdout
                    )
                    self.assertEqual(samples, [])
                    self.assertTrue(
                        benchmark.workload_flows_are_valid(flow_records, flows)
                    )
                    expected_total = flows * payload * (
                        2 if direction == "bidi" else 1
                    )
                    self.assertEqual(summary["bytes"], expected_total)
                    results, complete = servers.stream_run_results(flows)
                    self.assertTrue(complete)
                    self.assertEqual(len(results), flows)
                    for result in results:
                        self.assertTrue(
                            benchmark.stream_result_is_clean(
                                result, direction, payload
                            )
                        )
        finally:
            servers.stop()

    @unittest.skipIf(shutil.which("cc") is None, "cc not available")
    def test_workload_soak_smoke_profile_runs_complete_cycles(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=10)
        servers.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                workload = Path(directory) / "workload"
                progress_path = Path(directory) / "soak-progress"
                ack_path = Path(directory) / "soak-ack"
                benchmark.build_workload("cc", workload)
                servers.prepare_soak_stream_run()
                process = subprocess.Popen(
                    [
                        str(workload),
                        "soak",
                        "127.0.0.1",
                        str(servers.destination_port),
                        str(servers.stream_port),
                        "1",
                        "smoke",
                        str(progress_path),
                        str(ack_path),
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                acknowledged = 0
                deadline = time.monotonic() + 30
                while process.poll() is None:
                    self.assertLess(time.monotonic(), deadline)
                    if progress_path.exists():
                        cycle = int(progress_path.read_text().strip())
                        if cycle > acknowledged:
                            acknowledged = cycle
                            ack_path.write_text(f"{cycle}\n")
                    time.sleep(0.005)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, msg=stderr[-500:])
                flows, samples, summary = benchmark.parse_workload_output(stdout)
                self.assertEqual(flows, [])
                self.assertEqual(samples, [])
                self.assertGreaterEqual(summary["cycles"], 1)
                self.assertEqual(summary["completed_phases"], summary["cycles"] * 12)
                self.assertEqual(summary["successful"], summary["flows"])
                aggregate, complete = servers.soak_stream_results(
                    summary["stream_connections"]
                )
                self.assertTrue(complete)
                self.assertEqual(aggregate["violations"], 0)
                self.assertEqual(
                    aggregate["connections"], summary["stream_connections"]
                )
        finally:
            servers.stop()

    @unittest.skipIf(shutil.which("cc") is None, "cc not available")
    def test_workload_fairness_roundtrip(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=10)
        servers.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                workload = Path(directory) / "workload"
                benchmark.build_workload("cc", workload)
                quiet_flows, iterations, payload, hot_bytes = 3, 5, 512, 100000
                servers.prepare_stream_run()
                completed = subprocess.run(
                    [
                        str(workload),
                        "fairness",
                        "127.0.0.1",
                        str(servers.destination_port),
                        str(servers.stream_port),
                        str(quiet_flows),
                        str(iterations),
                        str(payload),
                        str(hot_bytes),
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, msg=completed.stderr[-500:])
                flow_records, samples, summary = benchmark.parse_workload_output(
                    completed.stdout
                )
                self.assertTrue(
                    benchmark.workload_flows_are_valid(flow_records, quiet_flows + 1)
                )
                kinds = {record["flow"]: record["kind"] for record in flow_records}
                self.assertEqual(kinds[0], "hot")
                self.assertEqual(
                    [kinds[flow] for flow in range(1, quiet_flows + 1)],
                    ["quiet"] * quiet_flows,
                )
                self.assertEqual(len(samples), quiet_flows * iterations)
                self.assertTrue(
                    all(sample["kind"] == "quiet_echo" for sample in samples)
                )
                self.assertTrue(all(sample["latency_ns"] > 0 for sample in samples))
                self.assertEqual(
                    summary["bytes"],
                    hot_bytes + 2 * payload * quiet_flows * iterations,
                )
                results, complete = servers.stream_run_results(1)
                self.assertTrue(complete)
                self.assertEqual(len(results), 1)
                self.assertTrue(
                    benchmark.stream_result_is_clean(results[0], "up", hot_bytes)
                )
        finally:
            servers.stop()

    def test_process_cpu_ns_samples_live_and_missing_processes(self) -> None:
        cpu = benchmark.process_cpu_ns(os.getpid())
        self.assertIsNotNone(cpu)
        assert cpu is not None
        self.assertGreaterEqual(cpu, 0)
        self.assertIsNone(benchmark.process_cpu_ns(2**31 - 1))

    def test_soak_resource_acceptance_checks_quiescent_growth(self) -> None:
        samples = [
            {
                "kind": "cycle_boundary",
                "cycle": cycle,
                "elapsed_ns": cycle * 1_000_000_000,
                "supervisor": {"fds": 10, "rss_kib": 6000},
                "target": {"fds": 4, "rss_kib": 1000},
            }
            for cycle in range(1, 31)
        ]

        accepted = benchmark.soak_resource_acceptance(samples, 30, "standard")
        leaked = benchmark.soak_resource_acceptance(
            [
                *samples[:-1],
                {
                    **samples[-1],
                    "supervisor": {"fds": 11, "rss_kib": 16000},
                },
            ],
            30,
            "standard",
        )

        self.assertTrue(accepted["passed"])
        self.assertFalse(leaked["passed"])
        self.assertTrue(any("fd delta" in reason for reason in leaked["reasons"]))
        self.assertTrue(any("RSS grew" in reason for reason in leaked["reasons"]))

    def test_parse_perf_stat_csv_keeps_counter_rows(self) -> None:
        text = (
            "# started on Fri Jul 25\n"
            "\n"
            "12345,,task-clock,1000,100.00,,\n"
            "<not supported>,,cache-misses,0,0.00,,\n"
        )
        counters = benchmark.parse_perf_stat_csv(text)
        self.assertEqual(
            counters,
            [
                {"value": "12345", "unit": "", "event": "task-clock"},
                {"value": "<not supported>", "unit": "", "event": "cache-misses"},
            ],
        )

    @unittest.skipIf(shutil.which("cc") is None, "cc not available")
    def test_workload_idle_writes_ready_file(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                workload = Path(directory) / "workload"
                ready_path = Path(directory) / "idle-ready"
                benchmark.build_workload("cc", workload)
                completed = subprocess.run(
                    [
                        str(workload),
                        "idle",
                        "127.0.0.1",
                        str(servers.destination_port),
                        "2",
                        "50",
                        str(ready_path),
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, msg=completed.stderr[-500:])
                self.assertEqual(ready_path.read_text().strip(), "2")
                flow_records, samples, _summary = benchmark.parse_workload_output(
                    completed.stdout
                )
                self.assertEqual(samples, [])
                self.assertTrue(benchmark.workload_flows_are_valid(flow_records, 2))
        finally:
            servers.stop()

    def test_reset_result_cleanliness_matrix(self) -> None:
        clean = {
            "header_ok": True,
            "direction": "R",
            "received": 100,
            "sent": 16,
            "content_ok": True,
            "eof": False,
            "acked": False,
            "aborted": True,
        }
        self.assertTrue(benchmark.reset_result_is_clean(clean, 100, 16, 0))
        self.assertTrue(
            benchmark.reset_result_is_clean({**clean, "received": 50}, 100, 16, 50)
        )
        self.assertFalse(
            benchmark.reset_result_is_clean({**clean, "aborted": False}, 100, 16, 0)
        )
        self.assertFalse(
            benchmark.reset_result_is_clean({**clean, "received": 99}, 100, 16, 0)
        )
        self.assertFalse(
            benchmark.reset_result_is_clean({**clean, "sent": 0}, 100, 16, 0)
        )

    def test_stream_server_reset_direction_aborts_after_prefix(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            request = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 5000
            with socket.create_connection(
                ("127.0.0.1", servers.stream_port), timeout=5
            ) as connection:
                connection.sendall(
                    benchmark.STREAM_HEADER.pack(
                        benchmark.STREAM_MAGIC, ord("R"), len(request), 64, 0
                    )
                    + request
                )
                observed = bytearray()
                with contextlib.suppress(ConnectionError):
                    while chunk := connection.recv(65536):
                        observed.extend(chunk)
            self.assertLessEqual(len(observed), 64)
            results, complete = servers.stream_run_results(1)
            self.assertTrue(complete)
            self.assertTrue(
                benchmark.reset_result_is_clean(results[0], len(request), 64, 0)
            )
        finally:
            servers.stop()

    def test_proxy_propagates_upstream_reset(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=5)
        servers.start()
        try:
            servers.prepare_stream_run()
            request = bytes([benchmark.STALLED_PAYLOAD_BYTE]) * 2000
            with socket.create_connection(
                ("127.0.0.1", servers.proxy_port), timeout=5
            ) as connection:
                connection.sendall(b"\x05\x01\x00")
                self.assertEqual(connection.recv(2), b"\x05\x00")
                connection.sendall(
                    b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                    + servers.stream_port.to_bytes(2, "big")
                )
                self.assertEqual(len(connection.recv(10)), 10)
                connection.sendall(
                    benchmark.STREAM_HEADER.pack(
                        benchmark.STREAM_MAGIC, ord("R"), len(request), 0, 0
                    )
                    + request
                )
                saw_reset = False
                try:
                    while connection.recv(65536):
                        pass
                except ConnectionError:
                    saw_reset = True
            self.assertTrue(saw_reset)
        finally:
            servers.stop()

    @unittest.skipIf(shutil.which("cc") is None, "cc not available")
    def test_workload_reset_roundtrip_classifies_outcomes(self) -> None:
        servers = benchmark.BenchmarkServers(safety_timeout=10)
        servers.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                workload = Path(directory) / "workload"
                benchmark.build_workload("cc", workload)
                flows, request = 4, 50000
                for prefix, consume in ((512, 0), (0, 25000)):
                    servers.prepare_stream_run()
                    completed = subprocess.run(
                        [
                            str(workload),
                            "reset",
                            "127.0.0.1",
                            str(servers.stream_port),
                            str(flows),
                            str(request),
                            str(prefix),
                            str(consume),
                        ],
                        text=True,
                        capture_output=True,
                        timeout=30,
                    )
                    self.assertEqual(
                        completed.returncode, 0, msg=completed.stderr[-500:]
                    )
                    flow_records, samples, summary = benchmark.parse_workload_output(
                        completed.stdout
                    )
                    self.assertEqual(samples, [])
                    self.assertTrue(
                        benchmark.workload_flows_are_valid(flow_records, flows)
                    )
                    self.assertTrue(
                        all(
                            record["outcome"] in ("reset", "eof")
                            for record in flow_records
                        )
                    )
                    self.assertEqual(
                        summary["reset_outcomes"] + summary["eof_outcomes"], flows
                    )
                    results, complete = servers.stream_run_results(flows)
                    self.assertTrue(complete)
                    self.assertEqual(len(results), flows)
                    for result in results:
                        self.assertTrue(
                            benchmark.reset_result_is_clean(
                                result, request, prefix, consume
                            )
                        )
        finally:
            servers.stop()


if __name__ == "__main__":
    unittest.main()
