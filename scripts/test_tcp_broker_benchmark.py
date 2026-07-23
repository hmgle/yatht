from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
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

    def test_git_commit_parser_normalizes_and_rejects_revisions(self) -> None:
        self.assertEqual(len(benchmark.git_commit("HEAD")), 40)
        with self.assertRaises(benchmark.argparse.ArgumentTypeError):
            benchmark.git_commit("definitely-not-a-commit")

    def test_missing_process_resources_are_null(self) -> None:
        self.assertIsNone(benchmark.process_resources(2**31 - 1))

    def test_process_exit_races_are_treated_as_missing_samples(self) -> None:
        error = ProcessLookupError(3, "No such process")
        with mock.patch.object(benchmark.Path, "read_text", side_effect=error):
            self.assertIsNone(benchmark.process_resources(123))
            self.assertEqual(benchmark.direct_child_pids(123), [])

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


if __name__ == "__main__":
    unittest.main()
