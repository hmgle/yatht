from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import importlib.util
import io
import os
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


if __name__ == "__main__":
    unittest.main()
