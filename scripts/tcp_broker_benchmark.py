#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run deterministic direct and stable TCP broker benchmarks."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
from contextlib import suppress
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import random
import resource
import signal
import shlex
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Coroutine


ROOT = Path(__file__).resolve().parent.parent
WORKLOAD_SOURCE = ROOT / "benchmarks" / "tcp_broker" / "workload.c"
DEFAULT_WORKLOAD = ROOT / "target" / "tcp-broker-benchmark" / "workload"
# Raw measurement archives must survive `cargo clean`; only the rebuildable
# workload binary stays under target/.
DEFAULT_OUTPUT_ROOT = ROOT / "bench-results" / "tcp-broker"
VARIANT_ORDER = ("direct", "stable")
STABLE_DATA_MOVERS = ("inherited", "buffered", "splice")
PROXY_SESSION_SOURCES = ("inherited", "cold", "warm-one-shot")
SPLICE_RAMP_BYTES = 4 * 1024 * 1024
SPLICE_STEADY_BYTES = 32 * 1024 * 1024
SPLICE_STEADY_MIN_GOODPUT_DELTA_PERCENT = -5.0
SPLICE_STEADY_MAX_CPU_DELTA_PERCENT = -15.0
# Warm readiness passes when one request point improves connections/s by 20%
# or connect p99 by 30%, no request point regresses connect p99 by more than 5%,
# and diagnostics show bounded staleness with zero replenish failures.
WARM_MIN_CONNS_PER_SEC_DELTA_PERCENT = 20.0
WARM_MAX_CONNECT_P99_DELTA_PERCENT = -30.0
WARM_CONNECT_P99_REGRESSION_LIMIT_PERCENT = 5.0
WARM_MAX_STALE_PER_HIT = 0.05
METRICS_SCHEMA_VERSION = 7
SAMPLE_INTERVAL_SECONDS = 0.005
SOAK_SAMPLE_INTERVAL_SECONDS = 1.0
SOAK_POLL_INTERVAL_SECONDS = 0.05
# Walking /proc for the whole process tree at 5 ms is a measurable observer
# effect with thousands of flows; per-role samples stay at 5 ms while the tree
# aggregate is refreshed every TREE_SAMPLE_STRIDE iterations.
TREE_SAMPLE_STRIDE = 20
SERVER_CALL_TIMEOUT_SECONDS = 5
# workload.c fills every payload byte with 0x5a; the stalled destination
# verifies the drained stream against it so relay corruption that conserves
# byte counts still fails the run gate.
STALLED_PAYLOAD_BYTE = 0x5A
# The stream server speaks the 32-byte header documented in workload.c: magic,
# direction, payload bytes, and an optional server-side read rate limit for
# slow-consumer scenarios. Uploads are acknowledged with a single 0xa5 byte
# only after byte count and content verify, so truncation cannot pass.
STREAM_MAGIC = b"YBW1"
STREAM_HEADER = struct.Struct("<4sB3xQQQ")
STREAM_ACK_BYTE = 0xA5
STREAM_DIRECTION_CODES = {"up": "U", "down": "D", "bidi": "B"}
STREAM_RESULT_WAIT_SECONDS = 2.0


class BenchmarkServers:
    def __init__(self, safety_timeout: float, proxy_rtt_seconds: float = 0.0) -> None:
        # Injected before each SOCKS5 reply to model a real proxy's network
        # round trips; the TCP connect itself stays at loopback speed, so a
        # nonzero setting understates the warm pool's real-world benefit.
        self.proxy_rtt_seconds = proxy_rtt_seconds
        self.loop: asyncio.AbstractEventLoop | None = None
        self.stop_event: asyncio.Event | None = None
        self.destination_port = 0
        self.proxy_port = 0
        self.stalled_port = 0
        self.stream_port = 0
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self._thread_main,
            name="benchmark-servers",
            daemon=True,
        )
        self.error: BaseException | None = None
        self.stalled_release: asyncio.Event | None = None
        self.stalled_results: list[dict[str, int | bool]] | None = None
        self.stream_results: list[dict[str, Any]] | None = None
        self.stream_aggregate: dict[str, Any] | None = None
        self.connection_tasks: set[asyncio.Task[None]] = set()
        self.connection_writers: set[asyncio.StreamWriter] = set()
        self.safety_timeout = safety_timeout

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=10):
            raise RuntimeError("benchmark servers did not start")
        if self.error is not None:
            raise RuntimeError("benchmark server startup failed") from self.error

    def stop(self) -> None:
        if self.loop is not None and self.stop_event is not None:
            # A handler failure already stopped and closed the loop; the stored
            # error re-raised below is the root cause worth reporting.
            with suppress(RuntimeError):
                self.loop.call_soon_threadsafe(self.stop_event.set)
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("benchmark servers did not stop")
        if self.error is not None:
            raise RuntimeError("benchmark servers failed") from self.error

    def cpu_ns(self) -> int:
        if self.loop is None:
            return 0
        return int(self._run_on_loop(self._thread_cpu_ns(), self.loop))

    def _run_on_loop(
        self,
        coroutine: Coroutine[Any, Any, Any],
        loop: asyncio.AbstractEventLoop,
    ) -> Any:
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        except RuntimeError:
            coroutine.close()
            self._raise_stored_failure()
            raise
        try:
            return future.result(timeout=SERVER_CALL_TIMEOUT_SECONDS)
        except TimeoutError:
            # Cancel so an abandoned call cannot linger on the loop.
            future.cancel()
            self._raise_stored_failure()
            raise
        except (RuntimeError, concurrent.futures.CancelledError, asyncio.CancelledError):
            # Shutting down after a handler failure cancels still-pending
            # calls; which CancelledError class arrives varies across Python
            # versions, and the stored error is the root cause either way.
            self._raise_stored_failure()
            raise

    def _raise_stored_failure(self) -> None:
        if self.error is not None:
            raise RuntimeError("benchmark servers failed") from self.error

    def prepare_stalled_run(self) -> None:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        self._run_on_loop(self._prepare_stalled_run(), self.loop)

    async def _prepare_stalled_run(self) -> None:
        self.stalled_release = asyncio.Event()
        self.stalled_results = []

    def stalled_run_results(self) -> list[dict[str, int | bool]]:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        return list(self._run_on_loop(self._stalled_run_results(), self.loop))

    async def _stalled_run_results(self) -> list[dict[str, int | bool]]:
        if self.stalled_results is None:
            raise RuntimeError("stalled run was not prepared")
        return list(self.stalled_results)

    def release_stalled_run(self) -> None:
        if self.loop is not None and self.stalled_release is not None:
            # Called from run_one's finally block: never let a dead loop mask
            # the in-flight exception; stop() re-raises the stored root cause.
            with suppress(RuntimeError):
                self.loop.call_soon_threadsafe(self.stalled_release.set)

    def prepare_stream_run(self) -> None:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        self._run_on_loop(self._prepare_stream_run(), self.loop)

    async def _prepare_stream_run(self) -> None:
        self.stream_results = []
        self.stream_aggregate = None

    def prepare_soak_stream_run(self) -> None:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        self._run_on_loop(self._prepare_soak_stream_run(), self.loop)

    async def _prepare_soak_stream_run(self) -> None:
        self.stream_results = None
        self.stream_aggregate = {
            "connections": 0,
            "violations": 0,
            "direction_counts": {},
        }

    def soak_stream_results(
        self, expected_connections: int
    ) -> tuple[dict[str, Any], bool]:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        aggregate, complete = self._run_on_loop(
            self._soak_stream_wait_results(expected_connections), self.loop
        )
        return aggregate, complete

    async def _soak_stream_wait_results(
        self, expected_connections: int
    ) -> tuple[dict[str, Any], bool]:
        if self.stream_aggregate is None:
            raise RuntimeError("soak stream run was not prepared")
        assert self.loop is not None
        deadline = self.loop.time() + STREAM_RESULT_WAIT_SECONDS
        while (
            self.stream_aggregate["connections"] < expected_connections
            and self.loop.time() < deadline
        ):
            await asyncio.sleep(0.005)
        return (
            {
                **self.stream_aggregate,
                "direction_counts": dict(self.stream_aggregate["direction_counts"]),
            },
            self.stream_aggregate["connections"] >= expected_connections,
        )

    def stream_run_results(
        self, expected_connections: int
    ) -> tuple[list[dict[str, Any]], bool]:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        results, complete = self._run_on_loop(
            self._stream_wait_results(expected_connections), self.loop
        )
        return results, complete

    async def _stream_wait_results(
        self, expected_connections: int
    ) -> tuple[list[dict[str, Any]], bool]:
        if self.stream_results is None:
            raise RuntimeError("stream run was not prepared")
        assert self.loop is not None
        deadline = self.loop.time() + STREAM_RESULT_WAIT_SECONDS
        while (
            len(self.stream_results) < expected_connections
            and self.loop.time() < deadline
        ):
            await asyncio.sleep(0.005)
        return (
            list(self.stream_results),
            len(self.stream_results) >= expected_connections,
        )

    async def _thread_cpu_ns(self) -> int:
        return time.thread_time_ns()

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._serve())
        except BaseException as error:
            self.error = error
            self.ready.set()

    async def _serve(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        destination = await asyncio.start_server(
            lambda reader, writer: self._spawn_connection(
                self._handle_destination(reader, writer), writer
            ),
            "127.0.0.1",
            0,
            backlog=65535,
        )
        proxy = await asyncio.start_server(
            lambda reader, writer: self._spawn_connection(
                self._handle_proxy(reader, writer), writer
            ),
            "127.0.0.1",
            0,
            backlog=65535,
        )
        stalled = await asyncio.start_server(
            self._spawn_stalled_connection,
            "127.0.0.1",
            0,
            backlog=65535,
        )
        for stalled_socket in stalled.sockets:
            stalled_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        stream = await asyncio.start_server(
            self._spawn_stream_connection,
            "127.0.0.1",
            0,
            backlog=65535,
        )
        self.destination_port = destination.sockets[0].getsockname()[1]
        self.proxy_port = proxy.sockets[0].getsockname()[1]
        self.stalled_port = stalled.sockets[0].getsockname()[1]
        self.stream_port = stream.sockets[0].getsockname()[1]
        self.ready.set()
        await self.stop_event.wait()
        destination.close()
        proxy.close()
        stalled.close()
        stream.close()
        writers = list(self.connection_writers)
        for writer in writers:
            writer.transport.abort()
        tasks = list(self.connection_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
        await destination.wait_closed()
        await proxy.wait_closed()
        await stalled.wait_closed()
        await stream.wait_closed()

    def _spawn_connection(
        self,
        coroutine: Coroutine[Any, Any, None],
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(coroutine)
        self.connection_tasks.add(task)
        self.connection_writers.add(writer)
        task.add_done_callback(lambda completed: self._connection_done(completed, writer))

    def _spawn_stalled_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # Capture the run state before scheduling the coroutine. The event
        # loop may accept a connection and queue its task while the caller is
        # preparing the next run from another thread.
        release = self.stalled_release
        results = self.stalled_results
        writer.transport.pause_reading()
        self._spawn_connection(
            self._handle_stalled_destination(reader, writer, release, results), writer
        )

    def _spawn_stream_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # Same capture rule as the stalled listener: a late connection from a
        # finished run must not append into the next run's result list.
        results = self.stream_results
        aggregate = self.stream_aggregate
        self._spawn_connection(
            self._handle_stream(reader, writer, results, aggregate), writer
        )

    def _connection_done(
        self,
        task: asyncio.Task[None],
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connection_tasks.discard(task)
        self.connection_writers.discard(writer)
        if task.cancelled():
            return
        try:
            task.result()
        except BaseException as error:
            if self.error is None:
                self.error = error
            if self.stop_event is not None:
                self.stop_event.set()

    @staticmethod
    def _abort_with_reset(writer: asyncio.StreamWriter) -> None:
        # transport.abort() alone sends a FIN when nothing is queued; a hard
        # RST needs SO_LINGER zero on the underlying socket first.
        sock = writer.get_extra_info("socket")
        if sock is not None:
            with suppress(OSError):
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
        writer.transport.abort()

    async def _handle_destination(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _handle_proxy(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            greeting = await reader.readexactly(2)
            if greeting[0] != 5:
                return
            await reader.readexactly(greeting[1])
            if self.proxy_rtt_seconds > 0:
                await asyncio.sleep(self.proxy_rtt_seconds)
            writer.write(b"\x05\x00")
            await writer.drain()

            head = await reader.readexactly(4)
            if head[:3] != b"\x05\x01\x00":
                return
            if head[3] == 1:
                host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
            elif head[3] == 4:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            elif head[3] == 3:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode("ascii")
            else:
                return
            port = int.from_bytes(await reader.readexactly(2), "big")
            if self.proxy_rtt_seconds > 0:
                await asyncio.sleep(self.proxy_rtt_seconds)
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            await writer.drain()
            copy_tasks = [
                asyncio.create_task(self._copy_stream(reader, upstream_writer)),
                asyncio.create_task(self._copy_stream(upstream_reader, writer)),
            ]
            done, pending = await asyncio.wait(
                copy_tasks, return_when=asyncio.FIRST_COMPLETED
            )
            reset_seen = any(task.result() for task in done)
            if not reset_seen and pending:
                done, pending = await asyncio.wait(pending)
                reset_seen = any(task.result() for task in done)
            if reset_seen:
                # Propagate hard resets instead of translating them into a
                # clean FIN, so reset scenarios observe comparable failure
                # signals with and without the proxy in the chain.
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.wait(pending)
                self._abort_with_reset(writer)
                self._abort_with_reset(upstream_writer)
        except (ConnectionError, asyncio.IncompleteReadError, OSError, asyncio.CancelledError):
            pass
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                with suppress(ConnectionError, OSError):
                    await upstream_writer.wait_closed()
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _handle_stalled_destination(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        release: asyncio.Event | None,
        results: list[dict[str, int | bool]] | None,
    ) -> None:
        # The caller captures release/results before this task is scheduled.
        received = 0
        content_ok = True
        saw_eof = False
        try:
            if release is None or results is None:
                raise RuntimeError("stalled run was not prepared")
            await asyncio.wait_for(release.wait(), timeout=self.safety_timeout)
            writer.transport.resume_reading()
            while data := await reader.read(65536):
                received += len(data)
                if data.count(STALLED_PAYLOAD_BYTE) != len(data):
                    content_ok = False
            saw_eof = True
        except (ConnectionError, asyncio.TimeoutError, asyncio.CancelledError):
            pass
        finally:
            if results is not None:
                results.append(
                    {"bytes": received, "content_ok": content_ok, "eof": saw_eof}
                )
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _handle_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        results: list[dict[str, Any]] | None,
        aggregate: dict[str, Any] | None,
    ) -> None:
        record: dict[str, Any] = {
            "header_ok": False,
            "direction": None,
            "received": 0,
            "sent": 0,
            "content_ok": True,
            "eof": False,
            "acked": False,
            "aborted": False,
        }
        try:
            if results is None and aggregate is None:
                raise RuntimeError("stream run was not prepared")
            try:
                header = await reader.readexactly(STREAM_HEADER.size)
            except asyncio.IncompleteReadError:
                return
            magic, direction_code, payload_bytes, aux, aux2 = (
                STREAM_HEADER.unpack(header)
            )
            record["payload_bytes"] = payload_bytes
            record["aux"] = aux
            record["aux2"] = aux2
            if magic != STREAM_MAGIC:
                return
            direction = chr(direction_code)
            record["direction"] = direction
            if direction not in (*STREAM_DIRECTION_CODES.values(), "R"):
                return
            record["header_ok"] = True
            if direction == "U":
                await self._stream_sink(reader, record, aux)
                if (
                    record["eof"]
                    and record["content_ok"]
                    and record["received"] == payload_bytes
                ):
                    writer.write(bytes([STREAM_ACK_BYTE]))
                    await writer.drain()
                    if writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                    record["acked"] = True
                else:
                    # Fail fast: a short or corrupted upload must surface as a
                    # client-visible error, not a hung ack wait.
                    self._abort_with_reset(writer)
            elif direction == "D":
                await self._stream_source(writer, record, payload_bytes)
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                await self._stream_sink(reader, record, 0)
            elif direction == "B":
                await asyncio.gather(
                    self._stream_sink(reader, record, aux),
                    self._stream_source(writer, record, payload_bytes),
                )
                if (
                    record["eof"]
                    and record["content_ok"]
                    and record["received"] == payload_bytes
                ):
                    if writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                else:
                    self._abort_with_reset(writer)
            else:
                # 'R': consume aux2 bytes (0 = the whole request), optionally
                # answer with aux prefix bytes, then abort so the client and
                # any relay in between observe a hard reset.
                consume = aux2 if aux2 else payload_bytes
                remaining = consume
                while remaining > 0:
                    chunk = await reader.read(min(65536, remaining))
                    if not chunk:
                        break
                    record["received"] += len(chunk)
                    if chunk.count(STALLED_PAYLOAD_BYTE) != len(chunk):
                        record["content_ok"] = False
                    remaining -= len(chunk)
                if aux:
                    await self._stream_source(writer, record, aux)
                self._abort_with_reset(writer)
                record["aborted"] = True
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            if results is not None:
                results.append(record)
            if aggregate is not None:
                aggregate["connections"] += 1
                direction = record.get("direction") or "unknown"
                direction_counts = aggregate["direction_counts"]
                direction_counts[direction] = direction_counts.get(direction, 0) + 1
                if not soak_stream_result_is_clean(record):
                    aggregate["violations"] += 1
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _stream_sink(
        self,
        reader: asyncio.StreamReader,
        record: dict[str, Any],
        rate_bytes_per_second: int,
    ) -> None:
        chunk_limit = 16384 if rate_bytes_per_second else 65536
        while True:
            chunk = await reader.read(chunk_limit)
            if not chunk:
                record["eof"] = True
                return
            record["received"] += len(chunk)
            if chunk.count(STALLED_PAYLOAD_BYTE) != len(chunk):
                record["content_ok"] = False
            if rate_bytes_per_second:
                await asyncio.sleep(len(chunk) / rate_bytes_per_second)

    async def _stream_source(
        self,
        writer: asyncio.StreamWriter,
        record: dict[str, Any],
        total_bytes: int,
    ) -> None:
        payload = bytes([STALLED_PAYLOAD_BYTE]) * 65536
        remaining = total_bytes
        while remaining > 0:
            chunk = payload if remaining >= len(payload) else payload[:remaining]
            writer.write(chunk)
            await writer.drain()
            record["sent"] += len(chunk)
            remaining -= len(chunk)

    async def _copy_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """Copy until EOF; return whether a hard reset ended the copy."""
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
        except ConnectionResetError:
            return True
        except (ConnectionError, asyncio.CancelledError):
            pass
        return False


def stalled_server_is_quiescent(
    timed_out: bool,
    expected_flows: int,
    results: list[dict[str, int | bool]],
) -> bool:
    """Return whether the shared stalled listener is safe to reuse."""
    return (
        not timed_out
        and len(results) == expected_flows
        and all(result["eof"] for result in results)
    )


def require_stalled_server_quiescence(run: dict[str, Any]) -> None:
    if run["mode"] != "stalled" or run.get("stalled_server_quiescent") is True:
        return
    raise RuntimeError(
        f"stalled server did not quiesce after {run['scenario']}/{run['variant']}; "
        "aborting before the shared listener can contaminate another run"
    )


def stream_result_is_clean(
    result: dict[str, Any],
    direction: str,
    expected_bytes: int,
) -> bool:
    """Return whether one stream-server connection matched the scenario."""
    code = STREAM_DIRECTION_CODES[direction]
    if (
        not result.get("header_ok")
        or result.get("direction") != code
        or not result.get("content_ok")
    ):
        return False
    if direction == "up":
        return (
            result["received"] == expected_bytes
            and result["eof"]
            and result["acked"]
        )
    if direction == "down":
        return (
            result["sent"] == expected_bytes
            and result["eof"]
            and result["received"] == 0
        )
    return (
        result["received"] == expected_bytes
        and result["sent"] == expected_bytes
        and result["eof"]
    )


def require_stream_server_quiescence(run: dict[str, Any]) -> None:
    if (
        run["mode"] not in ("stream", "fairness", "reset", "soak")
        or run.get("stream_server_quiescent") is True
    ):
        return
    raise RuntimeError(
        f"stream server did not quiesce after {run['scenario']}/{run['variant']}; "
        "aborting before the shared listener can contaminate another run"
    )


def reset_result_is_clean(
    result: dict[str, Any],
    request_bytes: int,
    prefix_bytes: int,
    consume_bytes: int,
) -> bool:
    """Return whether one reset-server connection matched the scenario."""
    expected_consume = consume_bytes if consume_bytes else request_bytes
    return bool(
        result.get("header_ok")
        and result.get("direction") == "R"
        and result.get("content_ok")
        and result.get("aborted")
        and result["received"] == expected_consume
        and result["sent"] == prefix_bytes
    )


def soak_stream_result_is_clean(result: dict[str, Any]) -> bool:
    direction = result.get("direction")
    payload_bytes = result.get("payload_bytes")
    if not isinstance(payload_bytes, int):
        return False
    if direction == "U":
        return stream_result_is_clean(result, "up", payload_bytes)
    if direction == "D":
        return stream_result_is_clean(result, "down", payload_bytes)
    if direction == "B":
        return stream_result_is_clean(result, "bidi", payload_bytes)
    if direction == "R":
        return reset_result_is_clean(
            result,
            payload_bytes,
            result.get("aux") or 0,
            result.get("aux2") or 0,
        )
    return False


def executable(value: str) -> str:
    candidate = Path(value).expanduser()
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate.resolve())
    found = shutil.which(value)
    if found:
        return found
    raise argparse.ArgumentTypeError(f"executable not found: {value}")


def git_commit(value: str) -> str:
    resolved = command_output(
        ["git", "rev-parse", "--verify", f"{value}^{{commit}}"],
        cwd=ROOT,
    )
    if resolved is None:
        raise argparse.ArgumentTypeError(f"git commit not found in {ROOT}: {value}")
    return resolved


def comma_sizes(raw: str) -> list[int]:
    if not raw:
        return []
    try:
        values = [int(value) for value in raw.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from error
    if any(value < 0 for value in values):
        raise argparse.ArgumentTypeError("sizes must be nonnegative")
    return values


def comma_variants(raw: str) -> list[str]:
    values = raw.split(",")
    if not raw or any(not value for value in values):
        raise argparse.ArgumentTypeError("variants must not be empty")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("variants must not contain duplicates")
    unknown = sorted(set(values) - set(VARIANT_ORDER))
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown variants: {', '.join(unknown)}")
    return values


def comma_data_movers(raw: str) -> list[str]:
    values = raw.split(",")
    if not raw or any(not value for value in values):
        raise argparse.ArgumentTypeError("data movers must not be empty")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("data movers must not contain duplicates")
    unknown = sorted(set(values) - set(STABLE_DATA_MOVERS))
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown data movers: {', '.join(unknown)}")
    if "inherited" in values and len(values) > 1:
        raise argparse.ArgumentTypeError(
            "inherited data mover cannot be combined with explicit movers"
        )
    return values


def proxy_rtt_ms(raw: str) -> float:
    value = float(raw)
    # NaN compares false against every bound and would also leak an invalid
    # bare NaN token into environment.json, so demand a finite value here.
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("proxy RTT must be a finite nonnegative number")
    return value


def comma_proxy_sessions(raw: str) -> list[str]:
    values = raw.split(",")
    if not raw or any(not value for value in values):
        raise argparse.ArgumentTypeError("proxy session sources must not be empty")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("proxy session sources must not contain duplicates")
    unknown = sorted(set(values) - set(PROXY_SESSION_SOURCES))
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown proxy session sources: {', '.join(unknown)}")
    if "inherited" in values and len(values) > 1:
        raise argparse.ArgumentTypeError(
            "inherited proxy session source cannot be combined with explicit sources"
        )
    return values


def randomized_execution_order(
    args: argparse.Namespace, rng: random.Random
) -> list[tuple[str, str | None, str | None]]:
    groups: list[list[tuple[str, str | None, str | None]]] = []
    for variant in args.variants:
        if variant == "stable":
            group = [
                (variant, mover, session)
                for mover in args.stable_data_movers
                for session in args.proxy_session_sources
            ]
            rng.shuffle(group)
            groups.append(group)
        else:
            groups.append([(variant, None, None)])
    rng.shuffle(groups)
    return [target for group in groups for target in group]


def variant_environment(
    variant: str,
    data_mover: str | None,
    proxy_session: str | None = None,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    if variant == "stable" and data_mover in ("buffered", "splice"):
        environment["SUP_TCP_DATA_MOVER"] = data_mover
    if variant == "stable" and proxy_session in ("cold", "warm-one-shot"):
        environment["SUP_TCP_PROXY_SESSION"] = proxy_session
    return environment


def comma_directions(raw: str) -> list[str]:
    if not raw:
        return []
    values = raw.split(",")
    if any(not value for value in values):
        raise argparse.ArgumentTypeError("directions must not be empty")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("directions must not contain duplicates")
    unknown = sorted(set(values) - set(STREAM_DIRECTION_CODES))
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown directions: {', '.join(unknown)}")
    return values


def ensure_fd_limit(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    selected_flow_counts = list(args.idle_flows)
    if args.soak_seconds > 0:
        selected_flow_counts.append(512 if args.soak_profile == "standard" else 2)
    if args.payload_sizes:
        selected_flow_counts.append(args.connections)
    if args.stream_flows > 0:
        selected_flow_counts.append(args.stream_flows)
    if args.slow_flows > 0:
        selected_flow_counts.append(args.slow_flows)
    if args.fairness_quiet_flows > 0:
        selected_flow_counts.append(args.fairness_quiet_flows + 1)
    if args.reset_flows > 0:
        selected_flow_counts.append(args.reset_flows)
    if args.stalled_flows > 0:
        selected_flow_counts.append(args.stalled_flows)
    max_flows = max(selected_flow_counts)
    target_need = max_flows + 64
    server_multiplier = 3 if any(variant != "direct" for variant in args.variants) else 1
    server_need = server_multiplier * max_flows + 128
    stable_need = 4 * max_flows + 512 if "stable" in args.variants else 0
    required = max(target_need, server_need, stable_need)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and required > hard:
        parser.error(
            f"selected variants and flows need about {required} fds; hard limit is {hard}"
        )
    if soft != resource.RLIM_INFINITY and soft < required:
        new_soft = required if hard == resource.RLIM_INFINITY else min(required, hard)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
        except (OSError, ValueError) as error:
            parser.error(f"cannot raise RLIMIT_NOFILE from {soft} to {new_soft}: {error}")
    args.estimated_fd_limit = required


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_workload(cc: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread"]
    compiler = command_output([cc, "--version"])
    cache_key = {
        "compiler": compiler,
        "flags": flags,
        "source_sha256": sha256_file(WORKLOAD_SOURCE),
    }
    cache_path = output.with_suffix(output.suffix + ".build.json")
    if output.exists() and cache_path.exists():
        try:
            if json.loads(cache_path.read_text()) == cache_key:
                return
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
    subprocess.run([cc, *flags, str(WORKLOAD_SOURCE), "-o", str(output)], check=True)
    cache_path.write_text(json.dumps(cache_key, indent=2, sort_keys=True) + "\n")


def child_cpu_ns() -> int:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return int((usage.ru_utime + usage.ru_stime) * 1_000_000_000)


def host_cpu_ticks() -> dict[str, int]:
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    values = [int(value) for value in fields]
    return {name: values[index] if index < len(values) else 0 for index, name in enumerate(names)}


def host_cpu_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    delta = {name: after[name] - before[name] for name in before}
    total = sum(delta.values())
    idle = delta["idle"]
    iowait = delta["iowait"]
    return {
        "host_cpu_total_ticks": total,
        "host_cpu_idle_ticks": idle,
        "host_cpu_iowait_ticks": iowait,
        "host_cpu_non_idle_ticks": total - idle - iowait,
    }


_SAMPLE_DENIED_WARNED: set[int] = set()

_NS_PER_CLOCK_TICK = 1_000_000_000 // os.sysconf("SC_CLK_TCK")


def process_cpu_ns(pid: int) -> int | None:
    """Return utime+stime of one process (excluding children) in nanoseconds."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat.rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) * _NS_PER_CLOCK_TICK
    except (OSError, IndexError, ValueError):
        return None


def start_perf_stat(
    events: str, pid: int, output_path: Path
) -> subprocess.Popen[str] | None:
    command = [
        "perf",
        "stat",
        "-x",
        ",",
        "-e",
        events,
        "--pid",
        str(pid),
        "-o",
        str(output_path),
    ]
    try:
        return subprocess.Popen(
            command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
    except OSError:
        return None


def parse_perf_stat_csv(text: str) -> list[dict[str, str]]:
    counters = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        counters.append({"value": parts[0], "unit": parts[1], "event": parts[2]})
    return counters


def process_resources(pid: int) -> dict[str, int] | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text().splitlines()
        rss_line = next(line for line in status if line.startswith("VmRSS:"))
        hwm_line = next(line for line in status if line.startswith("VmHWM:"))
        fd_count = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        return {
            "rss_kib": int(rss_line.split()[1]),
            "rss_hwm_kib": int(hwm_line.split()[1]),
            "fds": fd_count,
        }
    except PermissionError:
        # Unlike an exit race this hides the process for the whole run (for
        # example hidepid or a setuid target); say so once instead of silently
        # reporting null peaks.
        if pid not in _SAMPLE_DENIED_WARNED:
            _SAMPLE_DENIED_WARNED.add(pid)
            print(
                f"warning: cannot sample /proc/{pid}: permission denied",
                file=sys.stderr,
            )
        return None
    except (OSError, StopIteration, ValueError):
        return None


def direct_child_pids(pid: int) -> list[int]:
    try:
        raw = Path(f"/proc/{pid}/task/{pid}/children").read_text()
    except OSError:
        return []
    return [int(value) for value in raw.split()]


def process_tree_pids(root_pid: int) -> list[int]:
    found: list[int] = []
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        found.append(pid)
        pending.extend(direct_child_pids(pid))
    return found


def update_process_peak(peaks: dict[str, int | None], sample: dict[str, int] | None) -> None:
    if sample is None:
        return
    for source, destination in (
        ("rss_kib", "rss_sampled_peak_kib"),
        ("rss_hwm_kib", "rss_hwm_kib"),
        ("fds", "fd_sampled_peak"),
    ):
        previous = peaks[destination]
        peaks[destination] = sample[source] if previous is None else max(previous, sample[source])


def empty_process_peaks() -> dict[str, int | None]:
    return {
        "rss_sampled_peak_kib": None,
        "rss_hwm_kib": None,
        "fd_sampled_peak": None,
    }


def percentile(values: list[int | float], fraction: float) -> float:
    ordered = sorted(float(value) for value in values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def median_field(runs: list[dict[str, Any]], field: str) -> float | None:
    values = [run[field] for run in runs if run.get(field) is not None]
    return statistics.median(values) if values else None


def max_field(runs: list[dict[str, Any]], field: str) -> int | None:
    values = [run[field] for run in runs if run.get(field) is not None]
    return max(values) if values else None


def parse_workload_output(
    stdout: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    flows = [record for record in records if record.get("event") == "flow"]
    samples = [record for record in records if record.get("event") == "sample"]
    summaries = [record for record in records if record.get("event") == "workload_summary"]
    if len(summaries) != 1:
        raise ValueError(f"expected one workload summary, got {len(summaries)}")
    return flows, samples, summaries[0]


def stalled_undersized_flow_count(
    flows: list[dict[str, Any]], bytes_per_flow: int
) -> int:
    """Count stalled flows that absorbed the whole payload without blocking.

    Such flows mean the relay chain's elasticity exceeded the configured
    payload, so the run never exercised backpressure: a calibration failure
    (raise --stalled-bytes), distinct from a backpressure violation.
    """
    return sum(
        1
        for flow in flows
        if not flow.get("blocked")
        and flow.get("errno") == 0
        and flow.get("accepted_bytes") == bytes_per_flow
    )


def workload_flows_are_valid(flows: list[dict[str, Any]], expected: int) -> bool:
    return (
        len(flows) == expected
        and {flow.get("flow") for flow in flows} == set(range(expected))
        and all(flow.get("ok") for flow in flows)
    )


def parse_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    try:
        lines = path.read_bytes().splitlines()
    except OSError as error:
        return events, [{"line": None, "error": str(error), "fragment": None}]
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            line = raw.decode("utf-8")
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("JSONL record is not an object")
            events.append(event)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            errors.append(
                {
                    "line": line_number,
                    "error": str(error),
                    "fragment": raw[:200].decode("utf-8", errors="backslashreplace"),
                }
            )
    return events, errors


def parse_run_summaries_streaming(
    path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summaries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    try:
        metric_file = path.open("rb")
    except OSError as error:
        return summaries, [{"line": None, "error": str(error), "fragment": None}]
    with metric_file:
        for line_number, raw in enumerate(metric_file, start=1):
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
                if not isinstance(event, dict):
                    raise ValueError("JSONL record is not an object")
                if event.get("event") == "run_summary":
                    summaries.append(event)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                errors.append(
                    {
                        "line": line_number,
                        "error": str(error),
                        "fragment": raw[:200].decode(
                            "utf-8", errors="backslashreplace"
                        ),
                    }
                )
    return summaries, errors


TCP_SETUP_STAGE_FIELDS = (
    "queue_wait_ns",
    "fd_inspection_ns",
    "proxy_connect_ns",
    "proxy_handshake_ns",
    "loopback_connect_accept_ns",
    "broker_register_ns",
    "notification_reply_ns",
)


def tcp_setup_stage_stats(values: list[int]) -> dict[str, float | int]:
    return {
        "sum_ns": sum(values),
        "mean_ns": sum(values) / len(values),
        "p50_ns": percentile(values, 0.50),
        "p95_ns": percentile(values, 0.95),
        "p99_ns": percentile(values, 0.99),
        "max_ns": max(values),
    }


def summarize_tcp_setup_stages(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    setups = [event for event in events if event.get("event") == "tcp_setup"]
    if not setups:
        return None
    completed = [event for event in setups if event.get("outcome") == "completed"]
    failure_stage_counts: dict[str, int] = {}
    for event in setups:
        if event.get("outcome") != "completed":
            stage = event.get("failure_stage") or "unknown"
            failure_stage_counts[stage] = failure_stage_counts.get(stage, 0) + 1
    summary: dict[str, Any] = {
        "setup_events": len(setups),
        "completed_events": len(completed),
        "failure_stage_counts": failure_stage_counts,
    }
    if not completed:
        return summary
    total_values = [
        (event.get("queue_wait_ns") or 0) + (event.get("handler_ns") or 0)
        for event in completed
    ]
    total_sum = sum(total_values)
    stages: dict[str, Any] = {}
    handler_stage_sum = 0
    for field in TCP_SETUP_STAGE_FIELDS:
        values = [event.get(field) or 0 for event in completed]
        stats = tcp_setup_stage_stats(values)
        if total_sum:
            stats["share_of_total"] = stats["sum_ns"] / total_sum
        stages[field.removesuffix("_ns")] = stats
        if field != "queue_wait_ns":
            handler_stage_sum += stats["sum_ns"]
    residual_values = [
        (event.get("handler_ns") or 0)
        - sum(
            event.get(field) or 0
            for field in TCP_SETUP_STAGE_FIELDS
            if field != "queue_wait_ns"
        )
        for event in completed
    ]
    residual = tcp_setup_stage_stats(residual_values)
    if total_sum:
        residual["share_of_total"] = residual["sum_ns"] / total_sum
    stages["handler_residual"] = residual
    summary["total"] = tcp_setup_stage_stats(total_values)
    summary["handler"] = tcp_setup_stage_stats(
        [event.get("handler_ns") or 0 for event in completed]
    )
    summary["stages"] = stages
    return summary


def terminate_process_group(process: subprocess.Popen[str], grace_seconds: float = 2.0) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def interrupt_benchmark(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def linear_slope(points: list[tuple[float, float]]) -> float | None:
    if len(points) < 2:
        return None
    x_mean = statistics.mean(point[0] for point in points)
    y_mean = statistics.mean(point[1] for point in points)
    denominator = sum((x - x_mean) ** 2 for x, _y in points)
    if denominator == 0:
        return None
    return sum((x - x_mean) * (y - y_mean) for x, y in points) / denominator


def soak_resource_acceptance(
    samples: list[dict[str, Any]], cycles: int, profile: str
) -> dict[str, Any]:
    boundaries = [sample for sample in samples if sample["kind"] == "cycle_boundary"]
    minimum_cycles = 30 if profile == "standard" else 1
    reasons: list[str] = []
    if cycles < minimum_cycles:
        reasons.append(f"requires {minimum_cycles} cycles, got {cycles}")
    if len(boundaries) != cycles:
        reasons.append(f"requires {cycles} boundary samples, got {len(boundaries)}")

    first = boundaries[0] if boundaries else None
    last = boundaries[-1] if boundaries else None
    fd_deltas: dict[str, int | None] = {}
    rss_growth_kib: dict[str, int | None] = {}
    if first is not None and last is not None:
        for role in ("supervisor", "target"):
            first_role = first.get(role)
            last_role = last.get(role)
            if first_role is None or last_role is None:
                reasons.append(f"missing {role} boundary resources")
                fd_deltas[role] = None
                rss_growth_kib[role] = None
                continue
            fd_delta = last_role["fds"] - first_role["fds"]
            rss_growth = last_role["rss_kib"] - first_role["rss_kib"]
            fd_deltas[role] = fd_delta
            rss_growth_kib[role] = rss_growth
            if fd_delta != 0:
                reasons.append(f"{role} quiescent fd delta is {fd_delta}, expected 0")
            rss_limit = max(8192, int(first_role["rss_kib"] * 0.10))
            if rss_growth > rss_limit:
                reasons.append(
                    f"{role} RSS grew {rss_growth} KiB, limit is {rss_limit} KiB"
                )

    slope_boundaries = boundaries[9:] if len(boundaries) > 10 else boundaries
    rss_points = [
        (
            sample["elapsed_ns"] / 3_600_000_000_000,
            float(sample["supervisor"]["rss_kib"] + sample["target"]["rss_kib"]),
        )
        for sample in slope_boundaries
        if sample.get("supervisor") is not None and sample.get("target") is not None
    ]
    rss_slope_kib_per_hour = linear_slope(rss_points)
    if rss_slope_kib_per_hour is not None and rss_slope_kib_per_hour > 4096:
        reasons.append(
            f"combined RSS slope is {rss_slope_kib_per_hour:.1f} KiB/hour, limit is 4096"
        )
    return {
        "passed": not reasons,
        "reasons": reasons,
        "minimum_cycles": minimum_cycles,
        "cycles": cycles,
        "boundary_samples": len(boundaries),
        "fd_deltas": fd_deltas,
        "rss_growth_kib": rss_growth_kib,
        "combined_rss_slope_kib_per_hour": rss_slope_kib_per_hour,
    }


def variant_command(
    variant: str,
    args: argparse.Namespace,
    servers: BenchmarkServers,
    scenario: dict[str, Any],
    metrics_path: Path | None = None,
    stalled_ready_path: Path | None = None,
    idle_ready_path: Path | None = None,
    soak_progress_path: Path | None = None,
    soak_ack_path: Path | None = None,
) -> list[str]:
    if scenario["mode"] == "soak":
        if soak_progress_path is None or soak_ack_path is None:
            raise ValueError("soak workload requires progress and ack paths")
        workload = [
            str(args.workload),
            "soak",
            "127.0.0.1",
            str(servers.destination_port),
            str(servers.stream_port),
            str(scenario["duration_seconds"]),
            scenario["profile"],
            str(soak_progress_path),
            str(soak_ack_path),
        ]
    elif scenario["mode"] == "fairness":
        workload = [
            str(args.workload),
            "fairness",
            "127.0.0.1",
            str(servers.destination_port),
            str(servers.stream_port),
            str(scenario["quiet_flows"]),
            str(scenario["quiet_iterations"]),
            str(scenario["value"]),
            str(scenario["hot_bytes"]),
        ]
    else:
        if scenario["mode"] == "stalled":
            destination_port = servers.stalled_port
        elif scenario["mode"] in ("stream", "reset"):
            destination_port = servers.stream_port
        else:
            destination_port = servers.destination_port
        workload = [
            str(args.workload),
            scenario["mode"],
            "127.0.0.1",
            str(destination_port),
            str(scenario["flows"]),
            str(scenario["value"]),
        ]
        if scenario["mode"] == "stalled":
            workload.append(str(scenario["hold_ms"]))
            if stalled_ready_path is None:
                raise ValueError("stalled workload requires a ready path")
            workload.append(str(stalled_ready_path))
        if scenario["mode"] == "idle" and idle_ready_path is not None:
            workload.append(str(idle_ready_path))
        if scenario["mode"] == "stream":
            workload.append(scenario["direction"])
            workload.append(str(scenario["rate"]))
        if scenario["mode"] == "reset":
            workload.append(str(scenario["prefix"]))
            workload.append(str(scenario["consume"]))
    if variant == "direct":
        return workload
    yatht = args.yatht
    if yatht is None:
        raise ValueError("missing yatht binary")
    command = [
        yatht,
        "--proxy",
        f"socks5://127.0.0.1:{servers.proxy_port}",
        "--proxy-local",
    ]
    if metrics_path is not None:
        command += ["--metrics-file", str(metrics_path)]
    return command + ["--"] + workload


def run_one(
    variant: str,
    data_mover: str | None,
    proxy_session: str | None,
    args: argparse.Namespace,
    servers: BenchmarkServers,
    scenario: dict[str, Any],
    repetition: int,
    measurement_kind: str,
    metrics_path: Path | None,
    resource_samples_path: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="yatht-benchmark-control-") as control_dir:
        stalled_ready_path = Path(control_dir) / "stalled-ready"
        idle_ready_path = Path(control_dir) / "idle-ready"
        perf_output_path = Path(control_dir) / "perf-stat.csv"
        soak_progress_path = Path(control_dir) / "soak-progress"
        soak_ack_path = Path(control_dir) / "soak-ack"
        if scenario["mode"] == "stalled":
            servers.prepare_stalled_run()
        if scenario["mode"] in ("stream", "fairness", "reset"):
            servers.prepare_stream_run()
        if scenario["mode"] == "soak":
            servers.prepare_soak_stream_run()
        command = variant_command(
            variant,
            args,
            servers,
            scenario,
            metrics_path,
            stalled_ready_path if scenario["mode"] == "stalled" else None,
            idle_ready_path if scenario["mode"] == "idle" else None,
            soak_progress_path if scenario["mode"] == "soak" else None,
            soak_ack_path if scenario["mode"] == "soak" else None,
        )
        process_environment = variant_environment(variant, data_mover, proxy_session)
        env_prefix = []
        if variant == "stable" and data_mover in ("buffered", "splice"):
            env_prefix.append(f"SUP_TCP_DATA_MOVER={data_mover}")
        if variant == "stable" and proxy_session in ("cold", "warm-one-shot"):
            env_prefix.append(f"SUP_TCP_PROXY_SESSION={proxy_session}")
        logged_command = ["env", *env_prefix, *command] if env_prefix else command
        args.command_log.write(shlex.join(logged_command) + "\n")
        args.command_log.flush()
        child_before = child_cpu_ns()
        benchmark_server_before = servers.cpu_ns()
        host_cpu_before = host_cpu_ticks()
        started = time.perf_counter_ns()
        timed_out = False
        stalled_ready = False
        stalled_ready_flows: int | None = None
        stalled_released = False
        release_at: float | None = None
        idle_ready = False
        idle_ready_flows: int | None = None
        idle_ready_wall_ns: int | None = None
        supervisor_cpu_sampled_ns: int | None = None
        target_cpu_sampled_ns: int | None = None
        supervisor_cpu_at_idle_ready_ns: int | None = None
        target_cpu_at_idle_ready_ns: int | None = None
        perf_process: subprocess.Popen[str] | None = None
        supervisor_peaks = empty_process_peaks()
        target_peaks = empty_process_peaks()
        server_peaks = empty_process_peaks()
        process_tree_rss_sampled_peak_kib: int | None = None
        process_tree_fd_sampled_peak: int | None = None
        supervisor_pid: int | None = None
        target_pid: int | None = None
        soak_last_cycle = 0
        soak_resource_samples: list[dict[str, Any]] = []
        next_soak_resource_sample = time.monotonic()
        with tempfile.TemporaryFile(mode="w+") as stdout_file, tempfile.TemporaryFile(
            mode="w+"
        ) as stderr_file:
            process: subprocess.Popen[str] | None = None
            try:
                process = subprocess.Popen(
                    command,
                    text=True,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                    env=process_environment,
                )
                if variant == "direct":
                    target_pid = process.pid
                else:
                    supervisor_pid = process.pid
                if args.perf_stat_events and measurement_kind == "diagnostic":
                    perf_process = start_perf_stat(
                        args.perf_stat_events, process.pid, perf_output_path
                    )
                deadline = time.monotonic() + args.timeout
                iteration = 0
                while process.poll() is None:
                    if supervisor_pid is not None:
                        update_process_peak(supervisor_peaks, process_resources(supervisor_pid))
                        if target_pid is None:
                            children = direct_child_pids(supervisor_pid)
                            if children:
                                target_pid = children[0]
                    if target_pid is not None:
                        update_process_peak(target_peaks, process_resources(target_pid))
                    update_process_peak(server_peaks, process_resources(os.getpid()))
                    if supervisor_pid is not None:
                        sampled_cpu = process_cpu_ns(supervisor_pid)
                        if sampled_cpu is not None:
                            supervisor_cpu_sampled_ns = sampled_cpu
                    if target_pid is not None:
                        sampled_cpu = process_cpu_ns(target_pid)
                        if sampled_cpu is not None:
                            target_cpu_sampled_ns = sampled_cpu
                    if iteration % TREE_SAMPLE_STRIDE == 0:
                        tree_samples = [
                            sample
                            for pid in process_tree_pids(process.pid)
                            if (sample := process_resources(pid)) is not None
                        ]
                        if tree_samples:
                            tree_rss = sum(sample["rss_kib"] for sample in tree_samples)
                            tree_fds = sum(sample["fds"] for sample in tree_samples)
                            process_tree_rss_sampled_peak_kib = max(
                                process_tree_rss_sampled_peak_kib or 0, tree_rss
                            )
                            process_tree_fd_sampled_peak = max(
                                process_tree_fd_sampled_peak or 0, tree_fds
                            )
                    iteration += 1
                    now = time.monotonic()
                    if scenario["mode"] == "soak" and now >= next_soak_resource_sample:
                        sample = {
                            "kind": "periodic",
                            "cycle": soak_last_cycle,
                            "elapsed_ns": time.perf_counter_ns() - started,
                            "supervisor": process_resources(supervisor_pid)
                            if supervisor_pid is not None
                            else None,
                            "target": process_resources(target_pid)
                            if target_pid is not None
                            else None,
                            "benchmark_server": process_resources(os.getpid()),
                        }
                        soak_resource_samples.append(sample)
                        if resource_samples_path is not None:
                            with resource_samples_path.open("a") as resource_file:
                                resource_file.write(json.dumps(sample, sort_keys=True) + "\n")
                        next_soak_resource_sample = now + SOAK_SAMPLE_INTERVAL_SECONDS
                    if scenario["mode"] == "soak" and soak_progress_path.exists():
                        try:
                            completed_cycle = int(soak_progress_path.read_text().strip())
                        except (OSError, ValueError):
                            pass
                        else:
                            if completed_cycle > soak_last_cycle:
                                soak_last_cycle = completed_cycle
                                sample = {
                                    "kind": "cycle_boundary",
                                    "cycle": completed_cycle,
                                    "elapsed_ns": time.perf_counter_ns() - started,
                                    "supervisor": process_resources(supervisor_pid)
                                    if supervisor_pid is not None
                                    else None,
                                    "target": process_resources(target_pid)
                                    if target_pid is not None
                                    else None,
                                    "benchmark_server": process_resources(os.getpid()),
                                }
                                soak_resource_samples.append(sample)
                                if resource_samples_path is not None:
                                    with resource_samples_path.open("a") as resource_file:
                                        resource_file.write(
                                            json.dumps(sample, sort_keys=True) + "\n"
                                        )
                                soak_ack_path.write_text(f"{completed_cycle}\n")
                    if scenario["mode"] == "idle" and not idle_ready:
                        if idle_ready_path.exists():
                            try:
                                idle_ready_flows = int(
                                    idle_ready_path.read_text().strip()
                                )
                            except (OSError, ValueError):
                                pass
                            else:
                                # Registration/steady boundary: everything the
                                # supervisor burns after this point is idle
                                # readiness cost, not connection setup.
                                idle_ready = True
                                idle_ready_wall_ns = time.perf_counter_ns() - started
                                supervisor_cpu_at_idle_ready_ns = (
                                    supervisor_cpu_sampled_ns
                                )
                                target_cpu_at_idle_ready_ns = target_cpu_sampled_ns
                    if scenario["mode"] == "stalled" and not stalled_ready:
                        if stalled_ready_path.exists():
                            try:
                                stalled_ready_flows = int(
                                    stalled_ready_path.read_text().strip()
                                )
                            except (OSError, ValueError):
                                pass
                            else:
                                stalled_ready = True
                                release_at = now + scenario["hold_ms"] / 1000
                    if release_at is not None and now >= release_at and not stalled_released:
                        servers.release_stalled_run()
                        stalled_released = True
                    if now >= deadline:
                        timed_out = True
                        terminate_process_group(process)
                        break
                    time.sleep(
                        SOAK_POLL_INTERVAL_SECONDS
                        if scenario["mode"] == "soak"
                        else SAMPLE_INTERVAL_SECONDS
                    )
            finally:
                if scenario["mode"] == "stalled" and not stalled_released:
                    servers.release_stalled_run()
                if process is not None:
                    terminate_process_group(process)
            assert process is not None
            returncode = process.wait()
            stdout_file.seek(0)
            stderr_file.seek(0)
            completed = subprocess.CompletedProcess(
                command,
                124 if timed_out else returncode,
                stdout_file.read(),
                stderr_file.read(),
            )
        perf_stat: dict[str, Any] | None = None
        if perf_process is not None:
            try:
                perf_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                perf_process.send_signal(signal.SIGINT)
                with suppress(subprocess.TimeoutExpired):
                    perf_process.wait(timeout=5)
                if perf_process.poll() is None:
                    perf_process.kill()
                    perf_process.wait()
            perf_stderr = perf_process.stderr.read() if perf_process.stderr else ""
            try:
                perf_csv = perf_output_path.read_text()
            except OSError:
                perf_csv = ""
            perf_stat = {
                "events": args.perf_stat_events,
                "returncode": perf_process.returncode,
                "counters": parse_perf_stat_csv(perf_csv),
                "stderr": perf_stderr[-2000:],
            }
    wall_ns = time.perf_counter_ns() - started
    host_cpu_after = host_cpu_ticks()
    benchmark_server_cpu_ns = servers.cpu_ns() - benchmark_server_before
    child_delta_ns = child_cpu_ns() - child_before
    stalled_server_results = (
        servers.stalled_run_results() if scenario["mode"] == "stalled" else None
    )
    stream_server_results: list[dict[str, Any]] | None = None
    stream_results_complete: bool | None = None
    if scenario["mode"] in ("stream", "fairness", "reset"):
        expected_stream_connections = (
            1 if scenario["mode"] == "fairness" else scenario["flows"]
        )
        stream_server_results, stream_results_complete = servers.stream_run_results(
            expected_stream_connections
        )

    parse_error = None
    try:
        flows, workload_samples, workload_summary = parse_workload_output(
            completed.stdout
        )
    except (json.JSONDecodeError, ValueError) as error:
        flows, workload_samples, workload_summary = [], [], {}
        parse_error = str(error)

    soak_stream_aggregate: dict[str, Any] | None = None
    if scenario["mode"] == "soak" and parse_error is None:
        expected_stream_connections = workload_summary.get("stream_connections")
        if isinstance(expected_stream_connections, int):
            soak_stream_aggregate, stream_results_complete = servers.soak_stream_results(
                expected_stream_connections
            )

    metric_summary: dict[str, Any] | None = None
    metric_parse_errors: list[dict[str, Any]] = []
    tcp_setup_stage_summary: dict[str, Any] | None = None
    if metrics_path is not None:
        if scenario["mode"] == "soak":
            summaries, metric_parse_errors = parse_run_summaries_streaming(metrics_path)
            metric_events: list[dict[str, Any]] = []
        else:
            metric_events, metric_parse_errors = parse_jsonl(metrics_path)
            summaries = [
                event for event in metric_events if event.get("event") == "run_summary"
            ]
        if len(summaries) == 1:
            metric_summary = summaries[0]
        else:
            metric_parse_errors.append(
                {
                    "line": None,
                    "error": f"expected one run summary, got {len(summaries)}",
                    "fragment": None,
                }
            )
        if scenario["mode"] != "soak":
            tcp_setup_stage_summary = summarize_tcp_setup_stages(metric_events)

    successful = [flow for flow in flows if flow.get("ok")]
    if scenario["mode"] == "soak":
        ok = bool(
            completed.returncode == 0
            and parse_error is None
            and workload_summary.get("mode") == "soak"
            and workload_summary.get("cycles", 0) > 0
            and workload_summary.get("successful") == workload_summary.get("flows")
            and workload_summary.get("failed_phase") is None
            and workload_summary.get("phase_returncode") == 0
        )
    else:
        ok = (
            completed.returncode == 0
            and parse_error is None
            and workload_flows_are_valid(flows, scenario["flows"])
        )
    stalled_server_connections: int | None = None
    stalled_server_corrupt_connections: int | None = None
    stalled_server_byte_mismatch_connections: int | None = None
    stalled_server_incomplete_connections: int | None = None
    stalled_server_quiescent: bool | None = None
    stalled_undersized_flows: int | None = None
    if scenario["mode"] == "stalled":
        assert stalled_server_results is not None
        stalled_undersized_flows = stalled_undersized_flow_count(
            flows, scenario["value"]
        )
        stalled_server_connections = len(stalled_server_results)
        stalled_server_corrupt_connections = sum(
            1 for result in stalled_server_results if not result["content_ok"]
        )
        stalled_server_byte_mismatch_connections = sum(
            1 for result in stalled_server_results if result["bytes"] != scenario["value"]
        )
        stalled_server_incomplete_connections = sum(
            1 for result in stalled_server_results if not result["eof"]
        )
        stalled_server_quiescent = stalled_server_is_quiescent(
            timed_out, scenario["flows"], stalled_server_results
        )
        ok = (
            ok
            and stalled_ready
            and stalled_ready_flows == scenario["flows"]
            and stalled_released
            and workload_summary.get("blocked_flows") == scenario["flows"]
            and stalled_server_connections == scenario["flows"]
            and stalled_server_corrupt_connections == 0
            and stalled_server_byte_mismatch_connections == 0
            and stalled_server_incomplete_connections == 0
        )
    stream_server_connections: int | None = None
    stream_server_violations: int | None = None
    stream_server_quiescent: bool | None = None
    fairness_quiet_samples: int | None = None
    reset_outcome_counts: dict[str, int] | None = None
    if scenario["mode"] == "stream":
        assert stream_server_results is not None
        stream_server_connections = len(stream_server_results)
        stream_server_violations = sum(
            1
            for result in stream_server_results
            if not stream_result_is_clean(
                result, scenario["direction"], scenario["value"]
            )
        )
        stream_server_quiescent = (
            stream_results_complete is True
            and stream_server_connections == scenario["flows"]
        )
        expected_payload_total = (
            scenario["flows"]
            * scenario["value"]
            * (2 if scenario["direction"] == "bidi" else 1)
        )
        ok = (
            ok
            and stream_server_connections == scenario["flows"]
            and stream_server_violations == 0
            and workload_summary.get("bytes") == expected_payload_total
        )
    if scenario["mode"] == "fairness":
        assert stream_server_results is not None
        stream_server_connections = len(stream_server_results)
        stream_server_violations = sum(
            1
            for result in stream_server_results
            if not stream_result_is_clean(result, "up", scenario["hot_bytes"])
        )
        stream_server_quiescent = (
            stream_results_complete is True and stream_server_connections == 1
        )
        quiet_expected = scenario["quiet_flows"] * scenario["quiet_iterations"]
        fairness_quiet_samples = sum(
            1 for sample in workload_samples if sample.get("kind") == "quiet_echo"
        )
        expected_payload_total = (
            scenario["hot_bytes"] + 2 * scenario["value"] * quiet_expected
        )
        ok = (
            ok
            and stream_server_connections == 1
            and stream_server_violations == 0
            and fairness_quiet_samples == quiet_expected
            and workload_summary.get("bytes") == expected_payload_total
        )
    if scenario["mode"] == "idle":
        ok = ok and idle_ready and idle_ready_flows == scenario["flows"]
    if scenario["mode"] == "reset":
        assert stream_server_results is not None
        stream_server_connections = len(stream_server_results)
        stream_server_violations = sum(
            1
            for result in stream_server_results
            if not reset_result_is_clean(
                result, scenario["value"], scenario["prefix"], scenario["consume"]
            )
        )
        stream_server_quiescent = (
            stream_results_complete is True
            and stream_server_connections == scenario["flows"]
        )
        reset_outcome_counts = {
            "reset": sum(1 for flow in flows if flow.get("outcome") == "reset"),
            "eof": sum(1 for flow in flows if flow.get("outcome") == "eof"),
        }
        ok = (
            ok
            and stream_server_connections == scenario["flows"]
            and stream_server_violations == 0
        )
    if scenario["mode"] == "soak":
        stream_server_connections = (
            soak_stream_aggregate.get("connections")
            if soak_stream_aggregate is not None
            else None
        )
        stream_server_violations = (
            soak_stream_aggregate.get("violations")
            if soak_stream_aggregate is not None
            else None
        )
        stream_server_quiescent = bool(
            stream_results_complete is True
            and soak_stream_aggregate is not None
            and stream_server_connections == workload_summary.get("stream_connections")
        )
        ok = ok and stream_server_quiescent and stream_server_violations == 0
    if metric_summary is not None and metric_summary.get("dropped_metric_events") != 0:
        ok = False
    if metrics_path is not None:
        ok = ok and metric_summary is not None and not metric_parse_errors
        if metric_summary is not None:
            ok = ok and metric_summary.get("schema_version") == METRICS_SCHEMA_VERSION
            expected_setup_flows = (
                workload_summary.get("flows")
                if scenario["mode"] == "soak"
                else scenario["flows"]
            )
            ok = ok and metric_summary.get("tcp_setup_completed") == expected_setup_flows
            ok = ok and metric_summary.get("tcp_active_flows") == 0
            ok = ok and metric_summary.get("tcp_pending_bytes") == 0
            ok = ok and metric_summary.get("tcp_reserved_pending_bytes") == 0
            ok = ok and metric_summary.get("tcp_buffer_capacity_bytes") == 0
            outcomes = sum(
                metric_summary.get(field, 0)
                for field in (
                    "tcp_flows_completed",
                    "tcp_flow_failures",
                    "tcp_flows_cancelled",
                )
            )
            ok = ok and outcomes == metric_summary.get("tcp_flows_started")
            if scenario["mode"] == "soak":
                ok = ok and metric_summary.get("tcp_pipe_bytes") == 0
                ok = ok and metric_summary.get("tcp_splice_fallbacks") == 0
    run = {
        "scenario": scenario["name"],
        "mode": scenario["mode"],
        "variant": variant,
        "data_mover": data_mover,
        "proxy_session_source": proxy_session,
        "stream_bytes_per_flow": (
            scenario["value"] if scenario["mode"] == "stream" else None
        ),
        "stream_direction": scenario.get("direction"),
        "measurement_kind": measurement_kind,
        "repetition": repetition,
        "ok": ok,
        "returncode": completed.returncode,
        "timed_out": timed_out,
        "stalled_ready": stalled_ready if scenario["mode"] == "stalled" else None,
        "stalled_ready_flows": (
            stalled_ready_flows if scenario["mode"] == "stalled" else None
        ),
        "stalled_released": stalled_released if scenario["mode"] == "stalled" else None,
        "application_backpressure_confirmed": (
            stalled_ready and workload_summary.get("blocked_flows") == scenario["flows"]
            if scenario["mode"] == "stalled"
            else None
        ),
        "stalled_server_connections": stalled_server_connections,
        "stalled_server_corrupt_connections": stalled_server_corrupt_connections,
        "stalled_server_byte_mismatch_connections": stalled_server_byte_mismatch_connections,
        "stalled_server_incomplete_connections": stalled_server_incomplete_connections,
        "stalled_server_quiescent": stalled_server_quiescent,
        "stalled_undersized_flows": stalled_undersized_flows,
        "stream_server_connections": stream_server_connections,
        "stream_server_violations": stream_server_violations,
        "stream_server_quiescent": stream_server_quiescent,
        "fairness_quiet_samples": fairness_quiet_samples,
        "reset_outcome_counts": reset_outcome_counts,
        "idle_ready": idle_ready if scenario["mode"] == "idle" else None,
        "idle_ready_flows": idle_ready_flows if scenario["mode"] == "idle" else None,
        "idle_ready_wall_ns": idle_ready_wall_ns,
        "supervisor_cpu_sampled_ns": supervisor_cpu_sampled_ns,
        "target_cpu_sampled_ns": target_cpu_sampled_ns,
        "supervisor_cpu_at_idle_ready_ns": supervisor_cpu_at_idle_ready_ns,
        "target_cpu_at_idle_ready_ns": target_cpu_at_idle_ready_ns,
        "perf_stat": perf_stat,
        "broker_pending_peak_bytes": (
            metric_summary.get("tcp_peak_pending_bytes")
            if scenario["mode"] == "stalled" and metric_summary is not None
            else None
        ),
        "expected_flows": (
            workload_summary.get("flows", 0)
            if scenario["mode"] == "soak"
            else scenario["flows"]
        ),
        "successful_flows": (
            workload_summary.get("successful", 0)
            if scenario["mode"] == "soak"
            else len(successful)
        ),
        "wall_ns": wall_ns,
        "child_cpu_ns": child_delta_ns,
        "benchmark_server_cpu_ns": benchmark_server_cpu_ns,
        "supervisor_pid": supervisor_pid,
        "target_pid": target_pid,
        "benchmark_server_pid": os.getpid(),
        **{f"supervisor_{key}": value for key, value in supervisor_peaks.items()},
        **{f"target_{key}": value for key, value in target_peaks.items()},
        **{f"benchmark_server_{key}": value for key, value in server_peaks.items()},
        "process_tree_rss_sampled_peak_kib": process_tree_rss_sampled_peak_kib,
        "process_tree_fd_sampled_peak": process_tree_fd_sampled_peak,
        **host_cpu_delta(host_cpu_before, host_cpu_after),
        "target_user_cpu_ns": workload_summary.get("user_cpu_ns"),
        "target_system_cpu_ns": workload_summary.get("system_cpu_ns"),
        "bytes": workload_summary.get("bytes", 0),
        "parse_error": parse_error,
        "stderr": completed.stderr[-2000:],
        "command": logged_command,
        "metrics_file": str(metrics_path) if metrics_path is not None else None,
        "metric_summary": metric_summary,
        "metric_parse_errors": metric_parse_errors,
        "tcp_setup_stage_summary": tcp_setup_stage_summary,
        "soak_resource_samples": soak_resource_samples,
        "soak_cycles": workload_summary.get("cycles")
        if scenario["mode"] == "soak"
        else None,
        "soak_stream_aggregate": soak_stream_aggregate,
    }
    if scenario["mode"] == "soak":
        soak_acceptance = soak_resource_acceptance(
            soak_resource_samples,
            workload_summary.get("cycles", 0),
            scenario["profile"],
        )
        run["soak_acceptance"] = soak_acceptance
        run["ok"] = run["ok"] and soak_acceptance["passed"]
    enriched = [
        {
            **record,
            "scenario": scenario["name"],
            "variant": variant,
            "data_mover": data_mover,
            "proxy_session_source": proxy_session,
            "measurement_kind": measurement_kind,
            "repetition": repetition,
        }
        for record in [*flows, *workload_samples]
    ]
    return run, enriched


def scenarios(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.soak_seconds > 0:
        return [
            {
                "name": f"soak-{args.soak_profile}-{args.soak_seconds}-seconds",
                "mode": "soak",
                "flows": 0,
                "duration_seconds": args.soak_seconds,
                "profile": args.soak_profile,
            }
        ]
    result = [
        {
            "name": f"request-{payload}-bytes",
            "mode": "request",
            "flows": args.connections,
            "value": payload,
        }
        for payload in args.payload_sizes
    ]
    result += [
        {
            "name": f"idle-{flows}-flows",
            "mode": "idle",
            "flows": flows,
            "value": args.idle_hold_ms,
        }
        for flows in args.idle_flows
    ]
    if args.stream_flows > 0:
        stream_sizes = args.stream_byte_sizes or [args.stream_bytes]
        multiple_stream_sizes = len(stream_sizes) > 1
        result += [
            {
                "name": (
                    f"stream-{direction}-{args.stream_flows}-flows-{stream_bytes}-bytes"
                    if multiple_stream_sizes
                    else f"stream-{direction}-{args.stream_flows}-flows"
                ),
                "mode": "stream",
                "flows": args.stream_flows,
                "value": stream_bytes,
                "direction": direction,
                "rate": 0,
            }
            for stream_bytes in stream_sizes
            for direction in args.stream_directions
        ]
    if args.slow_flows > 0:
        result.append(
            {
                "name": f"slow-{args.slow_flows}-flows",
                "mode": "stream",
                "flows": args.slow_flows,
                "value": args.slow_bytes,
                "direction": "up",
                "rate": args.slow_rate,
            }
        )
    if args.fairness_quiet_flows > 0:
        result.append(
            {
                "name": f"fairness-{args.fairness_quiet_flows}-quiet-flows",
                "mode": "fairness",
                "flows": args.fairness_quiet_flows + 1,
                "value": args.fairness_quiet_payload,
                "quiet_flows": args.fairness_quiet_flows,
                "quiet_iterations": args.fairness_quiet_iterations,
                "hot_bytes": args.fairness_hot_bytes,
            }
        )
    if args.reset_flows > 0:
        result += [
            {
                "name": f"reset-response-{args.reset_flows}-flows",
                "mode": "reset",
                "flows": args.reset_flows,
                "value": args.reset_request_bytes,
                "prefix": args.reset_prefix_bytes,
                "consume": 0,
            },
            {
                "name": f"reset-early-{args.reset_flows}-flows",
                "mode": "reset",
                "flows": args.reset_flows,
                "value": args.reset_request_bytes,
                "prefix": 0,
                "consume": args.reset_request_bytes // 2,
            },
        ]
    if args.stalled_flows > 0:
        result.append(
            {
                "name": f"stalled-{args.stalled_flows}-flows",
                "mode": "stalled",
                "flows": args.stalled_flows,
                "value": args.stalled_bytes,
                "hold_ms": args.stalled_hold_ms,
            }
        )
    return result


def summarize(
    runs: list[dict[str, Any]],
    flow_samples: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    keys = sorted(
        {
            (
                run["scenario"],
                run["variant"],
                run.get("data_mover") or "",
                run.get("proxy_session_source") or "",
            )
            for run in runs
            if run["measurement_kind"] == "measurement"
        }
    )
    for scenario, variant, mover_key, session_key in keys:
        data_mover = mover_key or None
        proxy_session = session_key or None
        selected_runs = [
            run
            for run in runs
            if run["scenario"] == scenario
            and run["variant"] == variant
            and run.get("data_mover") == data_mover
            and run.get("proxy_session_source") == proxy_session
            and run["measurement_kind"] == "measurement"
        ]
        valid_run_keys = {
            (
                run["scenario"],
                run["variant"],
                run.get("data_mover"),
                run.get("proxy_session_source"),
                run["repetition"],
                run["measurement_kind"],
            )
            for run in selected_runs
            if run["ok"]
        }
        selected_flows = [
            flow
            for flow in flow_samples
            if flow["scenario"] == scenario
            and flow["variant"] == variant
            and flow.get("data_mover") == data_mover
            and flow.get("proxy_session_source") == proxy_session
            and flow["measurement_kind"] == "measurement"
            and flow.get("ok")
            and (
                flow["scenario"],
                flow["variant"],
                flow.get("data_mover"),
                flow.get("proxy_session_source"),
                flow["repetition"],
                flow["measurement_kind"],
            )
            in valid_run_keys
        ]
        connect = [flow["connect_ns"] for flow in selected_flows]
        first = [
            flow["first_response_ns"]
            for flow in selected_flows
            if "first_response_ns" in flow
        ]
        wall = [run["wall_ns"] for run in selected_runs if run["ok"]]
        valid_runs = [run for run in selected_runs if run["ok"]]
        successful = sum(run["successful_flows"] for run in valid_runs)
        compact_soak = bool(selected_runs) and all(
            run.get("mode") == "soak" for run in selected_runs
        )
        wall_total = sum(wall)
        bytes_moved = sum(run.get("bytes") or 0 for run in valid_runs)
        cpu_per_byte = [
            run["child_cpu_ns"] / run["bytes"]
            for run in valid_runs
            if run.get("bytes") and run.get("child_cpu_ns") is not None
        ]
        selected_samples = [
            sample
            for sample in flow_samples
            if sample.get("event") == "sample"
            and sample["scenario"] == scenario
            and sample["variant"] == variant
            and sample.get("data_mover") == data_mover
            and sample.get("proxy_session_source") == proxy_session
            and sample["measurement_kind"] == "measurement"
            and (
                sample["scenario"],
                sample["variant"],
                sample.get("data_mover"),
                sample.get("proxy_session_source"),
                sample["repetition"],
                sample["measurement_kind"],
            )
            in valid_run_keys
        ]
        quiet_echo = [
            sample["latency_ns"]
            for sample in selected_samples
            if sample.get("kind") == "quiet_echo"
        ]
        hot_goodput = [
            flow["sent_bytes"] / (flow["total_ns"] / 1_000_000_000)
            for flow in selected_flows
            if flow.get("kind") == "hot"
            and flow.get("sent_bytes")
            and flow.get("total_ns")
        ]
        idle_steady_cpu = [
            run["supervisor_cpu_sampled_ns"] - run["supervisor_cpu_at_idle_ready_ns"]
            for run in valid_runs
            if run.get("supervisor_cpu_sampled_ns") is not None
            and run.get("supervisor_cpu_at_idle_ready_ns") is not None
        ]
        idle_steady_wall = [
            run["wall_ns"] - run["idle_ready_wall_ns"]
            for run in valid_runs
            if run.get("idle_ready_wall_ns") is not None
        ]
        rows.append(
            {
                "scenario": scenario,
                "variant": variant,
                "data_mover": data_mover,
                "proxy_session_source": proxy_session,
                "valid_runs": sum(run["ok"] for run in selected_runs),
                "total_runs": len(selected_runs),
                "valid_flows": successful if compact_soak else len(selected_flows),
                "valid_flow_count_consistent": (
                    True if compact_soak else len(selected_flows) == successful
                ),
                "connect_p50_ns": percentile(connect, 0.50) if connect else None,
                "connect_p95_ns": percentile(connect, 0.95) if connect else None,
                "connect_p99_ns": percentile(connect, 0.99) if connect else None,
                "first_response_p50_ns": percentile(first, 0.50) if first else None,
                "first_response_p99_ns": percentile(first, 0.99) if first else None,
                "wall_median_ns": statistics.median(wall) if wall else None,
                "connections_per_second": (
                    successful / (wall_total / 1_000_000_000) if wall_total else None
                ),
                "goodput_bytes_per_second": (
                    bytes_moved / (wall_total / 1_000_000_000)
                    if wall_total and bytes_moved
                    else None
                ),
                "child_cpu_ns_per_byte_median": (
                    statistics.median(cpu_per_byte) if cpu_per_byte else None
                ),
                "quiet_echo_samples": len(quiet_echo),
                "quiet_echo_p50_ns": percentile(quiet_echo, 0.50) if quiet_echo else None,
                "quiet_echo_p95_ns": percentile(quiet_echo, 0.95) if quiet_echo else None,
                "quiet_echo_p99_ns": percentile(quiet_echo, 0.99) if quiet_echo else None,
                "hot_goodput_bytes_per_second_median": (
                    statistics.median(hot_goodput) if hot_goodput else None
                ),
                "reset_outcome_reset_flows": sum(
                    1 for flow in selected_flows if flow.get("outcome") == "reset"
                ),
                "reset_outcome_eof_flows": sum(
                    1 for flow in selected_flows if flow.get("outcome") == "eof"
                ),
                "idle_steady_supervisor_cpu_median_ns": (
                    statistics.median(idle_steady_cpu) if idle_steady_cpu else None
                ),
                "idle_steady_wall_median_ns": (
                    statistics.median(idle_steady_wall) if idle_steady_wall else None
                ),
                "child_cpu_median_ns": median_field(valid_runs, "child_cpu_ns"),
                "benchmark_server_cpu_median_ns": median_field(
                    valid_runs, "benchmark_server_cpu_ns"
                ),
                "supervisor_rss_hwm_median_kib": median_field(
                    valid_runs, "supervisor_rss_hwm_kib"
                ),
                "supervisor_rss_sampled_peak_median_kib": median_field(
                    valid_runs, "supervisor_rss_sampled_peak_kib"
                ),
                "supervisor_fd_sampled_peak_max": max_field(
                    valid_runs, "supervisor_fd_sampled_peak"
                ),
                "target_rss_hwm_median_kib": median_field(
                    valid_runs, "target_rss_hwm_kib"
                ),
                "target_rss_sampled_peak_median_kib": median_field(
                    valid_runs, "target_rss_sampled_peak_kib"
                ),
                "target_fd_sampled_peak_max": max_field(valid_runs, "target_fd_sampled_peak"),
                "process_tree_rss_sampled_peak_median_kib": median_field(
                    valid_runs, "process_tree_rss_sampled_peak_kib"
                ),
                "process_tree_fd_sampled_peak_max": max_field(
                    valid_runs, "process_tree_fd_sampled_peak"
                ),
                "benchmark_server_rss_hwm_median_kib": median_field(
                    valid_runs, "benchmark_server_rss_hwm_kib"
                ),
                "benchmark_server_fd_sampled_peak_max": max_field(
                    valid_runs, "benchmark_server_fd_sampled_peak"
                ),
            }
        )
    return rows


def distribution(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "mean": statistics.mean(values) if values else None,
        "sample_stdev": statistics.stdev(values) if len(values) > 1 else None,
        "median": statistics.median(values) if values else None,
        "min": min(values) if values else None,
        "max": max(values) if values else None,
    }


def paired_mover_comparisons(runs: list[dict[str, Any]]) -> dict[str, Any]:
    measurement_runs = [
        run
        for run in runs
        if run["measurement_kind"] == "measurement"
        and run["variant"] == "stable"
        and run.get("data_mover") in ("buffered", "splice")
    ]
    grouped: dict[tuple[str, str | None, int], dict[str, dict[str, Any]]] = {}
    for run in measurement_runs:
        grouped.setdefault(
            (run["scenario"], run.get("proxy_session_source"), run["repetition"]), {}
        )[run["data_mover"]] = run

    pairs: list[dict[str, Any]] = []
    for (scenario, _session, repetition), movers in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][1] or "", item[0][2])
    ):
        buffered = movers.get("buffered")
        splice = movers.get("splice")
        pair_ok = buffered is not None and splice is not None
        pair_ok = bool(pair_ok and buffered["ok"] and splice["ok"])
        goodput_delta: float | None = None
        cpu_delta: float | None = None
        if pair_ok:
            assert buffered is not None and splice is not None
            buffered_bytes = buffered.get("bytes") or 0
            splice_bytes = splice.get("bytes") or 0
            if buffered_bytes > 0 and buffered_bytes == splice_bytes:
                buffered_goodput = buffered_bytes / buffered["wall_ns"]
                splice_goodput = splice_bytes / splice["wall_ns"]
                goodput_delta = 100.0 * (splice_goodput / buffered_goodput - 1.0)
                buffered_cpu = buffered.get("child_cpu_ns")
                splice_cpu = splice.get("child_cpu_ns")
                if buffered_cpu and splice_cpu is not None:
                    cpu_delta = 100.0 * (splice_cpu / buffered_cpu - 1.0)
        representative = buffered or splice or {}
        pairs.append(
            {
                "scenario": scenario,
                "mode": representative.get("mode"),
                "stream_direction": representative.get("stream_direction"),
                "stream_bytes_per_flow": representative.get("stream_bytes_per_flow"),
                "repetition": repetition,
                "pair_ok": pair_ok,
                "buffered_ok": buffered["ok"] if buffered is not None else None,
                "splice_ok": splice["ok"] if splice is not None else None,
                "buffered_wall_ns": buffered["wall_ns"] if buffered is not None else None,
                "splice_wall_ns": splice["wall_ns"] if splice is not None else None,
                "goodput_delta_percent": goodput_delta,
                "child_cpu_per_byte_delta_percent": cpu_delta,
            }
        )

    summaries: list[dict[str, Any]] = []
    for scenario in sorted({pair["scenario"] for pair in pairs}):
        selected = [pair for pair in pairs if pair["scenario"] == scenario]
        goodput = [
            pair["goodput_delta_percent"]
            for pair in selected
            if pair["pair_ok"] and pair["goodput_delta_percent"] is not None
        ]
        cpu = [
            pair["child_cpu_per_byte_delta_percent"]
            for pair in selected
            if pair["pair_ok"] and pair["child_cpu_per_byte_delta_percent"] is not None
        ]
        representative = selected[0]
        summaries.append(
            {
                "scenario": scenario,
                "mode": representative["mode"],
                "stream_direction": representative["stream_direction"],
                "stream_bytes_per_flow": representative["stream_bytes_per_flow"],
                "total_pairs": len(selected),
                "valid_pairs": sum(pair["pair_ok"] for pair in selected),
                "splice_wins": sum((value or 0) > 0 for value in goodput),
                "goodput_delta_percent": distribution(goodput),
                "child_cpu_per_byte_delta_percent": distribution(cpu),
            }
        )
    return {"pairs": pairs, "summaries": summaries}


def flow_connect_percentiles(
    flow_samples: list[dict[str, Any]],
) -> dict[tuple[str, str, int], list[int]]:
    """Groups measurement flow connect times by (scenario, session, repetition)."""
    grouped: dict[tuple[str, str, int], list[int]] = {}
    for flow in flow_samples:
        if (
            flow.get("measurement_kind") != "measurement"
            or flow.get("variant") != "stable"
            or flow.get("proxy_session_source") not in ("cold", "warm-one-shot")
            or not flow.get("ok")
            or "connect_ns" not in flow
        ):
            continue
        key = (flow["scenario"], flow["proxy_session_source"], flow["repetition"])
        grouped.setdefault(key, []).append(flow["connect_ns"])
    return grouped


def paired_session_comparisons(
    runs: list[dict[str, Any]],
    flow_samples: list[dict[str, Any]],
) -> dict[str, Any]:
    """Adjacent-pair statistics for cold versus warm-one-shot proxy sessions.

    Mirrors the data-mover machinery: only pair-local deltas are recorded, a
    pair with either side failed stays out of the statistics, and the suite
    still fails on any failed run.
    """
    measurement_runs = [
        run
        for run in runs
        if run["measurement_kind"] == "measurement"
        and run["variant"] == "stable"
        and run.get("proxy_session_source") in ("cold", "warm-one-shot")
    ]
    connect_groups = flow_connect_percentiles(flow_samples)
    grouped: dict[tuple[str, int], dict[str, dict[str, Any]]] = {}
    for run in measurement_runs:
        grouped.setdefault((run["scenario"], run["repetition"]), {})[
            run["proxy_session_source"]
        ] = run

    pairs: list[dict[str, Any]] = []
    for (scenario, repetition), sessions in sorted(grouped.items()):
        cold = sessions.get("cold")
        warm = sessions.get("warm-one-shot")
        pair_ok = cold is not None and warm is not None
        pair_ok = bool(pair_ok and cold["ok"] and warm["ok"])
        conns_delta: float | None = None
        connect_p50_delta: float | None = None
        connect_p99_delta: float | None = None
        goodput_delta: float | None = None
        cpu_delta: float | None = None
        if pair_ok:
            assert cold is not None and warm is not None
            cold_flows = cold.get("successful_flows") or 0
            warm_flows = warm.get("successful_flows") or 0
            if cold_flows > 0 and cold_flows == warm_flows:
                cold_rate = cold_flows / cold["wall_ns"]
                warm_rate = warm_flows / warm["wall_ns"]
                conns_delta = 100.0 * (warm_rate / cold_rate - 1.0)
            cold_connect = connect_groups.get((scenario, "cold", repetition), [])
            warm_connect = connect_groups.get(
                (scenario, "warm-one-shot", repetition), []
            )
            if cold_connect and warm_connect:
                cold_p50 = percentile(cold_connect, 0.50)
                warm_p50 = percentile(warm_connect, 0.50)
                cold_p99 = percentile(cold_connect, 0.99)
                warm_p99 = percentile(warm_connect, 0.99)
                if cold_p50 > 0:
                    connect_p50_delta = 100.0 * (warm_p50 / cold_p50 - 1.0)
                if cold_p99 > 0:
                    connect_p99_delta = 100.0 * (warm_p99 / cold_p99 - 1.0)
            cold_bytes = cold.get("bytes") or 0
            warm_bytes = warm.get("bytes") or 0
            if cold_bytes > 0 and cold_bytes == warm_bytes:
                goodput_delta = 100.0 * (
                    (warm_bytes / warm["wall_ns"]) / (cold_bytes / cold["wall_ns"]) - 1.0
                )
                cold_cpu = cold.get("child_cpu_ns")
                warm_cpu = warm.get("child_cpu_ns")
                if cold_cpu and warm_cpu is not None:
                    cpu_delta = 100.0 * (warm_cpu / cold_cpu - 1.0)
        representative = cold or warm or {}
        pairs.append(
            {
                "scenario": scenario,
                "mode": representative.get("mode"),
                "stream_direction": representative.get("stream_direction"),
                "stream_bytes_per_flow": representative.get("stream_bytes_per_flow"),
                "repetition": repetition,
                "pair_ok": pair_ok,
                "cold_ok": cold["ok"] if cold is not None else None,
                "warm_ok": warm["ok"] if warm is not None else None,
                "cold_wall_ns": cold["wall_ns"] if cold is not None else None,
                "warm_wall_ns": warm["wall_ns"] if warm is not None else None,
                "connections_per_second_delta_percent": conns_delta,
                "connect_p50_delta_percent": connect_p50_delta,
                "connect_p99_delta_percent": connect_p99_delta,
                "goodput_delta_percent": goodput_delta,
                "child_cpu_per_byte_delta_percent": cpu_delta,
            }
        )

    summaries: list[dict[str, Any]] = []
    for scenario in sorted({pair["scenario"] for pair in pairs}):
        selected = [pair for pair in pairs if pair["scenario"] == scenario]
        valid = [pair for pair in selected if pair["pair_ok"]]

        def collect(field: str) -> list[float]:
            return [
                pair[field] for pair in valid if pair[field] is not None
            ]

        conns = collect("connections_per_second_delta_percent")
        representative = selected[0]
        summaries.append(
            {
                "scenario": scenario,
                "mode": representative["mode"],
                "stream_direction": representative["stream_direction"],
                "stream_bytes_per_flow": representative["stream_bytes_per_flow"],
                "total_pairs": len(selected),
                "valid_pairs": len(valid),
                "warm_wins": sum(value > 0 for value in conns),
                "connections_per_second_delta_percent": distribution(conns),
                "connect_p50_delta_percent": distribution(
                    collect("connect_p50_delta_percent")
                ),
                "connect_p99_delta_percent": distribution(
                    collect("connect_p99_delta_percent")
                ),
                "goodput_delta_percent": distribution(
                    collect("goodput_delta_percent")
                ),
                "child_cpu_per_byte_delta_percent": distribution(
                    collect("child_cpu_per_byte_delta_percent")
                ),
            }
        )
    return {"pairs": pairs, "summaries": summaries}


def warm_pool_health(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregates warm pool counters from warm-session diagnostic runs."""
    summaries = [
        run["metric_summary"]
        for run in runs
        if run["measurement_kind"] == "diagnostic"
        and run.get("proxy_session_source") == "warm-one-shot"
        and run.get("metric_summary") is not None
    ]
    hits = sum(summary.get("tcp_warm_sessions_hit", 0) for summary in summaries)
    stale = sum(summary.get("tcp_warm_sessions_stale", 0) for summary in summaries)
    return {
        "diagnostic_runs": len(summaries),
        # What the binary itself claims to be running; anything other than
        # warm-one-shot means the injected knob never took effect.
        "reported_sources": sorted(
            {str(summary.get("tcp_proxy_session_source")) for summary in summaries}
        ),
        "hits": hits,
        "misses": sum(summary.get("tcp_warm_sessions_miss", 0) for summary in summaries),
        "stale": stale,
        "expired": sum(
            summary.get("tcp_warm_sessions_expired", 0) for summary in summaries
        ),
        "replenish_failures": sum(
            summary.get("tcp_warm_replenish_failures", 0) for summary in summaries
        ),
        "stale_per_hit": (stale / hits) if hits > 0 else None,
    }


def warm_readiness_gate(
    session_comparisons: dict[str, Any],
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    request_summaries = [
        summary
        for summary in session_comparisons["summaries"]
        if summary["mode"] == "request"
    ]
    checks: list[dict[str, Any]] = []
    improvements = 0
    for summary in request_summaries:
        reasons: list[str] = []
        valid_pairs = summary["valid_pairs"]
        if valid_pairs < 10:
            reasons.append(f"requires 10 valid pairs, got {valid_pairs}")
        conns_mean = summary["connections_per_second_delta_percent"]["mean"]
        p99_mean = summary["connect_p99_delta_percent"]["mean"]
        improved = bool(
            (
                conns_mean is not None
                and conns_mean >= WARM_MIN_CONNS_PER_SEC_DELTA_PERCENT
            )
            or (
                p99_mean is not None
                and p99_mean <= WARM_MAX_CONNECT_P99_DELTA_PERCENT
            )
        )
        improvements += improved
        if p99_mean is None:
            reasons.append("missing connect p99 delta")
        elif p99_mean > WARM_CONNECT_P99_REGRESSION_LIMIT_PERCENT:
            reasons.append(
                "mean connect p99 regression exceeds "
                f"{WARM_CONNECT_P99_REGRESSION_LIMIT_PERCENT:.1f}%"
            )
        checks.append(
            {
                "scenario": summary["scenario"],
                "valid_pairs": valid_pairs,
                "improved": improved,
                "passed": not reasons,
                "reasons": reasons,
                "comparison": summary,
            }
        )
    health = warm_pool_health(runs)
    health_reasons: list[str] = []
    if health["diagnostic_runs"] == 0:
        health_reasons.append("no warm diagnostic run with metrics")
    else:
        # A warm run whose binary reports another source, or that never
        # recorded a single hit, means the comparison measured cold against
        # cold; noise could then still clear the improvement thresholds.
        wrong_sources = [
            source
            for source in health["reported_sources"]
            if source != "warm-one-shot"
        ]
        if wrong_sources:
            health_reasons.append(
                "warm diagnostic reports proxy session source "
                + ", ".join(wrong_sources)
            )
        if health["hits"] == 0:
            health_reasons.append("warm pool never engaged")
    if health["replenish_failures"] != 0:
        health_reasons.append("replenish failures are nonzero")
    if health["stale_per_hit"] is not None and health["stale_per_hit"] > WARM_MAX_STALE_PER_HIT:
        health_reasons.append(
            f"stale-per-hit ratio exceeds {WARM_MAX_STALE_PER_HIT:.2f}"
        )
    passed = bool(
        request_summaries
        and improvements > 0
        and all(check["passed"] for check in checks)
        and not health_reasons
    )
    return {
        "gate": "warm-readiness",
        "passed": passed,
        "improvements": improvements,
        "checks": checks,
        "warm_pool_health": {**health, "reasons": health_reasons},
        "thresholds": {
            "minimum_valid_pairs": 10,
            "min_connections_per_second_delta_percent": (
                WARM_MIN_CONNS_PER_SEC_DELTA_PERCENT
            ),
            "max_connect_p99_delta_percent": WARM_MAX_CONNECT_P99_DELTA_PERCENT,
            "connect_p99_regression_limit_percent": (
                WARM_CONNECT_P99_REGRESSION_LIMIT_PERCENT
            ),
            "max_stale_per_hit": WARM_MAX_STALE_PER_HIT,
        },
    }


def splice_readiness_gate(comparisons: dict[str, Any]) -> dict[str, Any]:
    summaries = comparisons["summaries"]
    checks: list[dict[str, Any]] = []
    for stream_bytes, stage in (
        (SPLICE_RAMP_BYTES, "ramp"),
        (SPLICE_STEADY_BYTES, "steady"),
    ):
        for direction in STREAM_DIRECTION_CODES:
            candidates = [
                summary
                for summary in summaries
                if summary["mode"] == "stream"
                and summary["stream_bytes_per_flow"] == stream_bytes
                and summary["stream_direction"] == direction
            ]
            summary = candidates[0] if len(candidates) == 1 else None
            valid_pairs = summary["valid_pairs"] if summary is not None else 0
            reasons: list[str] = []
            if summary is None:
                reasons.append("missing comparison")
            if valid_pairs < 10:
                reasons.append(f"requires 10 valid pairs, got {valid_pairs}")
            if stage == "steady" and summary is not None:
                goodput_mean = summary["goodput_delta_percent"]["mean"]
                cpu_mean = summary["child_cpu_per_byte_delta_percent"]["mean"]
                if (
                    goodput_mean is None
                    or goodput_mean < SPLICE_STEADY_MIN_GOODPUT_DELTA_PERCENT
                ):
                    reasons.append(
                        "mean goodput delta is below "
                        f"{SPLICE_STEADY_MIN_GOODPUT_DELTA_PERCENT:.1f}%"
                    )
                if cpu_mean is None or cpu_mean > SPLICE_STEADY_MAX_CPU_DELTA_PERCENT:
                    reasons.append(
                        "mean CPU/byte reduction is below "
                        f"{-SPLICE_STEADY_MAX_CPU_DELTA_PERCENT:.1f}%"
                    )
            checks.append(
                {
                    "stage": stage,
                    "stream_direction": direction,
                    "stream_bytes_per_flow": stream_bytes,
                    "passed": not reasons,
                    "reasons": reasons,
                    "comparison": summary,
                }
            )
    return {
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "thresholds": {
            "minimum_valid_pairs": 10,
            "steady_min_goodput_delta_percent": (
                SPLICE_STEADY_MIN_GOODPUT_DELTA_PERCENT
            ),
            "steady_max_cpu_per_byte_delta_percent": (
                SPLICE_STEADY_MAX_CPU_DELTA_PERCENT
            ),
            "ramp_performance_is_report_only": True,
        },
    }


def command_output(command: list[str], cwd: Path | None = None) -> str | None:
    try:
        return subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
            cwd=cwd,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def binary_metadata(path: str | None, commit: str | None, build_command: str | None) -> Any:
    if path is None:
        return None
    binary = Path(path)
    return {
        "path": str(binary),
        "sha256": sha256_file(binary),
        "commit": commit,
        "build_command": build_command,
    }


def environment_metadata(args: argparse.Namespace, dirty_diff_path: Path) -> dict[str, Any]:
    return {
        "schema_version": 4,
        "created_unix_ns": time.time_ns(),
        "git_commit": command_output(["git", "rev-parse", "HEAD"], cwd=ROOT),
        "git_status": command_output(["git", "status", "--short"], cwd=ROOT),
        "git_root": str(ROOT),
        "uname": command_output(["uname", "-a"]),
        "rustc": command_output(["rustc", "--version"]),
        "cc": command_output([args.cc, "--version"]),
        "python": sys.version,
        "cpu_count": os.cpu_count(),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "rlimit_nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
        "perf_available": shutil.which("perf") is not None,
        "kernel_perf_event_paranoid": command_output(
            ["cat", "/proc/sys/kernel/perf_event_paranoid"]
        ),
        "perf_stat_events": args.perf_stat_events,
        "yatht": binary_metadata(args.yatht, args.yatht_commit, args.yatht_build_command),
        "workload": {
            "path": str(args.workload),
            "sha256": sha256_file(args.workload),
            "source": str(WORKLOAD_SOURCE),
            "source_sha256": sha256_file(WORKLOAD_SOURCE),
        },
        "dirty_diff_artifact": str(dirty_diff_path),
        "warmups": args.warmups,
        "repetitions": args.repetitions,
        "connections": args.connections,
        "payload_sizes": args.payload_sizes,
        "idle_flows": args.idle_flows,
        "stable_data_movers": args.stable_data_movers,
        "proxy_session_sources": args.proxy_session_sources,
        "proxy_rtt_ms": args.proxy_rtt_ms,
        "stream_flows": args.stream_flows,
        "stream_bytes": args.stream_bytes,
        "stream_byte_sizes": args.stream_byte_sizes,
        "stream_directions": args.stream_directions,
        "slow_flows": args.slow_flows,
        "slow_bytes": args.slow_bytes,
        "slow_rate_bytes_per_second": args.slow_rate,
        "fairness_quiet_flows": args.fairness_quiet_flows,
        "fairness_quiet_iterations": args.fairness_quiet_iterations,
        "fairness_quiet_payload": args.fairness_quiet_payload,
        "fairness_hot_bytes": args.fairness_hot_bytes,
        "reset_flows": args.reset_flows,
        "reset_request_bytes": args.reset_request_bytes,
        "reset_prefix_bytes": args.reset_prefix_bytes,
        "stalled_flows": args.stalled_flows,
        "stalled_bytes": args.stalled_bytes,
        "stalled_hold_ms": args.stalled_hold_ms,
        "soak_seconds": args.soak_seconds,
        "soak_profile": args.soak_profile,
        "splice_readiness_gate": args.splice_readiness_gate,
        "random_seed": args.seed,
        "estimated_fd_limit": args.estimated_fd_limit,
        "resource_sampling": {
            "interval_ms": int(SAMPLE_INTERVAL_SECONDS * 1000),
            "process_tree_interval_ms": int(
                SAMPLE_INTERVAL_SECONDS * 1000 * TREE_SAMPLE_STRIDE
            ),
            "direct_target_role": "root process",
            "proxied_supervisor_role": "root process",
            "proxied_target_role": "first direct child",
            "benchmark_server_role": "persistent harness process",
            "process_tree_rss_note": "sum of VmRSS may double-count shared pages",
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yatht", default=str(ROOT / "target/release/yatht"))
    parser.add_argument("--yatht-commit", type=git_commit)
    parser.add_argument("--yatht-build-command", default="cargo build --release")
    parser.add_argument("--variants", type=comma_variants, default="direct,stable")
    parser.add_argument(
        "--stable-data-movers",
        type=comma_data_movers,
        default="inherited",
        help="stable mover(s) to run; explicit pairs are compared per repetition",
    )
    parser.add_argument(
        "--proxy-session-sources",
        type=comma_proxy_sessions,
        default="inherited",
        help="proxy session source(s) to run; explicit pairs are compared per repetition",
    )
    parser.add_argument(
        "--proxy-rtt-ms",
        type=proxy_rtt_ms,
        default=0.0,
        help="artificial delay before each SOCKS5 reply to model proxy RTT",
    )
    parser.add_argument("--connections", type=int, default=1000)
    parser.add_argument(
        "--payload-sizes",
        type=comma_sizes,
        default=comma_sizes("0,1,1024,16384,65536"),
    )
    parser.add_argument("--idle-flows", type=comma_sizes, default=comma_sizes("1000"))
    parser.add_argument("--idle-hold-ms", type=int, default=100)
    parser.add_argument("--stream-flows", type=int, default=32)
    parser.add_argument("--stream-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument(
        "--stream-byte-sizes",
        type=comma_sizes,
        help="optional comma-separated stream sizes to run in one suite",
    )
    parser.add_argument(
        "--stream-directions",
        type=comma_directions,
        default=comma_directions("up,down,bidi"),
    )
    parser.add_argument("--slow-flows", type=int, default=16)
    parser.add_argument("--slow-bytes", type=int, default=256 * 1024)
    # Per-flow server-side read rate; keeps each slow run within a few seconds
    # while the relay stays under visible backpressure the whole time.
    parser.add_argument("--slow-rate", type=int, default=128 * 1024)
    parser.add_argument("--fairness-quiet-flows", type=int, default=32)
    parser.add_argument("--fairness-quiet-iterations", type=int, default=40)
    parser.add_argument("--fairness-quiet-payload", type=int, default=1024)
    parser.add_argument("--fairness-hot-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--reset-flows", type=int, default=128)
    parser.add_argument("--reset-request-bytes", type=int, default=65536)
    parser.add_argument("--reset-prefix-bytes", type=int, default=1024)
    # Attached to the root benchmark process for diagnostic runs only; empty
    # disables. Requires kernel.perf_event_paranoid <= 2 (1 for kernel-side
    # counts); failures are recorded per run instead of failing the gate.
    parser.add_argument("--perf-stat-events", default="")
    parser.add_argument("--stalled-flows", type=int, default=128)
    # The proxied chain (kernel socket autotuning on both yatht hops, the 64 KiB
    # relay buffer, and the SOCKS proxy's stream buffers) can absorb several MiB
    # per flow on distributions with large tcp_rmem/tcp_wmem defaults; the
    # per-flow budget must exceed that or flows never observe EAGAIN.
    parser.add_argument("--stalled-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--stalled-hold-ms", type=int, default=250)
    parser.add_argument("--soak-seconds", type=int, default=0)
    parser.add_argument("--soak-profile", choices=("standard", "smoke"), default="standard")
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--seed", type=int, default=20260723)
    parser.add_argument("--cc", type=executable, default="cc")
    parser.add_argument("--workload", type=Path, default=DEFAULT_WORKLOAD)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--skip-diagnostics", action="store_true")
    parser.add_argument("--splice-readiness-gate", action="store_true")
    parser.add_argument("--warm-readiness-gate", action="store_true")
    args = parser.parse_args()
    if isinstance(args.variants, str):
        args.variants = comma_variants(args.variants)
    if isinstance(args.stable_data_movers, str):
        args.stable_data_movers = comma_data_movers(args.stable_data_movers)
    if isinstance(args.proxy_session_sources, str):
        args.proxy_session_sources = comma_proxy_sessions(args.proxy_session_sources)
    if "stable" in args.variants:
        try:
            args.yatht = executable(args.yatht)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
        if args.yatht_commit is None:
            try:
                args.yatht_commit = git_commit("HEAD")
            except argparse.ArgumentTypeError as error:
                parser.error(f"cannot resolve default --yatht-commit: {error}")
    else:
        args.yatht = None
        args.yatht_commit = None
        if args.stable_data_movers != ["inherited"]:
            parser.error("explicit stable data movers require the stable variant")
        if args.proxy_session_sources != ["inherited"]:
            parser.error("explicit proxy session sources require the stable variant")
    if args.connections <= 0 or args.warmups < 0 or args.repetitions <= 0:
        parser.error("connections/repetitions must be positive and warmups nonnegative")
    if any(flows <= 0 for flows in args.idle_flows):
        parser.error("idle flow counts must be positive")
    if args.idle_hold_ms < 0 or args.stalled_hold_ms < 0:
        parser.error("hold times must be nonnegative")
    stream_sizes = args.stream_byte_sizes or [args.stream_bytes]
    if args.stream_flows < 0 or (
        args.stream_flows > 0 and any(stream_bytes <= 0 for stream_bytes in stream_sizes)
    ):
        parser.error("stream flows must be nonnegative and stream bytes positive")
    if args.stream_flows > 0 and not args.stream_directions:
        parser.error("stream flows require at least one direction")
    if args.slow_flows < 0 or (
        args.slow_flows > 0 and (args.slow_bytes <= 0 or args.slow_rate <= 0)
    ):
        parser.error("slow flows must be nonnegative with positive bytes and rate")
    if args.fairness_quiet_flows < 0 or (
        args.fairness_quiet_flows > 0
        and (
            args.fairness_quiet_iterations <= 0
            or args.fairness_quiet_payload <= 0
            or args.fairness_hot_bytes <= 0
        )
    ):
        parser.error(
            "fairness quiet flows must be nonnegative with positive "
            "iterations, payload, and hot bytes"
        )
    if args.reset_flows < 0 or (
        args.reset_flows > 0
        and (args.reset_request_bytes <= 1 or args.reset_prefix_bytes < 0)
    ):
        parser.error(
            "reset flows must be nonnegative with request bytes above one "
            "and nonnegative prefix bytes"
        )
    if args.stalled_flows < 0 or (args.stalled_flows > 0 and args.stalled_bytes <= 0):
        parser.error("stalled flows must be nonnegative and stalled bytes positive")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if len(args.stable_data_movers) > 1 and len(args.proxy_session_sources) > 1:
        parser.error(
            "only one paired dimension per suite: use multiple data movers "
            "or multiple proxy session sources, not both"
        )
    if args.soak_seconds < 0:
        parser.error("soak seconds must be nonnegative")
    if args.soak_seconds > 0:
        if args.variants != ["stable"]:
            parser.error("soak requires --variants stable")
        if len(args.stable_data_movers) != 1 or args.stable_data_movers == ["inherited"]:
            parser.error("soak requires exactly one explicit stable data mover")
        if len(args.proxy_session_sources) != 1:
            parser.error("soak requires exactly one proxy session source")
        if args.warmups != 0 or args.repetitions != 1:
            parser.error("soak requires --warmups 0 --repetitions 1")
        if args.timeout <= args.soak_seconds:
            parser.error("soak timeout must exceed soak duration")
    if args.splice_readiness_gate:
        if args.variants != ["stable"]:
            parser.error("splice readiness gate requires --variants stable")
        if set(args.stable_data_movers) != {"buffered", "splice"}:
            parser.error(
                "splice readiness gate requires --stable-data-movers buffered,splice"
            )
        if len(args.proxy_session_sources) != 1:
            parser.error("splice readiness gate requires one proxy session source")
        if not {SPLICE_RAMP_BYTES, SPLICE_STEADY_BYTES}.issubset(stream_sizes):
            parser.error("splice readiness gate requires 4 MiB and 32 MiB stream sizes")
        if set(args.stream_directions) != set(STREAM_DIRECTION_CODES):
            parser.error("splice readiness gate requires up, down, and bidi streams")
        if args.repetitions < 10:
            parser.error("splice readiness gate requires at least 10 repetitions")
    if args.warm_readiness_gate:
        if args.splice_readiness_gate:
            parser.error("run one readiness gate per suite")
        if args.variants != ["stable"]:
            parser.error("warm readiness gate requires --variants stable")
        if set(args.proxy_session_sources) != {"cold", "warm-one-shot"}:
            parser.error(
                "warm readiness gate requires --proxy-session-sources cold,warm-one-shot"
            )
        if len(args.stable_data_movers) != 1:
            parser.error("warm readiness gate requires exactly one stable data mover")
        if not args.payload_sizes:
            parser.error("warm readiness gate requires request scenarios")
        if args.repetitions < 10:
            parser.error("warm readiness gate requires at least 10 repetitions")
        if args.skip_diagnostics:
            parser.error(
                "warm readiness gate needs diagnostics for warm pool health"
            )
    if (
        not args.payload_sizes
        and not args.idle_flows
        and args.stream_flows == 0
        and args.slow_flows == 0
        and args.fairness_quiet_flows == 0
        and args.reset_flows == 0
        and args.stalled_flows == 0
    ):
        parser.error("at least one scenario must be enabled")
    ensure_fd_limit(args, parser)
    return args


def main() -> None:
    args = parse_args()
    build_workload(args.cc, args.workload)
    run_name = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    output_dir = (args.output_dir or (DEFAULT_OUTPUT_ROOT / run_name)).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    metrics_dir = output_dir / "metrics"
    metrics_dir.mkdir()
    dirty_diff_path = output_dir / "workspace.diff"
    dirty_diff = command_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT)
    dirty_diff_path.write_text((dirty_diff or "") + "\n")
    (output_dir / "environment.json").write_text(
        json.dumps(environment_metadata(args, dirty_diff_path), indent=2, sort_keys=True) + "\n"
    )
    for name in ("runs.jsonl", "flow_samples.jsonl", "commands.txt"):
        (output_dir / name).write_text("")
    resource_samples_path = output_dir / "resource_samples.jsonl"
    if args.soak_seconds > 0:
        resource_samples_path.write_text("")

    servers = BenchmarkServers(args.timeout + 30, args.proxy_rtt_ms / 1000.0)
    rng = random.Random(args.seed)
    runs: list[dict[str, Any]] = []
    flow_samples: list[dict[str, Any]] = []
    execution_error: BaseException | None = None
    servers_started = False
    previous_sigterm = signal.signal(signal.SIGTERM, interrupt_benchmark)
    try:
        servers.start()
        servers_started = True
        with (
            (output_dir / "runs.jsonl").open("w") as run_file,
            (output_dir / "flow_samples.jsonl").open("w") as flow_file,
            (output_dir / "commands.txt").open("w") as command_log,
        ):
            args.command_log = command_log
            for scenario in scenarios(args):
                for warmup in range(args.warmups):
                    for variant, data_mover, proxy_session in randomized_execution_order(
                        args, rng
                    ):
                        warmup_run, warmup_flows = run_one(
                            variant,
                            data_mover,
                            proxy_session,
                            args,
                            servers,
                            scenario,
                            warmup,
                            "warmup",
                            None,
                        )
                        runs.append(warmup_run)
                        flow_samples.extend(warmup_flows)
                        run_file.write(json.dumps(warmup_run, sort_keys=True) + "\n")
                        for flow in warmup_flows:
                            flow_file.write(json.dumps(flow, sort_keys=True) + "\n")
                        run_file.flush()
                        flow_file.flush()
                        if not warmup_run["ok"]:
                            failure = {
                                key: warmup_run[key]
                                for key in (
                                    "returncode",
                                    "timed_out",
                                    "stalled_ready",
                                    "stalled_ready_flows",
                                    "stalled_released",
                                    "application_backpressure_confirmed",
                                    "stalled_server_connections",
                                    "stalled_server_corrupt_connections",
                                    "stalled_server_byte_mismatch_connections",
                                    "stalled_server_incomplete_connections",
                                    "stalled_server_quiescent",
                                    "stalled_undersized_flows",
                                    "stream_server_connections",
                                    "stream_server_violations",
                                    "stream_server_quiescent",
                                    "successful_flows",
                                    "parse_error",
                                    "stderr",
                                )
                            }
                            raise RuntimeError(
                                "warmup failed for "
                                f"{scenario['name']}/{variant}/{data_mover}/"
                                f"{proxy_session}: "
                                f"{json.dumps(failure, sort_keys=True)}"
                            )
                for repetition in range(args.repetitions):
                    for variant, data_mover, proxy_session in randomized_execution_order(
                        args, rng
                    ):
                        measurement_metrics_path = (
                            metrics_dir
                            / f"{scenario['name']}-{data_mover}-{proxy_session}.jsonl"
                            if scenario["mode"] == "soak"
                            else None
                        )
                        run, flows = run_one(
                            variant,
                            data_mover,
                            proxy_session,
                            args,
                            servers,
                            scenario,
                            repetition,
                            "measurement",
                            measurement_metrics_path,
                            resource_samples_path
                            if scenario["mode"] == "soak"
                            else None,
                        )
                        runs.append(run)
                        flow_samples.extend(flows)
                        run_file.write(json.dumps(run, sort_keys=True) + "\n")
                        for flow in flows:
                            flow_file.write(json.dumps(flow, sort_keys=True) + "\n")
                        run_file.flush()
                        flow_file.flush()
                        print(
                            f"{scenario['name']} {variant}/{data_mover}/{proxy_session} "
                            f"{repetition + 1}/{args.repetitions}: "
                            f"{'ok' if run['ok'] else 'FAILED'}",
                            flush=True,
                        )
                        if not run["ok"] and run.get("stalled_undersized_flows"):
                            print(
                                f"  calibration: {run['stalled_undersized_flows']} "
                                "stalled flow(s) absorbed the full payload without "
                                "blocking; raise --stalled-bytes",
                                flush=True,
                            )
                        require_stalled_server_quiescence(run)
                        require_stream_server_quiescence(run)
                if (
                    "stable" in args.variants
                    and not args.skip_diagnostics
                    and scenario["mode"] != "soak"
                ):
                    for data_mover in args.stable_data_movers:
                        for proxy_session in args.proxy_session_sources:
                            metrics_path = metrics_dir / (
                                f"{scenario['name']}-{data_mover}-{proxy_session}.jsonl"
                            )
                            run, flows = run_one(
                                "stable",
                                data_mover,
                                proxy_session,
                                args,
                                servers,
                                scenario,
                                0,
                                "diagnostic",
                                metrics_path,
                            )
                            runs.append(run)
                            flow_samples.extend(flows)
                            run_file.write(json.dumps(run, sort_keys=True) + "\n")
                            for flow in flows:
                                flow_file.write(json.dumps(flow, sort_keys=True) + "\n")
                            run_file.flush()
                            flow_file.flush()
                            require_stalled_server_quiescence(run)
                            require_stream_server_quiescence(run)
    except BaseException as error:
        execution_error = error
    finally:
        if servers_started:
            try:
                servers.stop()
            except BaseException as error:
                if execution_error is None:
                    execution_error = error
        signal.signal(signal.SIGTERM, previous_sigterm)

    summary = summarize(runs, flow_samples)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    with (output_dir / "summary.csv").open("w", newline="") as summary_file:
        writer = csv.DictWriter(summary_file, fieldnames=list(summary[0]) if summary else [])
        if summary:
            writer.writeheader()
            writer.writerows(summary)

    comparisons = paired_mover_comparisons(runs)
    session_comparisons = paired_session_comparisons(runs, flow_samples)
    (output_dir / "comparisons.json").write_text(
        json.dumps(
            {
                **comparisons,
                "session_pairs": session_comparisons["pairs"],
                "session_summaries": session_comparisons["summaries"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    comparison_pairs = comparisons["pairs"]
    with (output_dir / "comparisons.csv").open("w", newline="") as comparison_file:
        writer = csv.DictWriter(
            comparison_file,
            fieldnames=list(comparison_pairs[0]) if comparison_pairs else [],
        )
        if comparison_pairs:
            writer.writeheader()
            writer.writerows(comparison_pairs)
    session_pairs = session_comparisons["pairs"]
    if session_pairs:
        with (output_dir / "session_comparisons.csv").open(
            "w", newline=""
        ) as session_file:
            writer = csv.DictWriter(session_file, fieldnames=list(session_pairs[0]))
            writer.writeheader()
            writer.writerows(session_pairs)

    gate: dict[str, Any] | None = None
    if args.splice_readiness_gate:
        gate = splice_readiness_gate(comparisons)
        (output_dir / "gate.json").write_text(
            json.dumps(gate, indent=2, sort_keys=True) + "\n"
        )
    if args.warm_readiness_gate:
        gate = warm_readiness_gate(session_comparisons, runs)
        (output_dir / "gate.json").write_text(
            json.dumps(gate, indent=2, sort_keys=True) + "\n"
        )

    failed = [
        run
        for run in runs
        if run["measurement_kind"] in {"measurement", "diagnostic"} and not run["ok"]
    ]
    print(f"results: {output_dir}")
    if execution_error is not None:
        print(f"benchmark interrupted: {execution_error}", file=sys.stderr)
        if isinstance(execution_error, KeyboardInterrupt):
            raise SystemExit(130)
        raise execution_error
    if failed:
        print(f"failed runs: {len(failed)}", file=sys.stderr)
        raise SystemExit(1)
    if gate is not None and not gate["passed"]:
        print(
            f"{gate.get('gate', 'splice-readiness')} gate failed",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
