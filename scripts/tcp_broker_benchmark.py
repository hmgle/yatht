#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run deterministic direct, pre-stable, and stable TCP broker benchmarks."""

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
VARIANT_ORDER = ("direct", "addfd", "stable")
METRICS_SCHEMA_VERSION = 3
SAMPLE_INTERVAL_SECONDS = 0.005
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
    def __init__(self, safety_timeout: float) -> None:
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
        self._spawn_connection(self._handle_stream(reader, writer, results), writer)

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
            if results is None:
                raise RuntimeError("stream run was not prepared")
            try:
                header = await reader.readexactly(STREAM_HEADER.size)
            except asyncio.IncompleteReadError:
                return
            magic, direction_code, payload_bytes, aux, aux2 = (
                STREAM_HEADER.unpack(header)
            )
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
        run["mode"] not in ("stream", "fairness", "reset")
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


def variant_command(
    variant: str,
    args: argparse.Namespace,
    servers: BenchmarkServers,
    scenario: dict[str, Any],
    metrics_path: Path | None = None,
    stalled_ready_path: Path | None = None,
) -> list[str]:
    if scenario["mode"] == "fairness":
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
        if scenario["mode"] == "stream":
            workload.append(scenario["direction"])
            workload.append(str(scenario["rate"]))
        if scenario["mode"] == "reset":
            workload.append(str(scenario["prefix"]))
            workload.append(str(scenario["consume"]))
    if variant == "direct":
        return workload
    yatht = args.yatht if variant == "stable" else args.addfd_yatht
    if yatht is None:
        raise ValueError(f"missing binary for {variant}")
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
    args: argparse.Namespace,
    servers: BenchmarkServers,
    scenario: dict[str, Any],
    repetition: int,
    measurement_kind: str,
    metrics_path: Path | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="yatht-benchmark-control-") as control_dir:
        stalled_ready_path = Path(control_dir) / "stalled-ready"
        if scenario["mode"] == "stalled":
            servers.prepare_stalled_run()
        if scenario["mode"] in ("stream", "fairness", "reset"):
            servers.prepare_stream_run()
        command = variant_command(
            variant,
            args,
            servers,
            scenario,
            metrics_path,
            stalled_ready_path if scenario["mode"] == "stalled" else None,
        )
        args.command_log.write(shlex.join(command) + "\n")
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
        supervisor_peaks = empty_process_peaks()
        target_peaks = empty_process_peaks()
        server_peaks = empty_process_peaks()
        process_tree_rss_sampled_peak_kib: int | None = None
        process_tree_fd_sampled_peak: int | None = None
        supervisor_pid: int | None = None
        target_pid: int | None = None
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
                )
                if variant == "direct":
                    target_pid = process.pid
                else:
                    supervisor_pid = process.pid
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
                    time.sleep(SAMPLE_INTERVAL_SECONDS)
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

    metric_summary: dict[str, Any] | None = None
    metric_parse_errors: list[dict[str, Any]] = []
    if metrics_path is not None:
        metric_events, metric_parse_errors = parse_jsonl(metrics_path)
        summaries = [event for event in metric_events if event.get("event") == "run_summary"]
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

    successful = [flow for flow in flows if flow.get("ok")]
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
    if scenario["mode"] == "stalled":
        assert stalled_server_results is not None
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
    if metric_summary is not None and metric_summary.get("dropped_metric_events") != 0:
        ok = False
    if metrics_path is not None:
        ok = ok and metric_summary is not None and not metric_parse_errors
        if metric_summary is not None:
            ok = ok and metric_summary.get("schema_version") == METRICS_SCHEMA_VERSION
            ok = ok and metric_summary.get("tcp_setup_completed") == scenario["flows"]
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
    run = {
        "scenario": scenario["name"],
        "mode": scenario["mode"],
        "variant": variant,
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
        "stream_server_connections": stream_server_connections,
        "stream_server_violations": stream_server_violations,
        "stream_server_quiescent": stream_server_quiescent,
        "fairness_quiet_samples": fairness_quiet_samples,
        "reset_outcome_counts": reset_outcome_counts,
        "broker_pending_peak_bytes": (
            metric_summary.get("tcp_peak_pending_bytes")
            if scenario["mode"] == "stalled" and metric_summary is not None
            else None
        ),
        "expected_flows": scenario["flows"],
        "successful_flows": len(successful),
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
        "command": command,
        "metrics_file": str(metrics_path) if metrics_path is not None else None,
        "metric_summary": metric_summary,
        "metric_parse_errors": metric_parse_errors,
    }
    enriched = [
        {
            **record,
            "scenario": scenario["name"],
            "variant": variant,
            "measurement_kind": measurement_kind,
            "repetition": repetition,
        }
        for record in [*flows, *workload_samples]
    ]
    return run, enriched


def scenarios(args: argparse.Namespace) -> list[dict[str, Any]]:
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
        result += [
            {
                "name": f"stream-{direction}-{args.stream_flows}-flows",
                "mode": "stream",
                "flows": args.stream_flows,
                "value": args.stream_bytes,
                "direction": direction,
                "rate": 0,
            }
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
            (run["scenario"], run["variant"])
            for run in runs
            if run["measurement_kind"] == "measurement"
        }
    )
    for scenario, variant in keys:
        selected_runs = [
            run
            for run in runs
            if run["scenario"] == scenario
            and run["variant"] == variant
            and run["measurement_kind"] == "measurement"
        ]
        valid_run_keys = {
            (
                run["scenario"],
                run["variant"],
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
            and flow["measurement_kind"] == "measurement"
            and flow.get("ok")
            and (
                flow["scenario"],
                flow["variant"],
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
            and sample["measurement_kind"] == "measurement"
            and (
                sample["scenario"],
                sample["variant"],
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
        rows.append(
            {
                "scenario": scenario,
                "variant": variant,
                "valid_runs": sum(run["ok"] for run in selected_runs),
                "total_runs": len(selected_runs),
                "valid_flows": len(selected_flows),
                "valid_flow_count_consistent": len(selected_flows) == successful,
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
        "schema_version": 3,
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
        "yatht": binary_metadata(args.yatht, args.yatht_commit, args.yatht_build_command),
        "addfd_yatht": binary_metadata(
            args.addfd_yatht,
            args.addfd_commit,
            args.addfd_build_command,
        ),
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
        "stream_flows": args.stream_flows,
        "stream_bytes": args.stream_bytes,
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
    parser.add_argument("--addfd-yatht")
    parser.add_argument("--addfd-commit", type=git_commit)
    parser.add_argument("--addfd-build-command")
    parser.add_argument("--variants", type=comma_variants, default="direct,addfd,stable")
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
    parser.add_argument("--stalled-flows", type=int, default=128)
    # The proxied chain (kernel socket autotuning on both yatht hops, the 64 KiB
    # relay buffer, and the SOCKS proxy's stream buffers) can absorb several MiB
    # per flow on distributions with large tcp_rmem/tcp_wmem defaults; the
    # per-flow budget must exceed that or flows never observe EAGAIN.
    parser.add_argument("--stalled-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--stalled-hold-ms", type=int, default=250)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--seed", type=int, default=20260723)
    parser.add_argument("--cc", type=executable, default="cc")
    parser.add_argument("--workload", type=Path, default=DEFAULT_WORKLOAD)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--skip-diagnostics", action="store_true")
    args = parser.parse_args()
    if isinstance(args.variants, str):
        args.variants = comma_variants(args.variants)
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
    if "addfd" in args.variants:
        if (
            args.addfd_yatht is None
            or args.addfd_commit is None
            or args.addfd_build_command is None
        ):
            parser.error("addfd requires --addfd-yatht, --addfd-commit, and --addfd-build-command")
        try:
            args.addfd_yatht = executable(args.addfd_yatht)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
    else:
        args.addfd_yatht = None
        args.addfd_commit = None
    if args.connections <= 0 or args.warmups < 0 or args.repetitions <= 0:
        parser.error("connections/repetitions must be positive and warmups nonnegative")
    if any(flows <= 0 for flows in args.idle_flows):
        parser.error("idle flow counts must be positive")
    if args.idle_hold_ms < 0 or args.stalled_hold_ms < 0:
        parser.error("hold times must be nonnegative")
    if args.stream_flows < 0 or (args.stream_flows > 0 and args.stream_bytes <= 0):
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

    servers = BenchmarkServers(args.timeout + 30)
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
                    order = list(args.variants)
                    rng.shuffle(order)
                    for variant in order:
                        warmup_run, warmup_flows = run_one(
                            variant,
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
                                    "stream_server_connections",
                                    "stream_server_violations",
                                    "stream_server_quiescent",
                                    "successful_flows",
                                    "parse_error",
                                    "stderr",
                                )
                            }
                            raise RuntimeError(
                                f"warmup failed for {scenario['name']}/{variant}: "
                                f"{json.dumps(failure, sort_keys=True)}"
                            )
                for repetition in range(args.repetitions):
                    order = list(args.variants)
                    rng.shuffle(order)
                    for variant in order:
                        run, flows = run_one(
                            variant,
                            args,
                            servers,
                            scenario,
                            repetition,
                            "measurement",
                            None,
                        )
                        runs.append(run)
                        flow_samples.extend(flows)
                        run_file.write(json.dumps(run, sort_keys=True) + "\n")
                        for flow in flows:
                            flow_file.write(json.dumps(flow, sort_keys=True) + "\n")
                        run_file.flush()
                        flow_file.flush()
                        print(
                            f"{scenario['name']} {variant} {repetition + 1}/{args.repetitions}: "
                            f"{'ok' if run['ok'] else 'FAILED'}",
                            flush=True,
                        )
                        require_stalled_server_quiescence(run)
                        require_stream_server_quiescence(run)
                if "stable" in args.variants and not args.skip_diagnostics:
                    metrics_path = metrics_dir / f"{scenario['name']}.jsonl"
                    run, flows = run_one(
                        "stable",
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


if __name__ == "__main__":
    main()
