#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run deterministic direct, pre-stable, and stable TCP broker benchmarks."""

from __future__ import annotations

import argparse
import asyncio
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
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Coroutine


ROOT = Path(__file__).resolve().parent.parent
WORKLOAD_SOURCE = ROOT / "benchmarks" / "tcp_broker" / "workload.c"
DEFAULT_WORKLOAD = ROOT / "target" / "tcp-broker-benchmark" / "workload"
DEFAULT_OUTPUT_ROOT = ROOT / "target" / "tcp-broker-benchmarks"
VARIANT_ORDER = ("direct", "addfd", "stable")


class BenchmarkServers:
    def __init__(self, safety_timeout: float) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.stop_event: asyncio.Event | None = None
        self.destination_port = 0
        self.proxy_port = 0
        self.stalled_port = 0
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self._thread_main,
            name="benchmark-servers",
            daemon=True,
        )
        self.error: BaseException | None = None
        self.stalled_release: asyncio.Event | None = None
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
            self.loop.call_soon_threadsafe(self.stop_event.set)
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("benchmark servers did not stop")
        if self.error is not None:
            raise RuntimeError("benchmark servers failed") from self.error

    def cpu_ns(self) -> int:
        if self.loop is None:
            return 0
        future = asyncio.run_coroutine_threadsafe(self._thread_cpu_ns(), self.loop)
        return int(future.result(timeout=5))

    def prepare_stalled_run(self) -> None:
        if self.loop is None:
            raise RuntimeError("benchmark servers are not running")
        future = asyncio.run_coroutine_threadsafe(self._prepare_stalled_run(), self.loop)
        future.result(timeout=5)

    async def _prepare_stalled_run(self) -> None:
        self.stalled_release = asyncio.Event()

    def release_stalled_run(self) -> None:
        if self.loop is not None and self.stalled_release is not None:
            self.loop.call_soon_threadsafe(self.stalled_release.set)

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
            lambda reader, writer: self._spawn_connection(
                self._handle_stalled_destination(reader, writer), writer
            ),
            "127.0.0.1",
            0,
            backlog=65535,
        )
        self.destination_port = destination.sockets[0].getsockname()[1]
        self.proxy_port = proxy.sockets[0].getsockname()[1]
        self.stalled_port = stalled.sockets[0].getsockname()[1]
        self.ready.set()
        await self.stop_event.wait()
        destination.close()
        proxy.close()
        stalled.close()
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

    def _spawn_connection(
        self,
        coroutine: Coroutine[Any, Any, None],
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(coroutine)
        self.connection_tasks.add(task)
        self.connection_writers.add(writer)
        task.add_done_callback(lambda completed: self._connection_done(completed, writer))

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
            await asyncio.gather(
                self._copy_stream(reader, upstream_writer),
                self._copy_stream(upstream_reader, writer),
            )
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
    ) -> None:
        try:
            release = self.stalled_release
            if release is None:
                raise RuntimeError("stalled run was not prepared")
            await asyncio.wait_for(release.wait(), timeout=self.safety_timeout)
            while await reader.read(65536):
                pass
        except (ConnectionError, asyncio.TimeoutError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _copy_stream(
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


def executable(value: str) -> str:
    candidate = Path(value).expanduser()
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate.resolve())
    found = shutil.which(value)
    if found:
        return found
    raise argparse.ArgumentTypeError(f"executable not found: {value}")


def git_commit(value: str) -> str:
    resolved = command_output(["git", "rev-parse", "--verify", f"{value}^{{commit}}"])
    if resolved is None:
        raise argparse.ArgumentTypeError(f"git commit not found: {value}")
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


def ensure_fd_limit(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    selected_flow_counts = list(args.idle_flows)
    if args.payload_sizes:
        selected_flow_counts.append(args.connections)
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
    except (OSError, StopIteration):
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


def parse_workload_output(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    flows = [record for record in records if record.get("event") == "flow"]
    summaries = [record for record in records if record.get("event") == "workload_summary"]
    if len(summaries) != 1:
        raise ValueError(f"expected one workload summary, got {len(summaries)}")
    return flows, summaries[0]


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
    destination_port = (
        servers.stalled_port if scenario["mode"] == "stalled" else servers.destination_port
    )
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
                    now = time.monotonic()
                    if scenario["mode"] == "stalled" and not stalled_ready:
                        if stalled_ready_path.exists():
                            stalled_ready = True
                            release_at = now + scenario["hold_ms"] / 1000
                    if release_at is not None and now >= release_at and not stalled_released:
                        servers.release_stalled_run()
                        stalled_released = True
                    if now >= deadline:
                        timed_out = True
                        terminate_process_group(process)
                        break
                    time.sleep(0.005)
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

    parse_error = None
    try:
        flows, workload_summary = parse_workload_output(completed.stdout)
    except (json.JSONDecodeError, ValueError) as error:
        flows, workload_summary = [], {}
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
    if scenario["mode"] == "stalled":
        ok = (
            ok
            and stalled_ready
            and stalled_released
            and workload_summary.get("blocked_flows") == scenario["flows"]
            and workload_summary.get("released") is True
        )
    if metric_summary is not None and metric_summary.get("dropped_metric_events") != 0:
        ok = False
    if metrics_path is not None:
        ok = ok and metric_summary is not None and not metric_parse_errors
        if metric_summary is not None:
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
        "stalled_released": stalled_released if scenario["mode"] == "stalled" else None,
        "application_backpressure_confirmed": (
            stalled_ready and workload_summary.get("blocked_flows") == scenario["flows"]
            if scenario["mode"] == "stalled"
            else None
        ),
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
            **flow,
            "scenario": scenario["name"],
            "variant": variant,
            "measurement_kind": measurement_kind,
            "repetition": repetition,
        }
        for flow in flows
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


def command_output(command: list[str]) -> str | None:
    try:
        return subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
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
        "schema_version": 2,
        "created_unix_ns": time.time_ns(),
        "git_commit": command_output(["git", "rev-parse", "HEAD"]),
        "git_status": command_output(["git", "status", "--short"]),
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
        "stalled_flows": args.stalled_flows,
        "stalled_bytes": args.stalled_bytes,
        "stalled_hold_ms": args.stalled_hold_ms,
        "random_seed": args.seed,
        "estimated_fd_limit": args.estimated_fd_limit,
        "resource_sampling": {
            "interval_ms": 5,
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
    parser.add_argument("--stalled-flows", type=int, default=128)
    parser.add_argument("--stalled-bytes", type=int, default=1024 * 1024)
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
        args.yatht_commit = args.yatht_commit or git_commit("HEAD")
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
    if args.stalled_flows < 0 or (args.stalled_flows > 0 and args.stalled_bytes <= 0):
        parser.error("stalled flows must be nonnegative and stalled bytes positive")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if not args.payload_sizes and not args.idle_flows and args.stalled_flows == 0:
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
    dirty_diff = command_output(["git", "diff", "--binary", "HEAD"])
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
                                    "stalled_released",
                                    "application_backpressure_confirmed",
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
