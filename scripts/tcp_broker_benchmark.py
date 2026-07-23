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
from typing import Any


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
        self.thread = threading.Thread(target=self._thread_main, name="benchmark-servers")
        self.error: BaseException | None = None
        self.stalled_release: asyncio.Event | None = None
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
            self._handle_destination,
            "127.0.0.1",
            0,
            backlog=65535,
        )
        proxy = await asyncio.start_server(
            self._handle_proxy,
            "127.0.0.1",
            0,
            backlog=65535,
        )
        stalled = await asyncio.start_server(
            self._handle_stalled_destination,
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
        await destination.wait_closed()
        await proxy.wait_closed()
        await stalled.wait_closed()

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


def build_workload(cc: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.stat().st_mtime_ns >= WORKLOAD_SOURCE.stat().st_mtime_ns:
        return
    subprocess.run(
        [
            cc,
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            str(WORKLOAD_SOURCE),
            "-o",
            str(output),
        ],
        check=True,
    )


def child_cpu_ns() -> int:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return int((usage.ru_utime + usage.ru_stime) * 1_000_000_000)


def system_cpu_ticks() -> list[int]:
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    return [int(value) for value in fields]


def process_resources(pid: int) -> tuple[int, int]:
    try:
        status = Path(f"/proc/{pid}/status").read_text().splitlines()
        rss_line = next(line for line in status if line.startswith("VmRSS:"))
        rss_kib = int(rss_line.split()[1])
        fd_count = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        return rss_kib, fd_count
    except (FileNotFoundError, PermissionError, StopIteration):
        return 0, 0


def percentile(values: list[int | float], fraction: float) -> float:
    ordered = sorted(float(value) for value in values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def parse_workload_output(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    flows = [record for record in records if record.get("event") == "flow"]
    summaries = [record for record in records if record.get("event") == "workload_summary"]
    if len(summaries) != 1:
        raise ValueError(f"expected one workload summary, got {len(summaries)}")
    return flows, summaries[0]


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
        proxy_before = servers.cpu_ns()
        system_before = system_cpu_ticks()
        started = time.perf_counter_ns()
        timed_out = False
        stalled_ready = False
        stalled_released = False
        release_at: float | None = None
        peak_rss_kib = 0
        peak_fds = 0
        with tempfile.TemporaryFile(mode="w+") as stdout_file, tempfile.TemporaryFile(
            mode="w+"
        ) as stderr_file:
            process = subprocess.Popen(
                command,
                text=True,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            deadline = time.monotonic() + args.timeout
            while process.poll() is None:
                rss_kib, fd_count = process_resources(process.pid)
                peak_rss_kib = max(peak_rss_kib, rss_kib)
                peak_fds = max(peak_fds, fd_count)
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
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.005)
            if scenario["mode"] == "stalled" and not stalled_released:
                servers.release_stalled_run()
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
    system_after = system_cpu_ticks()
    proxy_cpu_ns = servers.cpu_ns() - proxy_before
    child_delta_ns = child_cpu_ns() - child_before

    parse_error = None
    try:
        flows, workload_summary = parse_workload_output(completed.stdout)
    except (json.JSONDecodeError, ValueError) as error:
        flows, workload_summary = [], {}
        parse_error = str(error)

    metric_summary: dict[str, Any] | None = None
    if metrics_path is not None and metrics_path.exists():
        metric_events = [
            json.loads(line)
            for line in metrics_path.read_text().splitlines()
            if line.strip()
        ]
        summaries = [event for event in metric_events if event.get("event") == "run_summary"]
        if summaries:
            metric_summary = summaries[-1]

    successful = [flow for flow in flows if flow.get("ok")]
    ok = (
        completed.returncode == 0
        and parse_error is None
        and len(successful) == scenario["flows"]
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
        ok = ok and metric_summary is not None
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
        "proxy_cpu_ns": proxy_cpu_ns,
        "process_peak_rss_kib": peak_rss_kib,
        "process_peak_fds": peak_fds,
        "system_cpu_ticks": sum(system_after) - sum(system_before),
        "target_user_cpu_ns": workload_summary.get("user_cpu_ns"),
        "target_system_cpu_ns": workload_summary.get("system_cpu_ns"),
        "bytes": workload_summary.get("bytes", 0),
        "parse_error": parse_error,
        "stderr": completed.stderr[-2000:],
        "command": command,
        "metrics_file": str(metrics_path) if metrics_path is not None else None,
        "metric_summary": metric_summary,
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


def summarize(runs: list[dict[str, Any]], flow_samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
        selected_flows = [
            flow
            for flow in flow_samples
            if flow["scenario"] == scenario
            and flow["variant"] == variant
            and flow["measurement_kind"] == "measurement"
            and flow.get("ok")
        ]
        connect = [flow["connect_ns"] for flow in selected_flows]
        first = [
            flow["first_response_ns"]
            for flow in selected_flows
            if "first_response_ns" in flow
        ]
        wall = [run["wall_ns"] for run in selected_runs if run["ok"]]
        successful = sum(run["successful_flows"] for run in selected_runs if run["ok"])
        wall_total = sum(wall)
        rows.append(
            {
                "scenario": scenario,
                "variant": variant,
                "valid_runs": sum(run["ok"] for run in selected_runs),
                "total_runs": len(selected_runs),
                "valid_flows": len(selected_flows),
                "connect_p50_ns": percentile(connect, 0.50) if connect else None,
                "connect_p95_ns": percentile(connect, 0.95) if connect else None,
                "connect_p99_ns": percentile(connect, 0.99) if connect else None,
                "first_response_p50_ns": percentile(first, 0.50) if first else None,
                "first_response_p99_ns": percentile(first, 0.99) if first else None,
                "wall_median_ns": statistics.median(wall) if wall else None,
                "connections_per_second": (
                    successful / (wall_total / 1_000_000_000) if wall_total else None
                ),
                "child_cpu_median_ns": (
                    statistics.median(run["child_cpu_ns"] for run in selected_runs if run["ok"])
                    if wall
                    else None
                ),
                "proxy_cpu_median_ns": (
                    statistics.median(run["proxy_cpu_ns"] for run in selected_runs if run["ok"])
                    if wall
                    else None
                ),
                "process_peak_rss_median_kib": (
                    statistics.median(
                        run["process_peak_rss_kib"] for run in selected_runs if run["ok"]
                    )
                    if wall
                    else None
                ),
                "process_peak_fds_max": (
                    max(run["process_peak_fds"] for run in selected_runs if run["ok"])
                    if wall
                    else None
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


def environment_metadata(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_unix_ns": time.time_ns(),
        "git_commit": command_output(["git", "rev-parse", "HEAD"]),
        "git_status": command_output(["git", "status", "--short"]),
        "uname": command_output(["uname", "-a"]),
        "rustc": command_output(["rustc", "--version"]),
        "cc": command_output([args.cc, "--version"]),
        "python": sys.version,
        "cpu_count": os.cpu_count(),
        "rlimit_nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
        "perf_available": shutil.which("perf") is not None,
        "yatht": args.yatht,
        "addfd_yatht": args.addfd_yatht,
        "workload": str(args.workload),
        "warmups": args.warmups,
        "repetitions": args.repetitions,
        "connections": args.connections,
        "payload_sizes": args.payload_sizes,
        "idle_flows": args.idle_flows,
        "stalled_flows": args.stalled_flows,
        "stalled_bytes": args.stalled_bytes,
        "stalled_hold_ms": args.stalled_hold_ms,
        "random_seed": args.seed,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yatht", type=executable, default=str(ROOT / "target/release/yatht"))
    parser.add_argument("--addfd-yatht", type=executable)
    parser.add_argument("--variants", default="direct,addfd,stable")
    parser.add_argument("--connections", type=int, default=1000)
    parser.add_argument("--payload-sizes", type=comma_sizes, default=comma_sizes("0,1,1024,16384,65536"))
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
    args.variants = [variant for variant in args.variants.split(",") if variant]
    unknown = sorted(set(args.variants) - set(VARIANT_ORDER))
    if unknown:
        parser.error(f"unknown variants: {', '.join(unknown)}")
    if "addfd" in args.variants and args.addfd_yatht is None:
        parser.error("--addfd-yatht is required when the addfd variant is enabled")
    if args.connections <= 0 or args.warmups < 0 or args.repetitions <= 0:
        parser.error("connections/repetitions must be positive and warmups nonnegative")
    return args


def main() -> None:
    args = parse_args()
    build_workload(args.cc, args.workload)
    run_name = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    output_dir = (args.output_dir or (DEFAULT_OUTPUT_ROOT / run_name)).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    metrics_dir = output_dir / "metrics"
    metrics_dir.mkdir()
    (output_dir / "environment.json").write_text(
        json.dumps(environment_metadata(args), indent=2, sort_keys=True) + "\n"
    )

    servers = BenchmarkServers(args.timeout + 30)
    servers.start()
    rng = random.Random(args.seed)
    runs: list[dict[str, Any]] = []
    flow_samples: list[dict[str, Any]] = []
    try:
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
                        warmup_run, _ = run_one(
                            variant,
                            args,
                            servers,
                            scenario,
                            warmup,
                            "warmup",
                            None,
                        )
                        if not warmup_run["ok"]:
                            raise RuntimeError(
                                f"warmup failed for {scenario['name']}/{variant}: "
                                f"{warmup_run['stderr']}"
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
    finally:
        servers.stop()

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
    if failed:
        print(f"failed runs: {len(failed)}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
