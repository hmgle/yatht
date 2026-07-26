# yatht

[![CI](https://github.com/hmgle/yatht/actions/workflows/ci.yml/badge.svg)](https://github.com/hmgle/yatht/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hmgle/yatht)](https://github.com/hmgle/yatht/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`yatht` stands for "Yet Another Traffic Handoff Transport": a short name for
handing a target process' traffic off to an external proxy transport.

TCP and experimental UDP proxy launcher for trusted Linux x86_64 processes
using seccomp user notification and `SECCOMP_IOCTL_NOTIF_ADDFD`.

## Features

- Redirects TCP `connect(2)` through a SOCKS5 or HTTP CONNECT proxy.
- Preserves the original TCP socket description, including existing epoll
  registrations and aliases, while relaying through a local broker.
- Relays TCP flows through a bounded-budget epoll broker, with opt-in
  experimental splice and warm proxy-session data paths.
- Redirects UDP/53 DNS queries as DNS-over-TCP when `--enable-dns` is set.
- Redirects request/response UDP through SOCKS5 UDP ASSOCIATE when
  experimental `--enable-udp` is set.
- Works without `LD_PRELOAD` or `ptrace`, including for static binaries that
  ignore preload-based tools.
- Lets local/private destinations bypass the proxy by default, with CIDR
  allow-list and bypass controls.

## Requirements

- Linux x86_64
- Linux kernel 5.9 or newer
- Rust toolchain for building from source
- A reachable SOCKS5 or HTTP CONNECT proxy

## Build

```sh
cargo build --release
```

The binary will be available at `target/release/yatht`.

## Quick Start

```sh
cargo build
target/debug/yatht --proxy socks5://127.0.0.1:1080 -- curl https://example.com
target/debug/yatht --proxy socks5://127.0.0.1:1080 --enable-dns -- curl https://example.com
```

Use `--` before the target command and its arguments. If `--proxy` is omitted,
the default proxy is `socks5://127.0.0.1:1080`.

## Configuration

Configuration can be passed through CLI flags or a TOML file:

```sh
target/release/yatht --config examples/config.toml -- curl https://example.com
```

```toml
proxy = "socks5://127.0.0.1:1080"
connect_timeout = "10s"
bypass_local = true
bypass_cidrs = []
proxy_cidrs = []
enable_dns = false
enable_udp = false
dns_server = "1.1.1.1:53"
debug = false
# metrics_file = "/tmp/yatht-metrics.jsonl"
```

Important options:

- `--proxy <url>`: `socks5://[user:pass@]host:port` or `http://host:port`.
- `--config <path>`: TOML configuration file.
- `--bypass-cidr <CIDR>`: direct-route matching destinations; repeatable.
- `--proxy-cidr <CIDR>`: proxy only matching destinations; repeatable.
- `--proxy-local`: proxy local/private/link-local destinations too.
- `--connect-timeout <duration>`: proxy connection timeout, default `10s`.
- `--enable-dns`: redirect UDP/53 through DNS-over-TCP.
- `--enable-udp`: redirect generic UDP through SOCKS5 UDP ASSOCIATE.
- `--dns-server <addr>`: DNS-over-TCP upstream for `--enable-dns`.
- `--debug`: print routing and notification diagnostics.
- `--metrics-file <path>`: write experimental performance metrics as JSONL.

CLI CIDR options extend file CIDR lists. CLI booleans enable their matching
features. `--proxy-local` disables the default `bypass_local = true` behavior.

The metrics file is opt-in and must not already exist. It contains versioned
run metadata (schema version 6), TCP broker limits, one setup record per
proxied TCP connection with per-stage timings and its proxy session source
(cold, warm hit, or warm miss), and a final summary with queue, flow,
pending-byte, allocated-buffer, relay, syscall, CPU, warm-session-pool, and
failure counters. Event delivery uses a bounded queue; the final
`dropped_metric_events` counter reports any records discarded under pressure.

The TCP broker admits at most 16,384 active flows and reduces that limit when
`RLIMIT_NOFILE` cannot preserve fd headroom. Registration is bounded to 128
pending flows. Relay buffers have separate 256 MiB global limits for logical
pending bytes and allocated payload capacity. Empty 16 KiB blocks are released
immediately. Resource exhaustion is fail-closed and classified in the summary.

### Runtime environment selectors

The TCP broker data plane exposes environment selectors. The defaults are the
supported configuration; the alternates exist for rollback and for opt-in
experiments. Unsupported values fail startup instead of being ignored.

- `SUP_TCP_REACTOR=epoll|poll`: readiness backend. Default `epoll`; `poll` is
  the explicit rollback path.
- `SUP_TCP_DATA_MOVER=buffered|splice`: relay strategy. Default `buffered`
  user-space copies; `splice` is experimental and moves payload through
  kernel pipes with a per-round budget.
- `SUP_TCP_SPLICE_QUICKACK=on|off`: default `on`. With the splice mover,
  flushes the pending delayed ACK after a small drained round to avoid a
  delayed-ACK/Nagle timer interlock. The buffered mover ignores it.
- `SUP_TCP_PROXY_SESSION=cold|warm-one-shot`: proxy session source. Default
  `cold` dials the proxy once per flow. `warm-one-shot` is experimental and
  keeps a demand-driven pool of up to 16 pre-established proxy sessions with
  a 30 s idle timeout; each warm session serves exactly one flow and misses
  fall back to cold dials. It mainly benefits short-connection bursts against
  proxies with non-trivial RTT.

## Compatibility and Limitations

TCP redirection is intended for conventional blocking clients. The target's
original AF_INET/AF_INET6 socket is connected to a per-flow loopback broker
after the upstream proxy handshake succeeds. This keeps the socket's open file
description stable, so existing epoll registrations, `dup(2)`/`fork(2)`
aliases, explicit bind state, and socket options remain attached.

This is still split-connection proxying rather than complete remote socket
semantics. A nonblocking `connect(2)` is completed synchronously. Kernel peer
and transport queries such as `getpeername(2)` and `TCP_INFO` describe the
local broker leg rather than the requested remote peer. Route-affecting options
such as `SO_BINDTODEVICE` can also prevent the target socket from reaching the
loopback broker.

Generic UDP redirection is experimental and currently models one request with
at most one response. It does not preserve unsolicited, delayed, reordered, or
multiple responses, ancillary data, pre-existing epoll registrations, or fd
aliases created with `dup(2)` or inherited across `fork(2)`.

UDP redirection currently covers `sendto(2)`, `sendmsg(2)`, `recvfrom(2)`, and
`recvmsg(2)`. Batched `sendmmsg(2)` / `recvmmsg(2)` calls are not rewritten.

HTTP CONNECT proxies are supported for TCP and DNS-over-TCP. Generic UDP
redirection requires a SOCKS5 proxy because it uses SOCKS5 UDP ASSOCIATE.

The supervisor acts as a child subreaper and keeps the seccomp listener alive
until descendants of the initially launched process have exited. Its final exit
status remains the status of the initially launched process.

By default the launcher is optimized for trusted-process transparent proxying.
Direct routes are continued in-kernel for low overhead. Do not treat CIDR
routing in this process as a security boundary for hostile code: seccomp user
notification `CONTINUE` has an inherent pointer-argument TOCTOU window. For
strict egress enforcement, run the target in a network namespace, nftables
ruleset, cgroup eBPF policy, or equivalent kernel network policy that only
allows the configured direct CIDRs and proxy endpoint.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The deterministic local TCP broker benchmark builds its C workload on demand
and stores raw JSONL, partial failure results, commands, role-specific resource
samples, binary provenance, and environment metadata under
`bench-results/tcp-broker/` (gitignored):

```sh
cargo build --release --locked
uv run scripts/tcp_broker_benchmark.py \
  --yatht target/release/yatht \
  --yatht-build-command 'cargo build --release --locked' \
  --addfd-yatht ../yatht-pre-stable-b5554b9/target/release/yatht \
  --addfd-commit b5554b9 \
  --addfd-build-command 'cargo build --release --locked'
```

Paired same-repetition comparisons of the experimental data paths are
available through `--stable-data-movers` and `--proxy-session-sources`,
with `--proxy-rtt-ms` to model proxy RTT and `--splice-readiness-gate` /
`--warm-readiness-gate` for pre-registered acceptance checks. The harness has
its own dependency-free test suite:

```sh
python3 -X dev scripts/test_tcp_broker_benchmark.py
```

See [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) for the current design,
scope, and test plan. See
[docs/SOCKET_SEMANTICS_ROADMAP.md](docs/SOCKET_SEMANTICS_ROADMAP.md) for the
compatibility architecture and backend roadmap.

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
