# yatht

[![CI](https://github.com/hmgle/yatht/actions/workflows/ci.yml/badge.svg)](https://github.com/hmgle/yatht/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hmgle/yatht)](https://github.com/hmgle/yatht/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Yet Another Traffic Handoff Transport** — a lightweight TCP and experimental
UDP proxy launcher for trusted Linux `x86_64` processes using seccomp user
notification (`SECCOMP_IOCTL_NOTIF_ADDFD`), with no `LD_PRELOAD` or `ptrace`.

## Features

- **TCP redirection**: Routes `connect(2)` through a SOCKS5 or HTTP CONNECT
  proxy while preserving the target's original socket file description (keeping
  `epoll` registrations, `dup(2)`/`fork(2)` aliases, and socket options intact).
- **DNS-over-TCP (`--enable-dns`)**: Tunnels UDP/53 queries over TCP through
  either SOCKS5 or HTTP CONNECT proxies.
- **Experimental UDP (`--enable-udp`)**: Relays generic UDP over SOCKS5 UDP
  ASSOCIATE, with optional stable socket identity (`--udp-socket-mode=stable`).
- **Static-binary friendly**: Operates at the syscall layer, working even for
  statically linked binaries that ignore `LD_PRELOAD`.
- **Flexible routing**: TCP and generic UDP bypass local/private destinations
  by default and support repeatable CIDR bypass and allow-list controls.
- **Bounded epoll broker**: Relays TCP flows with strict fd/memory caps and
  opt-in experimental `splice` and warm proxy-session data paths.

## Requirements

- Linux `x86_64`, kernel **6.9+** (`PIDFD_THREAD` required)
- Rust **1.95+** (for building from source)
- A reachable SOCKS5 or HTTP CONNECT proxy

## Quick Start

Build the release binary from the repository root.

```sh
cargo build --release
```

Replace `127.0.0.1:7890` with your proxy address and put `--` before the target
command. Without a proxy setting on the CLI or in the config file, `yatht`
uses `socks5://127.0.0.1:1080`. The last two examples use `dig` to send UDP
queries without falling back to TCP.

```sh
# Basic TCP proxying
target/release/yatht --proxy socks5://127.0.0.1:7890 -- curl https://example.com

# Tunnel a UDP DNS query over TCP
target/release/yatht --proxy socks5://127.0.0.1:7890 --enable-dns -- \
  dig +notcp +ignore @1.1.1.1 example.com

# Relay a UDP query via SOCKS5 UDP ASSOCIATE
target/release/yatht --proxy socks5://127.0.0.1:7890 --enable-udp -- \
  dig +notcp +ignore @1.1.1.1 example.com
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Configuration

Pass options via CLI flags or a TOML file (`--config examples/config.toml`). CLI
CIDR flags extend file lists, CLI booleans enable matching features, and
`--proxy-local` overrides `bypass_local = true`.

```toml
proxy = "socks5://127.0.0.1:1080"
connect_timeout = "10s"
bypass_local = true
bypass_cidrs = []
proxy_cidrs = []
enable_dns = false
enable_udp = false
dns_server = "1.1.1.1:53"
udp_socket_mode = "lazy"
debug = false
# metrics_file = "/tmp/yatht-metrics.jsonl"
```

| Flag | Description |
| --- | --- |
| `--proxy <url>` | `socks5://[user:pass@]host:port` or `http://host:port` (percent-encode reserved chars in credentials). |
| `--config <path>` | Load settings from a TOML configuration file. |
| `--bypass-cidr <CIDR>` | Direct-route matching destinations (repeatable). |
| `--proxy-cidr <CIDR>` | Proxy only matching destinations (repeatable). |
| `--proxy-local` | Also proxy loopback, private, and link-local destinations. |
| `--connect-timeout <duration>` | Absolute proxy setup deadline per flow and for startup proxy DNS resolution (default `10s`). |
| `--enable-dns` | Redirect UDP/53 as DNS-over-TCP, taking precedence over local and CIDR routing rules. |
| `--dns-server <addr>` | Upstream DNS server for `--enable-dns` (default `1.1.1.1:53`). |
| `--enable-udp` | Redirect generic UDP via SOCKS5 UDP ASSOCIATE (experimental). |
| `--udp-socket-mode <lazy\|stable>` | UDP socket identity model (default `lazy`; `stable` requires `--enable-udp`). |
| `--debug` | Print routing and notification diagnostics. |
| `--metrics-file <path>` | Write experimental JSONL metrics (schema v7; file must not already exist). |

<details>
<summary>Advanced runtime environment selectors (rollback &amp; experiments)</summary>

Defaults are the supported configuration; unsupported values fail startup.

| Variable | Values | Notes |
| --- | --- | --- |
| `SUP_TCP_REACTOR` | `epoll` (default), `poll` | Readiness backend (`poll` is the rollback path). |
| `SUP_TCP_DATA_MOVER` | `buffered` (default), `splice` | Relay strategy; experimental `splice` moves data through kernel pipes with a per-round budget. |
| `SUP_TCP_SPLICE_QUICKACK` | `on` (default), `off` | Flushes delayed ACK after small `splice` rounds; ignored by `buffered`. |
| `SUP_TCP_PROXY_SESSION` | `cold` (default), `warm-one-shot` | Experimental `warm-one-shot` keeps up to 16 pre-established sessions (30 s idle timeout) for short-connection bursts over higher-RTT proxies. |
| `SUP_UDP_SOCKET_MODE` | `lazy`, `stable` | **Deprecated** lowest-precedence alias for `--udp-socket-mode` (prints a notice; slated for removal after 0.5.0). |

</details>

## Compatibility and Limitations

### Protocol support matrix

| Feature | SOCKS5 | HTTP CONNECT | Status |
| --- | --- | --- | --- |
| TCP `connect(2)` | Yes | Yes | Stable (conventional blocking clients) |
| DNS-over-TCP (UDP/53) | Yes | Yes | Supported (`--enable-dns`) |
| Generic UDP | Yes (UDP ASSOCIATE) | No | Experimental (`--enable-udp`) |

### TCP

- **Preserved**: Open file description identity, pre-existing `epoll`
  registrations, `dup(2)`/`fork(2)` aliases, bind state, and ordinary socket
  options.
- **Limitations**: Split-connection proxying, not full remote socket emulation.
  Nonblocking `connect(2)` completes synchronously; `getpeername(2)` and
  `TCP_INFO` reflect the local loopback broker leg; route-affecting options like
  `SO_BINDTODEVICE` can block reaching the loopback broker.
- **Broker limits**: Up to 16,384 active flows (adjusted for `RLIMIT_NOFILE`),
  128 pending registrations, and 256 MiB global pending/allocated buffer caps
  (fail-closed).

### UDP (Experimental)

- **Covered syscalls**: `sendto(2)`, `sendmsg(2)`, `sendmmsg(2)`, `recvfrom(2)`,
  `recvmsg(2)`, `getsockname(2)`, `getpeername(2)`, common `SOL_SOCKET` identity
  options (`SO_DOMAIN`, `SO_TYPE`, `SO_PROTOCOL`, `SO_ERROR`), and `recvmmsg(2)`
  in `stable` mode.
- **`lazy` vs `stable` mode**: `lazy` (default) injects the relay on the first
  proxied send/connect. Earlier aliases and `epoll` registrations stay on the
  original socket. `stable` (`--udp-socket-mode=stable`) injects at `socket(2)`
  time, so aliases and `epoll` registrations refer to the same endpoint. It
  also reserves real local ports on bind/connect/send.
- **Async I/O & limits**: Sends and receives are decoupled across independent
  16-datagram per-route queues (direct, SOCKS5, DNS) and up to 128 active UDP
  relays (`ENOBUFS` when exhausted). Successful sends indicate queue admission,
  not delivery; SOCKS5 payloads above 65,497 B (IPv4) / 65,485 B (IPv6) fail
  with `EMSGSIZE`.
- **Not preserved**: Ancillary data (`msg_control`), error queues,
  connected-peer receive filtering, `IPV6_V6ONLY` virtualization, and SOCKS5
  replies with domain-name source addresses.

### DNS-over-TCP

- Pipelines queries over up to 16 TCP streams per relay (one per original DNS
  destination), buffering at most one outgoing and one incoming frame per
  stream.
- Healthy streams are not evicted; queries beyond 16 destinations are dropped
  and counted in `udp_dropped_jobs`. Failed streams reconnect on later queries
  without replaying in-flight ones.

### Process Supervision & Security Model

- **Subreaper**: Keeps the seccomp listener alive until all descendants exit,
  while returning the exit status of the initially launched process.
- **Trusted processes only**: Direct routes use `SECCOMP_USER_NOTIF_FLAG_CONTINUE`,
  which has an inherent pointer-argument TOCTOU window. Do **not** rely on CIDR
  rules as a security boundary against hostile code — enforce egress at the
  kernel layer (network namespace, `nftables`, cgroup eBPF). See
  [SECURITY.md](SECURITY.md).

For full socket semantics, timeout/disconnect rules, relay reclamation, and
metrics definitions, see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Development

Run the standard checks:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run the deterministic local TCP broker benchmark (writes results under
gitignored `bench-results/tcp-broker/`):

```sh
cargo build --release --locked
uv run scripts/tcp_broker_benchmark.py \
  --yatht target/release/yatht \
  --yatht-build-command 'cargo build --release --locked'
```

Use `--stable-data-movers`, `--proxy-session-sources`, `--proxy-rtt-ms`,
`--splice-readiness-gate`, and `--warm-readiness-gate` for paired experimental
comparisons. Run the benchmark harness tests with:

```sh
python3 -X dev scripts/test_tcp_broker_benchmark.py
```

### Further Documentation

- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) — detailed socket semantics,
  edge cases, limits, and metrics reference
- [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) — current design, scope,
  and test plan
- [docs/SOCKET_SEMANTICS_ROADMAP.md](docs/SOCKET_SEMANTICS_ROADMAP.md) —
  compatibility architecture and backend roadmap

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
