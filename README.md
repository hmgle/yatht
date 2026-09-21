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
- Redirects UDP through SOCKS5 UDP ASSOCIATE when
  experimental `--enable-udp` is set.
- Works without `LD_PRELOAD` or `ptrace`, including for static binaries that
  ignore preload-based tools.
- Lets local/private destinations bypass the proxy by default, with CIDR
  allow-list and bypass controls.

## Requirements

- Linux x86_64
- Linux kernel 6.9 or newer (`PIDFD_THREAD` is required)
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
udp_socket_mode = "lazy"
debug = false
# metrics_file = "/tmp/yatht-metrics.jsonl"
```

Important options:

- `--proxy <url>`: `socks5://[user:pass@]host:port` or `http://host:port`.
  Percent-encode reserved characters in SOCKS5 usernames and passwords.
- `--config <path>`: TOML configuration file.
- `--bypass-cidr <CIDR>`: direct-route matching destinations; repeatable.
- `--proxy-cidr <CIDR>`: proxy only matching destinations; repeatable.
- `--proxy-local`: proxy local/private/link-local destinations too.
- `--connect-timeout <duration>`: absolute proxy setup deadline covering each
  flow's address attempts and protocol handshake, default `10s`. Proxy DNS is
  resolved once at startup under the same bounded duration.
- `--enable-dns`: redirect UDP/53 through DNS-over-TCP.
- `--enable-udp`: redirect generic UDP through SOCKS5 UDP ASSOCIATE.
- `--dns-server <addr>`: DNS-over-TCP upstream for `--enable-dns`.
- `--udp-socket-mode <lazy|stable>`: UDP socket identity model, default `lazy`.
  Requires `--enable-udp`; `stable` without it fails startup.
- `--debug`: print routing and notification diagnostics.
- `--metrics-file <path>`: write experimental performance metrics as JSONL.

CLI CIDR options extend file CIDR lists. CLI booleans enable their matching
features. `--proxy-local` disables the default `bypass_local = true` behavior.

The metrics file is opt-in and must not already exist. It contains versioned
run metadata (schema version 6), TCP broker limits, one setup record per
proxied TCP connection with per-stage timings and its proxy session source
(cold, warm hit, or warm miss), and a final summary with queue, flow,
pending-byte, allocated-buffer, relay, syscall, CPU, warm-session-pool, and
failure counters. `udp_dropped_jobs` counts accepted datagrams that workers
fail to forward (setup/send errors, expired writes, DNS stream capacity, or an
incomplete DNS frame lost with its stream), independently of `--debug`.
It excludes synchronous syscall errors, missing replies, and jobs abandoned at
process teardown; the summary is a snapshot, since UDP workers are detached.
Event delivery uses a bounded queue; the final
`dropped_metric_events` counter reports any records discarded under pressure.

The TCP broker admits at most 16,384 active flows and reduces that limit when
`RLIMIT_NOFILE` cannot preserve fd headroom. Registration is bounded to 128
pending flows. Relay buffers have separate 256 MiB global limits for logical
pending bytes and allocated payload capacity. Empty 16 KiB blocks are released
immediately. Resource exhaustion is fail-closed and classified in the summary.

### Runtime environment selectors

The data plane exposes environment selectors. The defaults are the supported
configuration; the alternates exist for rollback and for opt-in experiments.
Unsupported values fail startup instead of being ignored.

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

`SUP_UDP_SOCKET_MODE=lazy|stable` is a deprecated alias for
`--udp-socket-mode`. It still works but prints a notice and will be removed in
the next release; it also has the lowest precedence, so the CLI flag and the
configuration key both override it. The mode changes observable socket
semantics rather than gating an internal data-plane implementation, which is
why it belongs on the CLI instead of alongside the selectors above.

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

Generic UDP redirection is experimental. Direct and SOCKS5 relay sends do not
wait for responses: silent peers do not throttle subsequent datagrams. Once a
transport exists, its receive path runs independently, including delayed,
reordered, and multiple responses. Different direct/proxy peers have no shared
response ordering guarantee. Ancillary data, connected-peer receive filtering,
and pre-existing epoll registrations are not preserved.
SOCKS5 sends intercepted through `sendto`, `sendmsg`, or `sendmmsg` reject
payloads above 65497 bytes for IPv4 destinations or 65485 bytes for IPv6
(including IPv4-mapped IPv6) with `EMSGSIZE`. These conservative limits reserve
the 10/22-byte SOCKS5 header within a 65507-byte outer UDP envelope, before the
association reveals the relay address. They also apply to IPv6 relay transports;
direct and DNS paths retain their native destination-family limits. Smaller
path-MTU limits or other asynchronous send failures remain possible and are
counted by `udp_dropped_jobs` when observed by the worker.
Emulated receives report `msg_controllen = 0` when returning no ancillary data.
The default lazy mode creates the relay on the first proxied send and does not
preserve aliases created before that point. Aliases made after replacement
share the relay, which survives until the last alias closes.
Pass `--udp-socket-mode=stable` with `--enable-udp` to inject an endpoint at
`socket(2)` time; this mode keeps
the open-file identity stable across `dup(2)`, `fork(2)`, and close races by
using `SO_COOKIE` as the primary relay key. Virtualized `sendmmsg(2)` runs in
every mode, including the first proxied batch; receive-supervisor handling of
`recvmmsg(2)` remains a stable-mode feature. Active UDP relay creation is
capped at 128, with separate bounded 16-datagram input queues for direct,
SOCKS5, and DNS traffic in each relay. Each route has its own pending send;
a stalled established transport does not block sends on other routes. Queues
apply backpressure independently (or `EAGAIN` for nonblocking sends). A thread
blocked sending to a full DNS queue must still return before it can issue its
next call, and all DNS destinations share one route queue. Successful
sends acknowledge queue admission, not remote delivery; queue overflow, network
errors, and closing/exiting before queued work is forwarded can still lose data.
`--connect-timeout` bounds proxy setup and stalled writes, not the time allowed
for a UDP reply. Initial proxy setup remains blocking and can delay both
forwarding and worker retirement until its deadline. After setup, reaping wakes
the I/O worker immediately, without waiting for a silent peer. A
`sendmmsg(2)` batch that outpaces the relay worker reports only the enqueued
entries as its sent count — like a kernel socket whose send buffer has filled
— so a large batch under `MSG_DONTWAIT` can partially commit. A dedicated
low-priority supervisor thread reclaims relays whose AF_UNIX inode no longer
has an open target-side alias, so its host-wide
`/proc/net/unix` read never stalls the receive reactor. It sweeps every second
and, after five consecutive sweeps that reclaim nothing, backs off up to 30
seconds; reclaiming a relay or creating a new one restores the base cadence.
Capacity-bound admission also sweeps and retries briefly, so a long backoff
delays cleanup without costing capacity. Normal socket creation does not scan
procfs, and an unavailable `/proc/net/unix` delays cleanup instead of breaking
creation while capacity remains.

UDP redirection covers `sendto(2)`, `sendmsg(2)`, `recvfrom(2)`, and
`recvmsg(2)`. `sendmmsg(2)` entries are rewritten and virtualized in every
mode, creating a lazy/DNS relay when the first batch needs proxy routing.
Mixed direct/proxy batches retain per-entry routing and partial-error results.
Stable mode serves `recvmmsg(2)` through the receive supervisor. Every relay
mode virtualizes `getsockname(2)`, `getpeername(2)`, and the common
`SOL_SOCKET` identity options (`SO_DOMAIN`, `SO_TYPE`, `SO_PROTOCOL`, and
`SO_ERROR`) for AF_INET/AF_INET6 UDP sockets. The reported bind and peer
addresses are logical relay state; an unbound socket reports its family's
wildcard address with port zero. Lazy/DNS queries preserve the local address
observed before replacement until a direct worker allocates a local socket;
that snapshot does not reserve the original port or describe the proxy's
external source address. Stable `bind(2)` reserves a real local UDP
socket immediately, so port zero becomes a kernel-assigned ephemeral port
before `getsockname(2)` returns; direct sends reuse that reservation.
Stable sends and connects also reserve an automatic local port before
returning, so a subsequent `bind(2)` fails with `EINVAL`. This reservation is
made even for proxy-only traffic, where it does not carry the outbound packets;
a newly created socket without bind/connect/send does not reserve a port.
The local port is released during relay cleanup after the last alias closes
(and after its workers exit), rather than synchronously with `close(2)`.
A proxy's external source port can still differ.
Logical operations reject invalid destination ports and unsupported families
before creating a relay.
AF_INET sockets reject IPv6 destinations, while stable AF_INET6 sockets model
Linux's default dual-stack behavior and accept IPv4 and IPv6 destinations;
their logical addresses are reported in the socket's own family, so a
dual-stack peer or response source appears as a v4-mapped IPv6 address.
Destination names are read the way the target socket reads them: a zero-length
name fails `sendto(2)` and falls back to the connected peer in `sendmsg(2)`, an
`AF_UNSPEC` name is an AF_INET address on AF_INET sockets and no name at all on
AF_INET6 ones, and any other family is rejected with that socket's error.
Bind remains strict-family, including Linux's IPv6 length checks and IPv4
`AF_UNSPEC` wildcard compatibility. `IPV6_V6ONLY` is not yet virtualized. An
`AF_UNSPEC` connect clears the peer and, in stable mode, releases local ports
not locked by an explicit nonzero bind. Destination-free sends then fail
with `EDESTADDRREQ`. Virtualized integer socket options preserve Linux's
short-buffer truncation and negative-length rejection rules. For
unconnected request/response traffic, `recvfrom(2)`, `recvmsg(2)`, and each
`recvmmsg(2)` entry report the numeric source from the SOCKS5 UDP response header
or the direct worker's kernel peer. `MSG_PEEK`, `MSG_TRUNC`, `MSG_WAITFORONE`,
partial completion, and mixed receive calls preserve payload/source queue order.
Blocking relayed receives
honor `SO_RCVTIMEO` read from the injected endpoint: a quiet
`recvfrom(2)`/`recvmsg(2)` fails with `EAGAIN` at the deadline, while
`recvmmsg(2)` re-arms the socket timeout after each delivered entry and returns
the completed count once it expires with progress. Successful batches write the
remaining explicit interval back to the caller's timespec; a failed writeback
returns `EFAULT` even after batch progress. Stable `recvmmsg(2)`
uses an absolute reactor deadline and returns zero with a zero remaining interval
when an empty-queue explicit timeout expires, instead of reproducing Linux's
documented timeout hang; when both the socket timeout and an explicit timespec
are armed, the earlier deadline keeps its own expiry result. Lazy replacement
transfers a pre-existing `SO_RCVTIMEO` to the injected endpoint. SOCKS5
domain-name response sources, `msg_control` data, error queues, and other
IP-level option semantics remain limited.

DNS-over-TCP pipelines queries without waiting for earlier answers and retains
partial TCP frames across readiness events. Each relay keeps at most 16 streams,
one per original DNS destination, so reordered replies retain the correct source
even when destinations reuse transaction IDs. Each stream buffers at most one
outgoing and one incoming frame; failed streams are discarded and later queries
reconnect. In-flight queries are not automatically replayed after failure.
Requests exceeding the stream limit are dropped and counted in
`udp_dropped_jobs` (details with `--debug`). Streams are not evicted while
healthy, so a long-lived relay that fills all slots rejects new destinations
until a stream fails or the relay closes.
SOCKS5 replies with domain-name sources are also dropped because no numeric
source address can be reported reliably.

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
  --yatht-build-command 'cargo build --release --locked'
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
