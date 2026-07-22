# yatht

`yatht` stands for "Yet Another Traffic Handoff Transport": a short name for
handing a target process' traffic off to an external proxy transport.

TCP and experimental UDP proxy launcher for trusted Linux x86_64 processes
using seccomp user notification and `SECCOMP_IOCTL_NOTIF_ADDFD`.

## Features

- Redirects TCP `connect(2)` through a SOCKS5 or HTTP CONNECT proxy.
- Preserves the original TCP socket description, including existing epoll
  registrations and aliases, while relaying through a local broker.
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

CLI CIDR options extend file CIDR lists. CLI booleans enable their matching
features. `--proxy-local` disables the default `bypass_local = true` behavior.

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

See [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) for the current design,
scope, and test plan. See
[docs/SOCKET_SEMANTICS_ROADMAP.md](docs/SOCKET_SEMANTICS_ROADMAP.md) for the
compatibility architecture and backend roadmap.

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
