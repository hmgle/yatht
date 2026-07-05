# seccomp-unotify-proxy Development Plan

## Summary

`seccomp-unotify-proxy` is a proxychains-ng-like launcher for Linux processes.
The first version transparently redirects TCP `connect(2)` through one SOCKS5 or
HTTP CONNECT proxy without `LD_PRELOAD` and without `ptrace`.

The implementation is from-scratch Rust and targets Linux x86_64 with kernel
5.9 or newer. The key kernel features are `SECCOMP_RET_USER_NOTIF`,
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, and `SECCOMP_IOCTL_NOTIF_ADDFD`.

## Public Interface

```text
seccomp-unotify-proxy [OPTIONS] -- <command> [args...]

Options:
  --config <path>                 TOML configuration file
  --proxy <url>                   socks5://[user:pass@]host:port or http://host:port
  --bypass-cidr <CIDR>            CIDR that bypasses the proxy; repeatable
  --proxy-cidr <CIDR>             CIDR allow-list for proxying; repeatable
  --proxy-local                   Proxy local/private destinations too
  --connect-timeout <duration>    Proxy connection timeout, default 10s
  --debug                         Print routing and notification diagnostics
```

TOML configuration uses the same names where practical:

```toml
proxy = "socks5://127.0.0.1:1080"
connect_timeout = "10s"
bypass_local = true
bypass_cidrs = []
proxy_cidrs = []
debug = false
```

CLI values override or extend file values. If no proxy is provided, the default
is `socks5://127.0.0.1:1080`.

## Implementation

- The parent creates a Unix socketpair and re-execs itself into a small child
  stage.
- The child stage sets `PR_SET_NO_NEW_PRIVS`, installs a seccomp classic-BPF
  filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, sends the listener fd to the
  parent with `SCM_RIGHTS`, then `execve`s the requested target.
- The filter kills non-x86_64 ABIs, traps `connect(2)` with
  `SECCOMP_RET_USER_NOTIF`, and allows all other syscalls.
- For each notification the supervisor reads the target `sockaddr` from
  `/proc/<pid>/mem`, validates the notification id, and applies routing policy.
- Direct routes respond with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, letting the
  original `connect` run unchanged.
- Proxied routes complete the SOCKS5/HTTP CONNECT handshake in the supervisor,
  inject the connected TCP fd into the target with
  `SECCOMP_IOCTL_NOTIF_ADDFD | SECCOMP_ADDFD_FLAG_SETFD`, then respond with
  `connect() = 0`.
- Proxy failures are fail-closed and return `ECONNREFUSED`; they do not fall
  back to direct connections.

## Routing Rules

The first matching rule wins:

1. Non-IPv4/IPv6 socket families are continued directly.
2. Local/private/link-local/multicast/unspecified addresses bypass by default.
3. `--bypass-cidr` / `bypass_cidrs` matches bypass.
4. If any `--proxy-cidr` / `proxy_cidrs` exist, only matching destinations are
   proxied.
5. Remaining TCP destinations are proxied.

## Test Plan

- Unit tests cover BPF shape, proxy URL parsing, CIDR routing, HTTP CONNECT
  request generation, sockaddr parsing, and internal argv encoding.
- Required local checks:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- Manual integration check on Linux x86_64/kernel >= 5.9:

```sh
cargo build
target/debug/seccomp-unotify-proxy --proxy socks5://127.0.0.1:1080 -- curl https://api.ipify.org
```

The reported IP should be the proxy egress IP. A connection to `127.0.0.1`
should bypass the proxy unless `--proxy-local` is set.

## Deferred Work

- DNS leak prevention for UDP/53.
- Generic UDP through SOCKS5 UDP ASSOCIATE.
- Multiple proxy chain modes compatible with proxychains-ng.
- Additional architectures such as aarch64.
- Optional compatibility fallback for kernels older than 5.9.
