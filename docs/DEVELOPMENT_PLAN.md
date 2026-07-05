# seccomp-unotify-proxy Development Plan

## Summary

`seccomp-unotify-proxy` is a proxychains-ng-like launcher for Linux processes.
The current version transparently redirects TCP `connect(2)`, UDP DNS queries,
and generic UDP sends through one configured proxy without `LD_PRELOAD` and
without `ptrace`.

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
  --enable-dns                    Redirect UDP/53 through DNS-over-TCP
  --enable-udp                    Redirect generic UDP through SOCKS5 UDP ASSOCIATE
  --dns-server <addr>             DNS-over-TCP upstream, default 1.1.1.1:53
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
enable_dns = false
enable_udp = false
dns_server = "1.1.1.1:53"
```

CLI values override or extend file values. If no proxy is provided, the default
is `socks5://127.0.0.1:1080`.

## Implementation

- The parent creates a Unix socketpair and re-execs itself into a small child
  stage.
- The child stage sets `PR_SET_NO_NEW_PRIVS`, installs a seccomp classic-BPF
  filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, writes the listener fd number
  to the parent, then `execve`s the requested target after the parent
  acknowledges receipt.
- The filter kills non-x86_64 ABIs, always traps `connect(2)`, and traps UDP
  send/receive syscalls only when DNS or generic UDP redirection is enabled.
  All other syscalls are allowed.
- The child stage writes the listener fd number to the parent and the parent
  duplicates it with `pidfd_getfd(2)`, avoiding a post-filter `sendmsg(2)`
  bootstrap exception.
- For each notification the supervisor reads the target `sockaddr` from
  `/proc/<pid>/mem`, validates the notification id, and applies routing policy.
- Direct routes respond with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, letting the
  original `connect` run unchanged.
- Proxied routes complete the SOCKS5/HTTP CONNECT handshake in the supervisor,
  inject the connected TCP fd into the target with
  `SECCOMP_IOCTL_NOTIF_ADDFD | SECCOMP_ADDFD_FLAG_SETFD`, then respond with
  `connect() = 0`.
- TCP proxy failures are fail-closed and return `ECONNREFUSED`; they do not
  fall back to direct connections.
- UDP redirection injects a connected loopback datagram socket into the target
  and runs a supervisor relay. Explicit `sendto(2)` / `sendmsg(2)` destinations
  are forwarded by the notification handler; connected UDP sends are read by the
  relay socket.
- DNS redirection forwards each UDP/53 payload to `dns_server` using DNS-over-TCP
  through the configured TCP proxy. Generic UDP uses SOCKS5 UDP ASSOCIATE and is
  unavailable for HTTP CONNECT proxies.

## Routing Rules

The first matching rule wins:

1. Non-IPv4/IPv6 socket families are continued directly.
2. Local/private/link-local/multicast/unspecified addresses bypass by default.
3. `--bypass-cidr` / `bypass_cidrs` matches bypass.
4. If any `--proxy-cidr` / `proxy_cidrs` exist, only matching destinations are
   proxied.
5. Remaining TCP destinations are proxied.
6. With `--enable-dns`, UDP/53 is redirected before generic UDP policy.
7. With `--enable-udp`, generic UDP follows the same CIDR policy as TCP.

## Test Plan

- Unit tests cover BPF shape, proxy URL parsing, CIDR routing, HTTP CONNECT
  request generation, SOCKS5 UDP framing, sockaddr parsing, and internal argv
  encoding.
- Integration tests cover TCP CONNECT redirection, UDP/53 DNS-over-TCP
  redirection, and generic UDP over SOCKS5 UDP ASSOCIATE using local fake
  proxies.
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
target/debug/seccomp-unotify-proxy --proxy socks5://127.0.0.1:1080 --enable-dns -- curl https://example.com
```

The reported IP should be the proxy egress IP. A connection to `127.0.0.1`
should bypass the proxy unless `--proxy-local` is set.

## Deferred Work

- Multiple proxy chain modes compatible with proxychains-ng.
- Additional architectures such as aarch64.
- Optional compatibility fallback for kernels older than 5.9.
