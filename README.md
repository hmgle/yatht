# seccomp-unotify-proxy

Transparent TCP proxy launcher for Linux x86_64 using seccomp user notification
and `SECCOMP_IOCTL_NOTIF_ADDFD`.

```sh
cargo build
target/debug/seccomp-unotify-proxy --proxy socks5://127.0.0.1:1080 -- curl https://example.com
```

The first release redirects TCP `connect(2)` through one SOCKS5 or HTTP CONNECT
proxy. It does not use `LD_PRELOAD` or `ptrace`, so it can work with static
binaries that ignore preload-based tools.

Requirements:

- Linux x86_64
- kernel 5.9 or newer
- a reachable SOCKS5 or HTTP CONNECT proxy

See [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) for the current design,
scope, and test plan.
