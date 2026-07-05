# seccomp-unotify-proxy

Transparent TCP and UDP proxy launcher for Linux x86_64 using seccomp user
notification and `SECCOMP_IOCTL_NOTIF_ADDFD`.

```sh
cargo build
target/debug/seccomp-unotify-proxy --proxy socks5://127.0.0.1:1080 -- curl https://example.com
target/debug/seccomp-unotify-proxy --proxy socks5://127.0.0.1:1080 --enable-dns -- curl https://example.com
```

The tool redirects TCP `connect(2)` through one SOCKS5 or HTTP CONNECT proxy.
With `--enable-dns`, UDP/53 queries are forwarded as DNS-over-TCP through the
same TCP proxy. With `--enable-udp`, generic UDP is forwarded through SOCKS5 UDP
ASSOCIATE. It does not use `LD_PRELOAD` or `ptrace`, so it can work with static
binaries that ignore preload-based tools.

Requirements:

- Linux x86_64
- kernel 5.9 or newer
- a reachable SOCKS5 or HTTP CONNECT proxy

See [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) for the current design,
scope, and test plan.
