# yatht Development Plan

## Summary

`yatht` is short for "Yet Another Traffic Handoff Transport". It is a launcher
for trusted Linux processes. The current version
transparently redirects TCP `connect(2)`, UDP DNS queries, and generic UDP sends
through one configured proxy without `LD_PRELOAD` and without `ptrace`.

Generic UDP is experimental and limited to a request/response workload. The
seccomp backend is a compatibility tool, not a complete emulation of Linux
socket semantics or a security boundary.

The implementation is from-scratch Rust and targets Linux x86_64 with kernel
5.9 or newer. The key kernel features are `SECCOMP_RET_USER_NOTIF`,
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, and `SECCOMP_IOCTL_NOTIF_ADDFD`.

## Public Interface

```text
yatht [OPTIONS] -- <command> [args...]

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
  --metrics-file <path>           Write experimental performance metrics as JSONL
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
# metrics_file = "/tmp/yatht-metrics.jsonl"
```

CLI values override or extend file values. If no proxy is provided, the default
is `socks5://127.0.0.1:1080`.

## Implementation

- The parent creates a Unix socketpair and re-execs itself into a small child
  stage.
- The parent acts as a child subreaper. It preserves the initial target's exit
  status while keeping the listener alive until adopted descendants exit.
- Failure cleanup sends `SIGKILL` to the target tree and polls the direct child
  and adopted descendants against one shared one-second deadline. If the tree
  cannot be reaped or `/proc` enumeration fails, the supervisor reports both
  the monitoring and cleanup errors and exits before entering notification
  joins that require every seccomp filter user to be gone.
- The child stage sets `PR_SET_NO_NEW_PRIVS`, installs a seccomp classic-BPF
  filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, writes the listener fd number
  to the parent, then `execve`s the requested target after the parent
  acknowledges receipt.
- The filter kills non-x86_64 ABIs, always traps `connect(2)`, and traps UDP
  send/receive plus descriptor close/replacement syscalls only when DNS or
  generic UDP redirection is enabled. All other syscalls are allowed.
- The child stage writes the listener fd number to the parent and the parent
  duplicates it with `pidfd_getfd(2)`, avoiding a post-filter `sendmsg(2)`
  bootstrap exception.
- For each notification the supervisor reads target memory with
  `process_vm_readv(2)`, batching target iovecs when possible, validates the
  notification id, and applies routing policy. Simulated UDP receives write
  results back with `process_vm_writev(2)`.
- Direct routes respond with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, letting the
  original syscall run unchanged. Direct non-DNS `connect(2)` notifications use
  this fast path before socket-type inspection to avoid an extra
  `pidfd_getfd(2)`/`getsockopt(2)` round trip.
- Proxied routes duplicate the target TCP fd with `pidfd_getfd(2)`, complete the
  SOCKS5/HTTP CONNECT handshake on a separate upstream socket, then connect the
  original target open file description to a per-flow loopback listener. A
  shared bounded-buffer reactor relays the accepted local socket to the proxy
  tunnel before the supervisor responds with `connect() = 0`.
- Keeping the target TCP open file description avoids fd replacement races and
  natively preserves epoll registrations, descriptor aliases, bind state, and
  options on the target-side TCP leg. The reactor propagates half-closes and
  isolates ordinary flow errors without dedicating a thread to each flow.
- Before proxy setup, the broker reserves an active-flow permit. The default
  ceiling is 16,384 flows and is reduced from `RLIMIT_NOFILE` after preserving
  the larger of 20% or 256 fds, plus setup-worker headroom. Registration has a
  fixed capacity of 128, and buffered relay data shares a 256 MiB global
  pending-byte budget. Rejections are fail-closed and separately classified.
- Optional JSONL telemetry uses a bounded writer queue and records versioned run
  metadata, detected broker limits, per-flow setup spans and socket cookies,
  and a final resource/data/error summary. The destination path must not exist,
  so separate runs cannot silently overwrite one another.
- TCP proxy failures are fail-closed and return `ECONNREFUSED`; they do not
  fall back to direct connections.
- Nonblocking notifications are dispatched through a bounded queue to a bounded
  worker pool so slow proxy dials apply backpressure without creating one OS
  thread per notification. A readiness reactor retains pending blocking UDP
  receives without dedicating a thread to each quiet socket, then dispatches
  ready receives through a bounded worker pool. Once registered with the
  reactor, only one completion per relay runs at a time while different relays
  complete in parallel. The incoming receive queue remains unbounded so queue
  pressure does not change a blocking socket call into an `EAGAIN` retry; its
  size is bounded by the number of target threads because each thread can have
  only one notification pending.
- UDP redirection injects one end of an AF_UNIX datagram socketpair into the
  target and runs a supervisor relay on the other end. Explicit `sendto(2)` /
  `sendmsg(2)` destinations are forwarded by the notification handler;
  connected UDP sends are read by the relay socket. `close(2)`, closing
  `close_range(2)`, `dup2(2)`, and `dup3(2)` synchronize with relay creation so
  a concurrent descriptor change cannot cross the injection window. Closing
  calls also remove matching relays so long-running targets do not retain relay
  threads after closing UDP sockets.
- Each UDP relay has a bounded job queue. Blocking sends apply backpressure;
  nonblocking sends return `EAGAIN` when the queue is full.
- DNS redirection forwards UDP/53 payloads to `dns_server` using a reused
  DNS-over-TCP connection through the configured TCP proxy. Generic UDP uses
  SOCKS5 UDP ASSOCIATE and is unavailable for HTTP CONNECT proxies.
- Batched `sendmmsg(2)` / `recvmmsg(2)` calls are not rewritten in the current
  implementation.

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

Default routing is a fast transparent-proxy policy for trusted target
processes, not a security boundary. `SECCOMP_USER_NOTIF_FLAG_CONTINUE` resumes
the original syscall, so pointer arguments such as `sockaddr *` can be modified
by another target thread between supervisor inspection and kernel use. Strict
egress enforcement should be provided by the kernel network layer, such as a
dedicated netns with nftables rules or cgroup eBPF, allowing only intended
direct CIDRs and the configured proxy endpoint.

## Test Plan

- Unit tests cover BPF shape, proxy URL parsing, CIDR routing, HTTP CONNECT
  request generation, SOCKS5 UDP framing, sockaddr parsing, internal argv
  encoding, and bounded target-termination polling.
- Integration tests cover TCP CONNECT redirection, UDP/53 DNS-over-TCP
  redirection, and generic UDP over SOCKS5 UDP ASSOCIATE using local fake
  proxies. TCP integration also verifies stable socket identity, pre-connect
  epoll registration, explicit bind state, socket options, and an alias used
  after fork/exec. It also verifies that telemetry is complete and that active
  flows, queued registrations, actual pending bytes, and reserved pending-byte
  budget all return to zero at shutdown.
- Required local checks:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- The deterministic local TCP benchmark compares direct control, the fixed
  pre-stable `b5554b9` ADDFD binary, and the current stable broker. It covers
  short request/response flows, mostly-idle concurrency, and stalled readers;
  randomizes variant order after three warmups; repeats each measurement ten
  times; and archives raw samples, partial failure results, commands, binary
  hashes/commits/build commands, dirty-worktree artifacts, role-specific
  `VmHWM`/sampled fd peaks, and stable-broker diagnostics under `target/`.
  Stalled runs set the same small application send buffer for every variant,
  pause destination transport reads, require every flow to report `EAGAIN`,
  hold for the requested interval, then release and drain all bytes while the
  destination verifies the drained payload pattern, per-flow byte totals, and
  clean end of stream. Accepted connections capture their release event and
  result list before the handler task is scheduled. Because a connection can
  still remain in the shared listener backlog before acceptance, each run also
  records whether the stalled server reached quiescence; a timeout, missing
  handler, or incomplete EOF aborts the batch before another run can reuse the
  listener. A failed warmup, measurement, diagnostic, malformed metric line,
  incomplete flow set, or corrupted or short drain remains in the artifacts
  and fails the run gate.

```sh
cargo build --release --locked
uv run scripts/tcp_broker_benchmark.py \
  --yatht target/release/yatht \
  --yatht-build-command 'cargo build --release --locked' \
  --addfd-yatht ../yatht-pre-stable-b5554b9/target/release/yatht \
  --addfd-commit b5554b9 \
  --addfd-build-command 'cargo build --release --locked'
```

- Manual integration check on Linux x86_64/kernel >= 5.9:

```sh
cargo build
target/debug/yatht --proxy socks5://127.0.0.1:1080 -- curl https://api.ipify.org
target/debug/yatht --proxy socks5://127.0.0.1:1080 --enable-dns -- curl https://example.com
```

The reported IP should be the proxy egress IP. A connection to `127.0.0.1`
should bypass the proxy unless `--proxy-local` is set.

## Deferred Work

- Additional architectures such as aarch64.
- Optional compatibility fallback for kernels older than 5.9.
- Strict nonblocking connect completion, logical peer query virtualization, and
  general UDP socket semantics. These require the backend decisions in
  [SOCKET_SEMANTICS_ROADMAP.md](SOCKET_SEMANTICS_ROADMAP.md), not local syscall
  handlers alone.
