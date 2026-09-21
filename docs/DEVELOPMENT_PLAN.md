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
6.9 or newer. The key kernel features are `SECCOMP_RET_USER_NOTIF`,
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, `SECCOMP_IOCTL_NOTIF_ADDFD`, and
`PIDFD_THREAD`. Startup fails before launching the target when thread-scoped
pidfds are unavailable.

## Public Interface

```text
yatht [OPTIONS] -- <command> [args...]

Options:
  --config <path>                 TOML configuration file
  --proxy <url>                   socks5://[user:pass@]host:port or http://host:port
  --bypass-cidr <CIDR>            CIDR that bypasses the proxy; repeatable
  --proxy-cidr <CIDR>             CIDR allow-list for proxying; repeatable
  --proxy-local                   Proxy local/private destinations too
  --connect-timeout <duration>    Absolute proxy setup deadline, default 10s
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
  generic UDP redirection is enabled. These modes also trap `sendmmsg(2)`,
  `getsockname(2)`, `getpeername(2)`, and `getsockopt(2)`; query emulation applies
  only to relays and selected identity options. Opt-in stable UDP mode also
  traps `socket(2)`, `bind(2)`, and `recvmmsg(2)`; other syscalls are allowed.
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
- Thread-scoped pidfds are cached by notification TID in a bounded 256-entry
  cache and refreshed on thread exit or TID reuse. Repeated fd inspections
  avoid a separate `pidfd_open(2)` syscall while preserving each required
  `pidfd_getfd(2)` identity check.
- Proxied routes duplicate the target TCP fd with `pidfd_getfd(2)`, complete the
  SOCKS5/HTTP CONNECT handshake on a separate upstream socket, then connect the
  original target open file description to a per-flow loopback listener. A
  shared bounded-buffer reactor relays the accepted local socket to the proxy
  tunnel before the supervisor responds with `connect() = 0`.
- Keeping the target TCP open file description avoids fd replacement races and
  natively preserves epoll registrations, descriptor aliases, bind state, and
  options on the target-side TCP leg. The reactor propagates half-closes and
  isolates ordinary flow errors without dedicating a thread to each flow.
- The broker reactor runs on epoll by default; `SUP_TCP_REACTOR=poll` is the
  explicit rollback path. Relay bytes travel through buffered user-space
  copies by default; `SUP_TCP_DATA_MOVER=splice` opts into an experimental
  kernel-pipe mover with a per-round budget, and `SUP_TCP_SPLICE_QUICKACK`
  (default `on`) flushes the pending delayed ACK after small drained splice
  rounds to avoid a delayed-ACK/Nagle interlock.
- Proxy sessions dial cold per flow by default.
  `SUP_TCP_PROXY_SESSION=warm-one-shot` opts into an experimental
  demand-driven pool of at most 16 pre-established proxy sessions with a 30 s
  idle timeout; each warm session serves one flow and misses fall back to
  cold dials.
- Proxy endpoint DNS is resolved once during configuration loading under the
  configured timeout and reused by cold and warm paths. Each flow has one
  absolute setup deadline across all candidate-address connection attempts,
  proxy protocol reads/writes, warm completion, and any safe cold fallback.
- Before proxy setup, the broker reserves an active-flow permit. The default
  ceiling is 16,384 flows and is reduced from `RLIMIT_NOFILE` after preserving
  the larger of 20% or 256 fds, plus setup-worker headroom. Registration has a
  fixed capacity of 128, and buffered relay data shares a 256 MiB global
  pending-byte budget. Rejections are fail-closed and separately classified.
- Optional JSONL telemetry (schema version 6) uses a bounded writer queue and
  records versioned run metadata, detected broker limits, per-flow setup spans
  with stage timings, proxy session outcomes, and socket cookies, and a final
  resource/data/error summary including warm session pool counters. The
  destination path must not exist, so separate runs cannot silently overwrite
  one another.
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
  target and runs a supervisor relay on the other end. Lazy mode performs this
  replacement on the first proxied send. Stable mode (`SUP_UDP_SOCKET_MODE=stable`)
  traps UDP socket creation and uses `SECCOMP_ADDFD_FLAG_SEND` so the target sees
  the injected fd as the `socket(2)` result; `bind(2)` is emulated for the
  logical endpoint by retaining a bound kernel UDP socket. This reserves a
  port immediately, including ephemeral bind(0), and reports kernel bind errors
  synchronously. Direct workers clone that socket to preserve its source port.
  Port release follows relay reclamation and completion of any in-flight job.
  Stable connect/send paths reserve an automatic port synchronously, preventing
  bind-after-send races with the writer. Disconnect clears automatic and
  bind(0) reservations; nonzero explicit ports remain locked. Direct socket
  caching checks the reservation's cookie to follow disconnect/rebind changes.
  `getsockname(2)` and `getpeername(2)` return the logical local/connected
  destination, while `getsockopt(2)` reports the AF_INET/AF_INET6 UDP domain,
  type, protocol, and a zero socket error.
  Queries apply to lazy and DNS relays too. Lazy creation snapshots the
  original local address and connected peer before replacement; a direct
  worker's allocated socket supersedes the local snapshot. The snapshot
  alone does not retain the original kernel bind or preserve its source port.
  All relay state is keyed by the injected endpoint's `SO_COOKIE`, with
  `(tgid, fd)` as a fast alias cache, so dup/fork aliases can recover after a
  descriptor-number change, including aliases created after lazy replacement.
  Removing an alias cache entry never shuts down its relay. A dedicated
  low-frequency reaper in both DNS and generic UDP modes checks AF_UNIX
  inodes in `/proc/net/unix` and reclaims a relay only after its last target-side
  open file description has disappeared. Capacity-bound admission sweeps and
  retries briefly; normal socket creation avoids procfs, and read failures
  defer cleanup instead of failing creation while capacity remains.
  Explicit `sendto(2)`/`sendmsg(2)`
  destinations are forwarded by the notification handler; connected UDP sends
  are read by the relay socket. Destination names are resolved against the
  target socket's own address family: a zero-length name fails `sendto(2)` and
  falls back to the connected peer in `sendmsg(2)`, an `AF_UNSPEC` name is an
  AF_INET address on AF_INET sockets and no name at all on AF_INET6 ones, and
  other families take that socket's error. Ports and family compatibility are
  checked once the family is settled, so a peer recorded by `connect(2)` keeps
  whatever that call accepted. AF_INET6 sockets model the default dual-stack
  policy for destinations and report logical addresses in their own family,
  while bind stays strict-family and preserves native
  length errors. `IPV6_V6ONLY` remains unvirtualized. Disconnected sends fail,
  and `AF_UNSPEC` disconnect is emulated without altering the AF_UNIX transport.
  A send whose name the kernel drops is relayed by the supervisor rather than
  continued, so the AF_UNIX endpoint never sees an address it would reject.
  `close(2)`,
  closing `close_range(2)`, `dup2(2)`, and `dup3(2)` synchronize with relay
  creation so a concurrent descriptor change cannot cross the injection window.
- UDP relay admission is globally capped at 128. Each relay uses two fallible
  workers with explicit 512 KiB stacks and a bounded 16-job queue. Blocking
  sends apply backpressure; nonblocking sends return `EAGAIN` when the queue is
  full, and relay setup fails closed when the global limit is reached.
- DNS redirection forwards UDP/53 payloads to `dns_server` using a reused
  DNS-over-TCP connection through the configured TCP proxy. Generic UDP uses
  SOCKS5 UDP ASSOCIATE and is unavailable for HTTP CONNECT proxies.
- All UDP modes rewrite explicit destinations in `sendmmsg(2)` and write each
  successful message length back, including a lazy/DNS socket's first batch.
  A read-only routing scan decides whether the batch needs a relay before any
  entry is sent; mixed batches then resolve names against the known UDP domain
  and preserve partial completion without continuing a proxied prefix.
  Regression probes verify direct prefixes (named or using a connected peer),
  proxied entries, and a final invalid name in the same first batch.
  Stable `recvmmsg(2)` runs
  through the receive reactor, retains partial batch progress across readiness
  waits, and writes each entry's payload length, flags, and numeric source.
  `recvfrom(2)`, `recvmsg(2)`, and `recvmmsg(2)` atomically pair responses with
  the SOCKS5 UDP header source or the direct worker's kernel peer across
  `MSG_PEEK`, `MSG_TRUNC`, `MSG_WAITFORONE`, and mixed receive calls. Sources
  and peers are rendered in the socket's own family, so a dual-stack AF_INET6
  socket sees v4-mapped IPv4 addresses. Empty-queue
  batch timeouts use an absolute reactor deadline rather than reproducing the
  documented Linux timeout hang. Blocking receives sample `SO_RCVTIMEO` from
  the supervisor's duplicate of the injected endpoint (one open file
  description, so stable dup/fork aliases and the lazy replacement endpoint
  share the transferred option): a quiet `recvfrom(2)`/`recvmsg(2)` fails with
  `EAGAIN` at the syscall-relative deadline, and
  `recvmmsg(2)` bounds each inter-datagram gap, re-arms after every delivered
  entry, and returns the completed count when the timeout expires with
  progress. Successful batch progress writes the remaining explicit timeout
  back to the target timespec, and a failed writeback overrides progress with
  `EFAULT`; the earlier of the socket timeout and the
  explicit timespec keeps its own expiry result. SOCKS5 domain-name response
  sources, error queues, and ancillary/control data remain deferred.
  Emulated recvmsg/recvmmsg results clear msg_controllen because no control
  messages are returned; caller capacity must not masquerade as output data.

## Routing Rules

The first matching rule wins:

1. Non-IPv4/IPv6 socket families are continued directly.
2. Local/private/link-local/multicast/unspecified addresses bypass by default.
   IPv4-mapped IPv6 destinations are also classified by their mapped IPv4
   address and can match IPv4 CIDR rules.
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

- The deterministic local TCP benchmark compares direct control with the
  current stable broker. It covers
  short request/response flows, mostly-idle concurrency, streaming and
  slow-consumer transfers, hot/quiet fairness, mid-stream resets, stalled
  readers, and optional long-lived soak runs; randomizes variant order after
  three warmups; repeats each measurement ten times; and archives raw samples,
  partial failure results, commands, the binary hash/commit/build command,
  dirty-worktree artifacts, role-specific `VmHWM`/sampled fd peaks, and
  stable-broker diagnostics under `bench-results/tcp-broker/`. Paired
  same-repetition comparisons of the experimental data paths run through
  `--stable-data-movers` and `--proxy-session-sources`, with `--proxy-rtt-ms`
  RTT injection and `--splice-readiness-gate` / `--warm-readiness-gate`
  acceptance checks. The harness ships its own dependency-free test suite,
  `python3 -X dev scripts/test_tcp_broker_benchmark.py`.
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
  --yatht-build-command 'cargo build --release --locked'
```

- Manual integration check on Linux x86_64/kernel >= 6.9:

```sh
cargo build
target/debug/yatht --proxy socks5://127.0.0.1:1080 -- curl https://api.ipify.org
target/debug/yatht --proxy socks5://127.0.0.1:1080 --enable-dns -- curl https://example.com
```

The reported IP should be the proxy egress IP. A connection to `127.0.0.1`
should bypass the proxy unless `--proxy-local` is set.

## Deferred Work

- Additional architectures such as aarch64.
- Optional compatibility backend for kernels older than 6.9, if a current use
  case justifies the additional fd-table semantics and maintenance cost.
- Strict nonblocking connect completion, logical peer query virtualization, and
  general UDP socket semantics. These require the backend decisions in
  [SOCKET_SEMANTICS_ROADMAP.md](SOCKET_SEMANTICS_ROADMAP.md), not local syscall
  handlers alone.
