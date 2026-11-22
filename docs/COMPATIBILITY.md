# Compatibility, Semantics, and Limits

This reference documents the detailed socket semantics, resource limits, and
edge-case behavior of `yatht`. For an overview and quick start, see
[README.md](../README.md).

## TCP Redirection

TCP redirection targets conventional blocking clients. After the upstream proxy
handshake succeeds, the target's original `AF_INET`/`AF_INET6` socket is
connected to a per-flow loopback broker.

### Preserved semantics

- The target's open file description stays stable across `connect(2)`.
- Pre-existing `epoll` registrations, `dup(2)`/`fork(2)` aliases, explicit bind
  state, descriptor flags, and socket options remain attached.

### Known limitations

- **Split-connection model**: `yatht` does not emulate end-to-end remote socket
  state.
- **Nonblocking `connect(2)`**: Completed synchronously rather than returning
  `EINPROGRESS` while the proxy handshake runs.
- **Peer and transport inspection**: Untrapped kernel queries such as
  `getpeername(2)` and `TCP_INFO` describe the local broker leg rather than the
  requested remote peer.
- **Route-affecting options**: Options such as `SO_BINDTODEVICE` can prevent the
  target socket from reaching the loopback broker.

### Broker limits

| Resource | Limit / Behavior |
| --- | --- |
| Active flows | Up to 16,384 (automatically lowered if `RLIMIT_NOFILE` cannot preserve fd headroom) |
| Pending flow registrations | Up to 128 |
| Global logical pending bytes | 256 MiB |
| Global allocated payload capacity | 256 MiB (empty 16 KiB blocks are released immediately) |
| Exhaustion behavior | Fail-closed; failure reason recorded in metrics summary |

## Generic UDP Redirection (Experimental)

Generic UDP requires `--enable-udp` and a SOCKS5 proxy supporting UDP ASSOCIATE.

### Socket identity modes (`lazy` vs `stable`)

| Behavior | `lazy` (default) | `stable` (`--udp-socket-mode=stable`) |
| --- | --- | --- |
| Relay injection point | First proxied send/connect (or first `sendmmsg(2)` batch needing proxy routing) | At `socket(2)` time |
| Pre-existing `dup(2)`/`fork(2)` aliases | Not preserved; aliases created *after* replacement share the relay | Preserved across `dup(2)`, `fork(2)`, and close races (`SO_COOKIE` relay key) |
| `epoll` registrations | Registrations made before replacement stay on the original socket | Registrations refer to the injected endpoint from creation |
| Local port reservation | Preserves pre-replacement local address snapshot until a direct worker allocates a local socket (does not reserve the original port) | `bind(2)` reserves a real local UDP socket immediately (port 0 resolves to a kernel ephemeral port before `getsockname(2)` returns); sends/connects also reserve an automatic local port |
| `recvmmsg(2)` support | Not handled by receive supervisor | Handled by receive supervisor |

DNS-only relays also replace the original socket, leaving earlier `epoll`
registrations on that socket. Readiness on an injected endpoint reflects
its `AF_UNIX` socket. IP error queues and their `EPOLLERR` notifications are
unavailable.

Notes on port reservation in `stable` mode:

- Direct sends reuse the reserved local socket.
- Because sends and connects reserve an automatic local port before returning, a
  subsequent `bind(2)` fails with `EINVAL`.
- The reservation is made even for proxy-only traffic (where it does not carry
  outbound packets). A newly created socket with no bind/connect/send does not
  reserve a port.
- Local ports are released during relay cleanup after the last alias closes and
  workers exit, rather than synchronously inside `close(2)`.
- A proxy's external source address and port can still differ from the reported
  local address.

### Asynchronous I/O, queues, and backpressure

- **Decoupled send/receive**: Direct and SOCKS5 relay sends do not wait for
  responses; silent peers do not throttle subsequent datagrams. Once a transport
  exists, its receive path runs independently, supporting delayed, reordered,
  and multiple responses. Different direct/proxy peers have no shared response
  ordering guarantee.
- **Per-route queues**: Each relay has separate bounded 16-datagram input queues
  for direct, SOCKS5, and DNS traffic, each with its own pending send. A stalled
  established transport does not block sends on other routes, and queues apply
  backpressure independently (or return `EAGAIN` for nonblocking sends).
- **DNS queue sharing**: All DNS destinations share the relay's DNS route queue,
  and a thread blocked sending to a full queue must return before issuing its
  next call.
- **Delivery semantics**: Successful sends acknowledge queue admission, not
  remote delivery. Queue overflow, network errors, and closing/exiting before
  queued work is forwarded can still lose data.
- **Send syscalls**: Relays cover `sendto(2)`, `sendmsg(2)`, and `sendmmsg(2)`.
  `sendmmsg(2)` entries are rewritten in every mode, including the first
  proxied batch. Mixed direct/proxy batches retain per-entry routing and
  partial-error results. A batch that outpaces the relay
  worker reports only the enqueued entries as its sent count (so a large batch
  under `MSG_DONTWAIT` can partially commit). Empty `sendmmsg(2)` batches retain
  kernel descriptor validation (`EBADF`/`ENOTSOCK`).
- **Timeouts**: `--connect-timeout` bounds proxy setup and stalled writes, not
  the time allowed for a UDP reply. Initial proxy setup remains blocking and can
  delay both forwarding and worker retirement until its deadline.

### Payload size limits

- SOCKS5 sends via `sendto(2)`, `sendmsg(2)`, or `sendmmsg(2)` reject payloads
  above **65,497 bytes** (IPv4) or **65,485 bytes** (IPv6, including IPv4-mapped
  IPv6) with `EMSGSIZE`.
- These conservative ceilings reserve the 10/22-byte SOCKS5 header inside a
  65,507-byte outer UDP envelope before the association reveals the relay
  address, and also apply to IPv6 relay transports.
- Direct and DNS paths keep their native destination-family limits.
- Smaller path-MTU limits or other asynchronous send failures remain possible
  and are counted in `udp_dropped_jobs` when observed by the worker.

### Address families, naming, and disconnect semantics

- **Virtual identity**: Every relay mode virtualizes `getsockname(2)`,
  `getpeername(2)`, and `SOL_SOCKET` identity options (`SO_DOMAIN`, `SO_TYPE`,
  `SO_PROTOCOL`, `SO_ERROR`) for `AF_INET`/`AF_INET6` UDP sockets. Unbound
  sockets report their family's wildcard address with port 0. Virtualized
  integer options preserve Linux's short-buffer truncation and negative-length
  rejection rules.
- **Dual-stack handling**: Logical operations reject invalid destination ports
  and unsupported families before creating a relay. `AF_INET` sockets reject
  IPv6 destinations; relayed `AF_INET6` sockets model Linux's default dual-stack
  behavior (accepting IPv4 and IPv6) and retain that direct transport family
  across destination changes in stable, lazy, and DNS-only modes. Logical
  addresses are reported in the socket's own family (dual-stack peers and
  sources appear as IPv4-mapped IPv6 addresses). `IPV6_V6ONLY` is not yet
  virtualized.
- **Destination parsing**: Zero-length names fail `sendto(2)` and fall back to
  the connected peer in `sendmsg(2)`. An `AF_UNSPEC` name is treated as
  `AF_INET` on `AF_INET` sockets and as no name on `AF_INET6` sockets; other
  families fail with the socket's error. `bind(2)` remains strict-family,
  including Linux's IPv6 length checks and IPv4 `AF_UNSPEC` wildcard
  compatibility.
- **`AF_UNSPEC` disconnect**: Clears the peer and makes subsequent
  destination-free sends fail with `EDESTADDRREQ`. In `stable` mode, it also
  releases local ports not locked by an explicit nonzero bind while retaining
  any explicitly bound local IP (including after `bind(address, 0)`) for future
  port reservations. Port release completes before disconnect returns, even if
  the worker is blocked in proxy setup.

### Receive behavior and timeouts

- **Covered syscalls**: `recvfrom(2)`, `recvmsg(2)`, and (in `stable` mode)
  `recvmmsg(2)`.
- **Source addresses & flags**: Unconnected request/response traffic reports the
  numeric source from the SOCKS5 UDP response header or the direct worker's
  kernel peer. `MSG_PEEK`, `MSG_TRUNC`, `MSG_WAITFORONE`, partial completion,
  and mixed receive calls preserve payload/source queue order. Emulated receives
  report `msg_controllen = 0` when returning no ancillary data.
- **`SO_RCVTIMEO` handling**: Blocking relayed receives honor `SO_RCVTIMEO` from
  the injected endpoint (lazy replacement transfers a pre-existing
  `SO_RCVTIMEO`). A quiet `recvfrom(2)`/`recvmsg(2)` fails with `EAGAIN` at the
  deadline. `recvmmsg(2)` re-arms the socket timeout after each delivered entry
  and returns the completed count if it expires after progress.
- **Explicit `recvmmsg(2)` timeouts**: Successful batches write the remaining
  explicit interval back to the caller's timespec (a failed writeback returns
  `EFAULT` even after progress). Stable `recvmmsg(2)` uses an absolute reactor
  deadline and returns `0` with a zero remaining interval when an empty-queue
  explicit timeout expires (instead of Linux's documented timeout hang). When
  both `SO_RCVTIMEO` and an explicit timespec are armed, the earlier deadline
  keeps its own expiry result.
- **Not preserved / unsupported**: Ancillary data (`msg_control`), error queues,
  connected-peer receive filtering, other IP-level socket options, and SOCKS5
  replies with domain-name source addresses (dropped because no numeric source
  address can be reported reliably).

### Capacity and relay reclamation

- **Active relay cap**: Up to 128 active UDP relays. Exhausting this budget
  returns `ENOBUFS` from the creating call (`socket(2)` in stable mode, or the
  first proxied send/connect in lazy mode).
- **Worker teardown**: After setup completes, reaping wakes the I/O worker
  immediately without waiting for a silent peer. Dropping the last supervisor
  relay handle shuts down both workers automatically.
- **Background reaper**: A dedicated low-priority supervisor thread reclaims
  relays whose `AF_UNIX` inode no longer has an open target-side alias, keeping
  `/proc/net/unix` scans off the receive reactor. It sweeps every 1 s and, after
  5 consecutive empty sweeps, backs off up to 30 s; reclaiming or creating a
  relay resets the cadence. Capacity-bound admission also sweeps and retries
  briefly. Normal socket creation does not scan procfs, and an unavailable
  `/proc/net/unix` delays cleanup without breaking creation while capacity
  remains.

## DNS-over-TCP (`--enable-dns`)

- Redirects UDP/53 queries over TCP through either a SOCKS5 or HTTP CONNECT
  proxy to `--dns-server`. This route takes precedence over generic UDP
  redirection, the default local bypass, `--bypass-cidr`, and `--proxy-cidr`.
- Pipelines queries without waiting for earlier answers and retains partial TCP
  frames across readiness events.
- Keeps at most **16 streams per relay** (one per original DNS destination), so
  reordered replies preserve the correct source even when destinations reuse
  transaction IDs.
- Buffers at most **one outgoing and one incoming frame per stream**. Failed
  streams are discarded and later queries reconnect; in-flight queries are not
  replayed automatically.
- Healthy streams are not evicted. A long-lived relay that fills all 16 slots
  drops queries for new destinations and increments `udp_dropped_jobs` (logged
  under `--debug`) until a stream fails or the relay closes.

## Observability and Metrics (`--metrics-file`)

- Opt-in JSONL output; the target path must not already exist.
- Contains versioned run metadata (schema version 7), TCP broker limits, one
  setup record per proxied TCP connection (per-stage timings and proxy session
  source: cold, warm hit, or warm miss), and a final summary covering queue,
  flow, pending-byte, allocated-buffer, relay, syscall, CPU, warm-session-pool,
  and failure counters.
- `udp_dropped_jobs` counts accepted datagrams that workers fail to forward
  (setup/send errors, expired writes, DNS stream capacity, or an incomplete DNS
  frame lost with its stream), independently of `--debug`. It excludes
  synchronous syscall errors, missing replies, and jobs abandoned at process
  teardown; the summary is a snapshot because UDP workers are detached.
- Metric delivery uses a bounded queue; `dropped_metric_events` in the final
  summary reports any events discarded under pressure.

## Process Supervision and Security Model

- **Child subreaper**: The supervisor acts as a child subreaper and keeps the
  seccomp listener alive until all descendants of the initially launched process
  exit. Its final exit status is that of the initially launched process.
- **Trusted-process model**: Direct routes are continued in-kernel
  (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) for low overhead, which carries an
  inherent pointer-argument TOCTOU window. Do not treat CIDR routing in `yatht`
  as a security boundary for hostile code. For strict egress enforcement, run
  the target inside a network namespace, nftables ruleset, cgroup eBPF policy,
  or equivalent kernel network policy that only permits the configured direct
  CIDRs and proxy endpoint. See [SECURITY.md](../SECURITY.md).
