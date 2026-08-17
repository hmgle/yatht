# Socket Semantics Roadmap

## Decision

`yatht` keeps seccomp user notification as its low-prerequisite compatibility
backend, but it does not attempt to become a complete socket ABI virtual
machine. Compatibility work should preserve a kernel object whenever possible
and move interception to the network layer when strict timing is required.

The current TCP path therefore keeps the target's original AF_INET/AF_INET6
open file description. It completes the upstream proxy handshake separately,
connects that original socket to a short-lived loopback listener, and registers
the accepted socket plus proxy tunnel with one shared relay reactor.

Do not implement best-effort epoll migration for TCP. Stable identity makes it
unnecessary and avoids unrecoverable edge-triggered, one-shot, ready-list, and
shared-epoll state.

## Compatibility Tiers

| Backend | Stable application socket | Strict nonblocking connect | io_uring coverage | Main tradeoff |
| --- | --- | --- | --- | --- |
| seccomp broker | Yes for TCP | No | No policy coverage | Lightweight and synchronous |
| rootless TPROXY | Yes | No, local handshake completes early | Yes | Kernel TCP with split-connect timing |
| SYN-gated TPROXY | Yes | Intended | Yes | NFQUEUE control-plane complexity |
| yayatht TAP | Yes | Yes | Yes | Maintains a target-side TCP adapter |
| cgroup eBPF | Yes | No by itself | Yes | Requires host privilege/capability |

The scores implied by these tiers are workload-specific. No split-connection
backend can make remote RTT, congestion state, `TCP_INFO`, and proxy errors
identical to a direct end-to-end socket.

## Current TCP Contract

The seccomp broker guarantees the following for successfully proxied stream
connects:

- the target fd still references the same open file description after
  `connect(2)` returns;
- pre-existing `dup(2)` aliases and fork/exec inheritance remain usable;
- pre-existing epoll registrations keep monitoring the same object;
- target-side bind state, descriptor flags, signal ownership, and socket
  options are not reconstructed or copied because they were never replaced;
- the relay has bounded 64 KiB queues per direction, propagates FIN after
  queued bytes drain, and isolates ordinary errors to one flow.

The current contract deliberately does not claim:

- asynchronous `EINPROGRESS` followed by proxy-handshake completion;
- the requested destination from an untrapped `getpeername(2)` call;
- remote transport values from `TCP_INFO`, congestion-control options, or
  route-dependent IP options;
- compatibility when target routing marks or device binding prohibit a
  loopback connection;
- transparent TCP Fast Open data in the SYN.

## Milestone 1: Harden the Stable TCP Broker

Required work:

1. Add concurrent short-flow, slow-consumer, reset-with-buffered-data, IPv6,
   HTTP CONNECT, and notification-interruption integration tests.
2. Export active-flow, peak-buffer, queue-full, half-close, and reset metrics.
3. Benchmark the broker against a direct control with a local fake proxy.
   Report external-proxy measurements separately with enough environment
   metadata to reproduce them.
4. Prototype `splice(2)` pipes only after the buffered reactor remains the
   correctness oracle. Keep a per-round work budget so one hot flow cannot
   starve registrations or quiet flows. Status: delivered as the opt-in
   experimental `SUP_TCP_DATA_MOVER=splice` mover; buffered stays the default.
5. Record target and physical `SO_COOKIE` values for diagnostics. Do not put
   `kcmp(2)` on the normal data path; use `KCMP_FILE`/`KCMP_EPOLL_TFD` only for
   tests and exceptional reconciliation.

Exit criteria: no OFD, alias, epoll, bind, option, half-close, or flow-isolation
regressions in the integration matrix, and bounded memory under a stalled peer.

## Milestone 2: Stable UDP Creation

UDP now has an opt-in virtual-socket mode when generic UDP interception is
enabled. The mode is selected with `SUP_UDP_SOCKET_MODE=stable`; unset or
`lazy` keeps the existing first-send replacement path.

1. [x] Trap `socket(AF_INET/AF_INET6, SOCK_DGRAM, ...)` and inject the relay
   endpoint as the syscall result with `SECCOMP_ADDFD_FLAG_SEND`.
2. [x] Feature-detect `SECCOMP_ADDFD_FLAG_SEND`; it requires Linux 5.14 and is
   available on the current Linux 6.9 baseline. Unsupported kernels fall back
   to the lazy path after the first failed atomic addfd attempt.
3. [x] Key relay state by the injected socket's `SO_COOKIE`, with `(tgid, fd)`
   only as a lookup cache. This naturally follows dup and fork aliases. Stable
   admission reclaims closed relays by confirming that their AF_UNIX inode has
   disappeared from `/proc/net/unix`, which happens only after the final target
   alias closes.
4. [x] Relay direct and proxied destinations through the same stable endpoint
   once virtualized; destination-based bypass is decided per datagram.
5. [x] Stable mode rewrites `sendmmsg(2)` and virtualizes `getsockname(2)`,
   `getpeername(2)`, and the common `SOL_SOCKET` identity options for the
   logical AF_INET/AF_INET6 UDP socket. Logical operations preserve native
   address-family errors, disconnected sends, `AF_UNSPEC` disconnects, and
   short `getsockopt(2)` buffer truncation.
6. [x] Preserve numeric response sources for unconnected `recvfrom(2)` and
   `recvmsg(2)`. SOCKS5 replies use the UDP response header and direct replies
   use the kernel peer. A direct-kernel probe covers changed-source responses,
   `MSG_PEEK`, payload truncation, and `MSG_TRUNC` before running the same
   assertions through stable relays.
7. [x] Trap stable `recvmmsg(2)` and preserve per-entry payload length, flags,
   and numeric source while atomically advancing the response-source queue.
   Direct-kernel and stable probes cover `MSG_PEEK`, `MSG_TRUNC`,
   `MSG_WAITFORONE`, nonblocking calls, invalid target memory, partial
   completion, and mixing batches with later `recvfrom(2)`/`recvmsg(2)` calls.
   Blocking batches retain progress in the receive reactor and use an absolute
   deadline; an empty queue returns zero at expiry instead of preserving the
   documented Linux timeout bug. Successful progress writes the remaining
   interval back to the caller's explicit timeout, while the deliberate
   empty-queue expiry writes zero.
8. [x] Honor `SO_RCVTIMEO` for blocking relayed receives. The supervisor
   samples the timeout from its duplicate of the injected endpoint, expires a
   quiet `recvfrom(2)`/`recvmsg(2)` with `EAGAIN`, bounds each `recvmmsg(2)`
   inter-datagram gap with per-entry re-arming, and lets the earlier of the
   socket timeout and an explicit timespec keep its own expiry result. A
   direct-kernel probe anchors the semantics and runs unchanged against stable
   direct and stable SOCKS5 relays; lazy coverage verifies option transfer
   across replacement as well as a timeout set after replacement.
9. [~] SOCKS5 domain-name response sources, `msg_control` data, ancillary data,
   unsolicited datagrams, error queues, and multi-response ordering remain open
   compatibility work. These need explicit support or an unsupported policy;
   the batch source-queue consistency issue is closed.

AF_UNIX cannot receive arbitrary IP error-queue entries or generate matching
`EPOLLERR` state. `IP_RECVERR`, `MSG_ERRQUEUE`, packet-info control messages,
and other untrapped IP-level options remain explicit limitations. The
descriptor-identity and basic logical-query slices are delivered, but the full
milestone remains open until the remaining IP-level semantics have explicit
tests and a documented policy.

## Milestone 3: Rootless Network Backends

The conventional middle backend is a target network namespace with nftables
TPROXY and a transparent TCP/UDP broker. A helper that remains in the initial
network namespace creates direct or proxy sockets and passes them over a
pre-created Unix socketpair with `SCM_RIGHTS`. The socket retains the network
namespace in which it was created.

For strict TCP connect timing without a user-space TCP implementation, evaluate
a SYN-gated variant:

1. Route target traffic through a gateway network namespace owned by the same
   user namespace.
2. Queue only initial SYN packets with NFQUEUE before TPROXY.
3. Start and complete the host-side proxy handshake while the SYN is held.
4. On success, release and mark the SYN for TPROXY; on failure, route it to an
   nftables TCP reset/reject verdict.
5. Match the accepted transparent socket to the ready tunnel by its original
   four-tuple, then use the normal relay data plane.

The proof of concept must bound queued SYNs, coalesce retransmissions, cancel on
target close, handle helper failure, and explicitly reject or support TCP Fast
Open. If those invariants are not demonstrably simpler than the TAP adapter,
retain ordinary TPROXY as a common-semantics backend instead.

## Milestone 4: Strict Backend Boundary

`yayatht` is the existing strict rootless backend. It gives the application a
real kernel socket and delays the target-side SYN-ACK until direct connect or
proxy negotiation succeeds. It also contains UDP tuple tracking and ICMP error
synthesis that a seccomp AF_UNIX endpoint cannot reproduce naturally.

Do not duplicate that packet/TCP state machine inside the seccomp backend.
Keep the projects as separate implementation tiers or share only narrowly
defined configuration and proxy-protocol components after checking their MIT
and GPL-3.0-only licensing boundary.

## Verification Matrix

Every backend claim should be tested against direct Linux behavior for:

- blocking and nonblocking connect success, refusal, timeout, and interruption;
- epoll LT, ET, one-shot, pre-connect registration, and concurrent waiters;
- dup, fork/exec, descriptor reuse, close races, and SCM_RIGHTS where supported;
- bind, getsockname, getpeername, descriptor flags, common socket options,
  shutdown, FIN, RST, sendfile, and splice;
- connected and unconnected UDP, multiple peers, multiple replies, mmsg,
  ancillary data, truncation, peek, asynchronous errors, and PMTU;
- ordinary syscalls and io_uring under both direct and strict-egress modes.

Tests using the real configured proxy must record host TUN behavior separately
from local fake-proxy results. The network namespace backend, not seccomp
`CONTINUE`, is the security boundary for strict egress.
