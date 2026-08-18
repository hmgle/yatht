# Changelog

## Unreleased

- Sweep closed stable UDP relays on a dedicated low-priority thread instead of
  the blocking-receive reactor, so the host-wide `/proc/net/unix` read no
  longer delays ready receives or armed `SO_RCVTIMEO`/`recvmmsg` deadlines.
  Sweeps that reclaim nothing back off from one second to at most 30.
- Select the UDP socket identity model with `--udp-socket-mode=lazy|stable` or
  the `udp_socket_mode` configuration key, and reject `stable` without
  `--enable-udp` at startup. `SUP_UDP_SOCKET_MODE` remains a deprecated,
  lowest-precedence alias for one release and now prints a notice.

## 0.4.0

- Add an opt-in stable UDP socket mode (`SUP_UDP_SOCKET_MODE=stable` with
  `--enable-udp`) that injects the relay endpoint at `socket(2)` time, so the
  open file description survives `dup(2)`, `fork(2)`, and close races. The
  default lazy first-send replacement path is unchanged.
- Key stable relay state by `SO_COOKIE` and reclaim idle relays through a
  low-frequency sweep that confirms the target socket is gone; capacity-bound
  admission sweeps and retries instead of failing early.
- Virtualize `bind(2)`, `getsockname(2)`, `getpeername(2)`, and the
  `SOL_SOCKET` identity options for stable UDP sockets, preserving Linux
  destination and bind family rules, `AF_UNSPEC` connect and name handling,
  invalid port errors, and short or negative `getsockopt(2)` lengths.
- Model Linux default dual-stack behavior for stable IPv6 UDP sockets and
  report logical addresses in the socket's own family, so dual-stack peers and
  response sources appear as v4-mapped addresses.
- Rewrite `sendmmsg(2)` destinations and serve `recvmmsg(2)` through the
  receive supervisor, preserving per-entry length, flags, source, `MSG_PEEK`,
  `MSG_TRUNC`, `MSG_WAITFORONE`, partial completion, and remaining-timeout
  writeback.
- Preserve numeric UDP response sources from the SOCKS5 UDP response header or
  the direct worker's kernel peer for `recvfrom(2)`, `recvmsg(2)`, and each
  `recvmmsg(2)` entry.
- Honor `SO_RCVTIMEO` for blocking relayed receives, including per-entry
  re-arming across `recvmmsg(2)` batches and transfer of a pre-existing timeout
  across lazy replacement.
- Keep UDP-Lite sockets in the kernel instead of emulating their sends and
  connects.
- Match Linux validation for UDP destination name lengths, zero-length names,
  and oversized receive iovec segments.

## 0.3.0

- Require Linux 6.9 or newer so notification threads always support reliable
  descriptor inspection through thread-scoped pidfds.
- Apply one absolute timeout across proxy resolution, connection attempts, and
  handshakes.
- Route IPv4-mapped IPv6 destinations through both IPv6 and IPv4 policy rules.
- Decode and validate percent-encoded SOCKS5 credentials during startup.
- Bound UDP relay workers, queues, and payload memory.
- Cache thread-scoped pidfds to avoid repeated descriptor-inspection setup.

## 0.2.0

- Reject invalid and unsupported configuration combinations at startup.
- Serialize UDP relay injection with trapped descriptor replacement.
- Keep proxy handshake timeouts out of target TCP connections.
- Terminate the target when seccomp notification handling fails fatally.
- Keep the notification listener alive for adopted target descendants.
- Bound UDP job queues while preserving blocking receive behavior.
- Complete ready UDP receives in parallel without letting quiet sockets occupy
  notification workers.
- Clarify that generic UDP and complete Linux socket semantics remain
  experimental.

## 0.1.0

- Initial release of `yatht`.
- Transparent TCP `connect(2)` redirection through SOCKS5 or HTTP CONNECT.
- Optional UDP/53 DNS-over-TCP redirection.
- Optional generic UDP redirection through SOCKS5 UDP ASSOCIATE.
- CIDR-based direct/proxy routing controls.
