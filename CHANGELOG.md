# Changelog

## Unreleased

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
