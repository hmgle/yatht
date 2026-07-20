# Changelog

## Unreleased

- Reject invalid and unsupported configuration combinations at startup.
- Prevent UDP relay injection from replacing non-socket descriptors.
- Keep proxy handshake timeouts out of target TCP connections.
- Terminate the target when seccomp notification handling fails fatally.
- Keep the notification listener alive for adopted target descendants.
- Bound UDP job queues while preserving blocking receive behavior.
- Clarify that generic UDP and complete Linux socket semantics remain
  experimental.

## 0.1.0

- Initial release of `yatht`.
- Transparent TCP `connect(2)` redirection through SOCKS5 or HTTP CONNECT.
- Optional UDP/53 DNS-over-TCP redirection.
- Optional generic UDP redirection through SOCKS5 UDP ASSOCIATE.
- CIDR-based direct/proxy routing controls.
