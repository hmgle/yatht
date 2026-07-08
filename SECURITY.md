# Security Policy

## Supported Versions

Security fixes are handled on the current `main` branch before a stable release
policy exists.

## Reporting a Vulnerability

If GitHub Security Advisories are enabled for the repository, please use a
private advisory. Otherwise, open a public issue with a minimal description and
ask for a private contact path before sharing exploit details.

## Security Model

`yatht` is designed for trusted-process transparent proxying. It uses seccomp
user notification and may continue direct routes in-kernel for performance.
That `CONTINUE` path has a pointer-argument TOCTOU window and must not be used
as the only security boundary for hostile target code.

For strict egress enforcement, combine `yatht` with kernel network controls
such as a dedicated network namespace, nftables rules, cgroup eBPF policy, or
an equivalent policy that only allows the configured direct CIDRs and proxy
endpoint.
