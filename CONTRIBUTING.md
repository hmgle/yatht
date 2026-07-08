# Contributing

## Development Requirements

- Linux x86_64
- Linux kernel 5.9 or newer for runtime and integration tests
- Rust toolchain

## Checks

Run these before opening a pull request:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Notes

- Keep user-facing behavior documented in `README.md`.
- Keep design and implementation notes in `docs/DEVELOPMENT_PLAN.md`.
- Avoid relying on `yatht` as a security boundary for hostile target processes;
  use kernel network policy for strict egress enforcement.
