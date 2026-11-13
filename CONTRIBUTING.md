# Contributing to `silvia-art-cms-auth`

Thank you for contributing! This repository implements the OAuth 2.0 backend for Sveltia CMS in Rust targeting Cloudflare Workers (`wasm32-unknown-unknown`).

## Prerequisites

- Rust stable toolchain (`rustup`)
- `wasm32-unknown-unknown` target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- Optional for local Worker bundling:
  ```bash
  cargo install worker-build
  ```

## Development Checks

Run all checks before opening a pull request (each maps to a dedicated GitHub Actions workflow):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --target wasm32-unknown-unknown
```

## Code Guidelines

- Keep pure OAuth helper functions (URL building, cookie extraction, constant-time state verification, HTML escaping) isolated in `src/oauth.rs` so they remain testable with `cargo test`.
- Never log or return `GITHUB_CLIENT_SECRET` or user access tokens in error responses.
- Keep `escape_json_for_inline_script` coverage intact to prevent XSS inside the callback HTML page.
