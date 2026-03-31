# Contributing to hush-crypto

Thank you for your interest in contributing to the hush-crypto crate. This guide covers the development setup, testing, code style, and pull request process.

---

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain (latest stable recommended)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (for WASM builds)
- [cargo-audit](https://crates.io/crates/cargo-audit) (recommended: `cargo install cargo-audit`)

Install prerequisites:

```bash
# Rust stable
rustup update stable

# wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# cargo-audit (optional but recommended)
cargo install cargo-audit
```

---

## Development Setup

```bash
git clone https://github.com/hushhq/hush-crypto
cd hush-crypto
cargo build
```

---

## Running Tests

```bash
# Run all tests
cargo test

# Run with visible output
cargo test -- --nocapture

# Run a specific test module
cargo test group::tests

# Run a specific test
cargo test group::tests::test_create_and_encrypt_message

# Check for dependency vulnerabilities
cargo audit
```

All tests must pass before submitting a pull request. Run `cargo audit` to confirm no known CVEs in the dependency tree.

---

## Building WASM

To verify a change compiles correctly to WASM (required if you modify `wasm.rs` or any public-facing API):

```bash
wasm-pack build --target web
```

The build output appears in `pkg/`. Confirm the TypeScript definitions (`hush_crypto.d.ts`) reflect your API changes correctly.

---

## Code Style

This project follows Rust standard conventions plus the guidelines in the root `CLAUDE.md`:

- **Function length:** Keep functions focused. If a function exceeds ~30 lines, extract helpers.
- **Error handling:** Use `Result<T, JsValue>` for all public WASM-exposed functions. Return meaningful error messages - they surface as JavaScript exceptions in the client.
- **No panics in WASM paths:** A panic in WASM terminates the browser process without a useful error. Use `?` and `map_err` instead of `unwrap()` in any code that runs in the browser.
- **Safety comments:** Document any `unsafe` block with a clear justification.
- **No secrets in code:** Private keys, seeds, and test vectors containing real entropy must not appear in committed files.

Run clippy before committing:

```bash
cargo clippy -- -D warnings
cargo fmt
```

---

## Pull Request Process

1. **Open an issue first** for non-trivial changes to discuss the approach before writing code.
2. **Branch from `main`:** `git checkout -b feature/my-feature` or `fix/my-fix`.
3. **Write tests** for new functionality. Include both happy path and error cases.
4. **Run `cargo test`, `cargo clippy`, and `cargo fmt`** - all must pass cleanly.
5. **Build WASM** and confirm `wasm-pack build --target web` succeeds.
6. **Open a pull request** against `main` with a description of what changed and why.

### Commit message format

```
type(scope): short description

- change detail 1
- change detail 2
```

Types: `feat`, `fix`, `test`, `refactor`, `chore`, `docs`.

---

## Cryptographic Changes

Changes that affect the ciphersuite, key derivation, or MLS group state semantics require extra scrutiny:

- Include a reference to the relevant RFC 9420 section in the PR description.
- Explain why the change is safe (forward secrecy, post-compromise security, transcript hash integrity).
- Add or update tests that exercise the affected path end-to-end.

When in doubt, open an issue before coding to get feedback on the approach.

---

## Security Issues

Do not open public issues for security vulnerabilities. Email `security@gethush.live` with details. See the main security policy for the full responsible disclosure process.
