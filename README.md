![License](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![Ciphersuite](https://img.shields.io/badge/ciphersuite-MLS__128__DHKEMX25519__AES128GCM__SHA256__Ed25519-green)

# hush-crypto

Rust crate implementing the cryptographic core of [Hush](https://gethush.live). Wraps [OpenMLS](https://github.com/openmls/openmls) 0.8.1 (RFC 9420) and is compiled to WASM for use in the web client via wasm-pack. All encryption happens here — the server never sees plaintext.

---

## What hush-crypto does

| Operation | Description |
|-|-|
| Credential generation | Creates an Ed25519 `BasicCredential` for MLS group membership |
| KeyPackage creation | Builds one-time-use MLS KeyPackages for asynchronous group add |
| Group operations | Create group, add/remove members, commit, process incoming commits |
| Message encryption | `MlsGroup::create_message(plaintext)` → MLS Application Message ciphertext |
| Message decryption | `process_message(ciphertext)` → plaintext, epoch validated |
| `export_secret` | Derives AES-256-GCM keys for voice frame encryption and guild metadata encryption |
| Metadata encryption | AES-256-GCM encrypt/decrypt using keys derived from MLS `export_secret()` |

---

## Ciphersuite

`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

| Primitive | Algorithm | Specification |
|-|-|-|
| Key encapsulation | X25519 DHKEM | RFC 9420 §17.1 |
| Symmetric encryption | AES-128-GCM | RFC 9420 ciphersuite |
| Hash | SHA-256 | FIPS 180-4 |
| Signature | Ed25519 | RFC 8032 |

---

## Building

### Native (tests and development)

```bash
cargo build
```

### WASM (for web client)

Requires [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

```bash
# Install wasm-pack if needed
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build for web target (generates pkg/ directory)
wasm-pack build --target web
```

The build output in `pkg/` contains:
- `hush_crypto.js` — ES module JS bindings
- `hush_crypto_bg.wasm` — WASM binary
- `hush_crypto.d.ts` — TypeScript type definitions
- `package.json` — npm package metadata

The `hush-web` client imports the WASM package from `pkg/` (or from `@hushhq/hush-crypto` on GitHub Packages).

### Forcing a WASM rebuild

If you pull changes to this crate and the web client still imports a cached WASM:

```bash
# From hush-web client directory
npm run build:wasm:force
```

---

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run a specific test
cargo test group::tests::test_create_group

# Audit dependencies for known vulnerabilities
cargo audit
```

All tests run on the native target. WASM-specific behavior is tested in `hush-web` using Vitest with `@vitest/browser`.

---

## NPM Package

The compiled WASM package is published to GitHub Packages as `@hushhq/hush-crypto`.

**Consumers need npm auth for GitHub Packages.** Add to your `~/.npmrc`:

```
@hushhq:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_PAT
```

A PAT with `read:packages` scope is sufficient for consuming the package.

---

## API Overview

All public API is exposed via `wasm.rs` using `wasm-bindgen`. Key types and functions:

### Credential

```rust
// Generate a new Ed25519 BasicCredential
pub fn generate_credential(identity: &[u8]) -> Result<Credential, JsValue>
```

### KeyPackage

```rust
// Create a new one-time-use KeyPackage
pub fn create_key_package(credential: &Credential) -> Result<KeyPackageBundle, JsValue>
```

### MLS Group

```rust
// Create a new group
pub fn create_group(group_id: &[u8], credential: &Credential) -> Result<MlsGroup, JsValue>

// Add a member via their KeyPackage
pub fn add_member(group: &mut MlsGroup, key_package: &[u8]) -> Result<AddResult, JsValue>

// Remove a member
pub fn remove_member(group: &mut MlsGroup, member_index: u32) -> Result<CommitResult, JsValue>

// Encrypt a message
pub fn create_message(group: &mut MlsGroup, plaintext: &[u8]) -> Result<Vec<u8>, JsValue>

// Process an incoming commit, welcome, or application message
pub fn process_message(group: &mut MlsGroup, message: &[u8]) -> Result<ProcessedMessage, JsValue>

// Derive an epoch-scoped export secret (for voice frame keys, metadata keys)
pub fn export_secret(group: &MlsGroup, label: &str, length: usize) -> Result<Vec<u8>, JsValue>
```

### Metadata encryption

```rust
// AES-256-GCM encrypt using an MLS-derived key
pub fn encrypt_metadata(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue>

// AES-256-GCM decrypt
pub fn decrypt_metadata(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue>
```

---

## Source Structure

```
hush-crypto/
├── src/
│   ├── credential.rs    # Ed25519 BasicCredential generation
│   ├── key_package.rs   # MLS KeyPackage builder
│   ├── group.rs         # Group operations: create, add/remove, commit, export_secret
│   ├── metadata.rs      # AES-256-GCM metadata encryption (key from export_secret)
│   └── wasm.rs          # wasm-bindgen JS bindings
├── tests/               # Integration tests (native target)
├── Cargo.toml
└── Cargo.lock
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[AGPL-3.0](LICENSE). If you modify this crate and distribute it (including as part of a compiled application), you must publish your changes under the same license.
