//! WASM bindings for the web client.
//!
//! Exports two functions via wasm-bindgen:
//!   - `generateCredential(identity: string)` → `{ signingPublicKey, signingPrivateKey, credentialBytes }`
//!   - `generateKeyPackage(signingPrivateKey, signingPublicKey, credentialBytes)` → `{ keyPackageBytes, privateKeyBytes, hashRefBytes }`
//!
//! Both functions return `JsValue` (JSON-compatible objects) via `serde_wasm_bindgen`.
//! All `Vec<u8>` fields arrive in JS as `Uint8Array`.

use wasm_bindgen::prelude::*;

use crate::credential;
use crate::key_package;

/// No-op initialization hook retained for backward compatibility with
/// `hushCrypto.js` callers that invoke `m.init()` after loading the WASM module.
#[wasm_bindgen]
pub fn init() {}

/// Generate an MLS credential and Ed25519 signing keypair.
///
/// # Arguments
///
/// - `identity`: opaque string identifying the client (e.g. `"user_id:device_id"`)
///
/// # Returns
///
/// A JS object `{ signingPublicKey: Uint8Array, signingPrivateKey: Uint8Array, credentialBytes: Uint8Array }`
///
/// # Errors
///
/// Returns a `JsValue` error string on failure.
#[wasm_bindgen(js_name = "generateCredential")]
pub fn wasm_generate_credential(identity: &str) -> Result<JsValue, JsValue> {
    credential::generate_credential(identity)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(|out| serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string())))
}

/// Generate an MLS KeyPackage from an existing credential.
///
/// # Arguments
///
/// - `signing_private_key`: 64-byte private key (seed || public) from `generateCredential`
/// - `signing_public_key`: 32-byte Ed25519 public key from `generateCredential`
/// - `credential_bytes`: TLS-serialized credential bytes from `generateCredential`
///
/// # Returns
///
/// A JS object `{ keyPackageBytes: Uint8Array, privateKeyBytes: Uint8Array, hashRefBytes: Uint8Array }`
///
/// # Errors
///
/// Returns a `JsValue` error string on failure.
#[wasm_bindgen(js_name = "generateKeyPackage")]
pub fn wasm_generate_key_package(
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    key_package::generate_key_package(signing_private_key, signing_public_key, credential_bytes)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(|out| serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string())))
}
