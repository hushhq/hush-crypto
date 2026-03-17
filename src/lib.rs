//! Hush cryptographic foundation: MLS credential and KeyPackage generation.
//!
//! Builds as both a native rlib and a WASM cdylib (wasm-pack --target web).
//! The crate is stateless — it generates key material and returns bytes to
//! the caller.  Persistence is the caller's responsibility.

pub mod credential;
pub mod key_package;
pub mod storage;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
