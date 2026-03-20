//! Hush cryptographic foundation: MLS credential, KeyPackage generation,
//! and group lifecycle management.
//!
//! Builds as both a native rlib and a WASM cdylib (wasm-pack --target web).
//! Group state is persisted through the `StorageProvider` trait —
//! see `storage_bridge` for native (in-memory) and WASM (JS-callback) impls.

pub mod credential;
pub mod group;
pub mod key_package;
pub mod storage;
pub mod storage_bridge;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
