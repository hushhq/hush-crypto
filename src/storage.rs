//! In-memory StorageProvider wrapping `OpenMlsRustCrypto`.
//!
//! This provider is created per-call and discarded once key material has been
//! extracted.  There is no file I/O; all state lives in the heap and is dropped
//! with the provider value.

pub use openmls_rust_crypto::OpenMlsRustCrypto;

/// Returns a fresh, empty in-memory provider.
///
/// The returned value satisfies the `OpenMlsProvider` trait through the
/// blanket impl provided by `openmls_rust_crypto`.
pub fn new_provider() -> OpenMlsRustCrypto {
    OpenMlsRustCrypto::default()
}
