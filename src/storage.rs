//! In-memory StorageProvider wrapping Hush's hybrid OpenMLS provider.
//!
//! This provider is created per-call and discarded once key material has been
//! extracted.  There is no file I/O; all state lives in the heap and is dropped
//! with the provider value.

use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::provider::HybridCryptoProvider;

/// In-memory provider used by stateless credential and KeyPackage helpers.
pub struct HushProvider {
    crypto: HybridCryptoProvider,
    rand: RustCrypto,
    storage: MemoryStorage,
}

impl Default for HushProvider {
    fn default() -> Self {
        Self {
            crypto: HybridCryptoProvider::default(),
            rand: RustCrypto::default(),
            storage: MemoryStorage::default(),
        }
    }
}

impl OpenMlsProvider for HushProvider {
    type CryptoProvider = HybridCryptoProvider;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}

/// Returns a fresh, empty in-memory provider.
///
/// The returned value supports legacy Hush MLS groups plus the current X-Wing
/// ciphersuite for newly created groups.
pub fn new_provider() -> HushProvider {
    HushProvider::default()
}
