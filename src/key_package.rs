//! MLS KeyPackage generation with extractable HPKE private key.
//!
//! A KeyPackage is a pre-key bundle analogous to Signal's PreKeyBundle.
//! It contains the client's HPKE encryption key, credential, capabilities,
//! and a signature over the whole structure.
//!
//! Key packages are single-use: once consumed by a group add operation, the
//! private key is deleted from storage.

use openmls::prelude::*;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls_basic_credential::SignatureKeyPair;
use serde::Serialize;

use crate::credential::CIPHERSUITE;
use crate::storage::new_provider;

/// Output of a successful KeyPackage generation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageOutput {
    /// TLS-serialized `KeyPackage` bytes (public, safe to transmit).
    pub key_package_bytes: Vec<u8>,
    /// Raw HPKE init private key bytes (must be stored locally, never transmitted).
    pub private_key_bytes: Vec<u8>,
    /// Raw `HashReference` bytes that identify this KeyPackage in storage.
    pub hash_ref_bytes: Vec<u8>,
}

/// Generates a fresh MLS `KeyPackage` from an existing credential.
///
/// The caller provides the signing keypair bytes (from [`generate_credential`])
/// and the TLS-serialized credential.  A new HPKE init key is generated
/// internally by OpenMLS during `build()`.
///
/// # Arguments
///
/// - `signing_private_key`: 64-byte representation (32-byte seed || 32-byte public).
///   Only the first 32 bytes (seed) are passed to `SignatureKeyPair::from_raw`.
/// - `signing_public_key`: 32-byte Ed25519 public key.
/// - `credential_bytes`: TLS-serialized `Credential` from [`generate_credential`].
///
/// # Returns
///
/// A [`KeyPackageOutput`] containing:
/// - `key_package_bytes`: the public KeyPackage (TLS-serialized) for upload
/// - `private_key_bytes`: the HPKE init private key for local storage
/// - `hash_ref_bytes`: raw `HashReference` bytes for later look-up / deletion
///
/// # Errors
///
/// Returns a `String` error description on any failure.
pub fn generate_key_package(
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<KeyPackageOutput, String> {
    let provider = new_provider();

    // Reconstruct the credential from TLS bytes.
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let credential = {
        let mut slice = credential_bytes;
        Credential::tls_deserialize(&mut slice)
            .map_err(|e| format!("Credential TLS deserialize failed: {e}"))?
    };

    // signing_private_key is 64 bytes (seed || public).  OpenMLS only needs the
    // 32-byte seed portion.
    let seed = if signing_private_key.len() >= 32 {
        signing_private_key[..32].to_vec()
    } else {
        signing_private_key.to_vec()
    };

    // Reconstruct the SignatureKeyPair from raw bytes.
    let signature_keys = SignatureKeyPair::from_raw(
        CIPHERSUITE.into(),
        seed,
        signing_public_key.to_vec(),
    );

    // Persist the signature keys in this provider so OpenMLS can verify
    // self-signatures during build().
    signature_keys
        .store(provider.storage())
        .map_err(|e| format!("signature_keys.store failed: {e}"))?;

    let credential_with_key = CredentialWithKey {
        credential,
        signature_key: signing_public_key.to_vec().into(),
    };

    // Build the KeyPackage.  OpenMLS generates a fresh HPKE init key and
    // stores the KeyPackageBundle (public + private) into the provider's
    // storage during this call.
    let bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &provider, &signature_keys, credential_with_key)
        .map_err(|e| format!("KeyPackage::builder().build() failed: {e}"))?;

    // Compute the HashReference that identifies this bundle.
    let hash_ref = bundle
        .key_package()
        .hash_ref(provider.crypto())
        .map_err(|e| format!("hash_ref() failed: {e}"))?;

    // Extract the HPKE init private key from the bundle.
    // CRITICAL: access BEFORE dropping the bundle/provider.
    let private_key_bytes = bundle.init_private_key().to_vec();

    // TLS-serialize the public KeyPackage for transmission.
    let mut key_package_bytes = Vec::new();
    bundle
        .key_package()
        .tls_serialize(&mut key_package_bytes)
        .map_err(|e| format!("KeyPackage TLS serialize failed: {e}"))?;

    // Return the raw hash reference bytes (not TLS-serialized, just the inner value).
    let hash_ref_bytes = hash_ref.as_slice().to_vec();

    Ok(KeyPackageOutput {
        key_package_bytes,
        private_key_bytes,
        hash_ref_bytes,
    })
}
