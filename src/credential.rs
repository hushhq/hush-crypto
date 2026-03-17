//! MLS credential generation (BasicCredential + SignatureKeyPair).
//!
//! A credential encodes the client's identity inside MLS.  It is used when
//! building a KeyPackage and again when creating or joining a group.

use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use rand::rngs::OsRng;
use serde::Serialize;

use crate::storage::new_provider;

/// Output of a successful credential generation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOutput {
    /// Ed25519 signature public key — 32 bytes.
    pub signing_public_key: Vec<u8>,
    /// Ed25519 private key (seed 32 bytes || public key 32 bytes) — 64 bytes total.
    /// Stored in this format so the caller can reconstruct `SignatureKeyPair`
    /// via `from_raw(SignatureScheme::ED25519, signing_private_key, signing_public_key)`.
    pub signing_private_key: Vec<u8>,
    /// TLS-serialized `Credential` bytes.
    pub credential_bytes: Vec<u8>,
}

/// Ciphersuite used throughout the Hush MLS deployment.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Generates a fresh MLS `BasicCredential` and an Ed25519 `SignatureKeyPair`.
///
/// `identity` is an opaque byte string (e.g. `"user_id:device_id"`) that is
/// embedded verbatim into the credential.  OpenMLS does not interpret it.
///
/// # Returns
///
/// A [`CredentialOutput`] containing:
/// - `signing_public_key`: 32-byte Ed25519 public key
/// - `signing_private_key`: 64-byte representation (32-byte seed || 32-byte public)
/// - `credential_bytes`: TLS-serialized `Credential`
///
/// # Errors
///
/// Returns a `String` error description if key generation or serialization fails.
pub fn generate_credential(identity: &str) -> Result<CredentialOutput, String> {
    let provider = new_provider();

    // Generate Ed25519 keypair directly to capture the private key material.
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key_bytes: Vec<u8> = signing_key.verifying_key().to_bytes().to_vec();
    // Encode private key as 64 bytes: seed (32) || public_key (32).
    let mut private_key_bytes = signing_key.to_bytes().to_vec(); // 32-byte seed
    private_key_bytes.extend_from_slice(&public_key_bytes);     // + 32-byte public

    // Construct SignatureKeyPair for OpenMLS using the raw bytes.
    let signature_keys = SignatureKeyPair::from_raw(
        CIPHERSUITE.into(),
        signing_key.to_bytes().to_vec(), // OpenMLS stores only the 32-byte seed internally
        public_key_bytes.clone(),
    );

    // Persist the signature keys so subsequent KeyPackage builds can look them up.
    signature_keys
        .store(provider.storage())
        .map_err(|e| format!("signature_keys.store failed: {e}"))?;

    let basic_credential = BasicCredential::new(identity.as_bytes().to_vec());

    // TLS-serialize the credential so the caller can transmit/store raw bytes.
    use openmls::prelude::tls_codec::Serialize as TlsSerialize;
    let credential: Credential = basic_credential.into();
    let mut credential_bytes = Vec::new();
    credential
        .tls_serialize(&mut credential_bytes)
        .map_err(|e| format!("credential TLS serialization failed: {e}"))?;

    Ok(CredentialOutput {
        signing_public_key: public_key_bytes,
        signing_private_key: private_key_bytes,
        credential_bytes,
    })
}
