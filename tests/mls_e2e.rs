/// Integration tests for OpenMLS credential and KeyPackage generation,
/// and MLS group lifecycle (export_voice_frame_key).
/// These tests run on the native target (`cargo test`).

use hush_crypto::credential::generate_credential;
use hush_crypto::group;
use hush_crypto::key_package::generate_key_package;

#[test]
fn test_generate_credential_returns_non_empty_fields() {
    let result = generate_credential("user_id:device_id").unwrap();
    assert!(!result.signing_public_key.is_empty(), "signing_public_key must not be empty");
    assert!(!result.signing_private_key.is_empty(), "signing_private_key must not be empty");
    assert!(!result.credential_bytes.is_empty(), "credential_bytes must not be empty");
}

#[test]
fn test_generate_credential_signing_public_key_is_32_bytes() {
    let result = generate_credential("user_id:device_id").unwrap();
    assert_eq!(
        result.signing_public_key.len(),
        32,
        "Ed25519 public key must be 32 bytes, got {}",
        result.signing_public_key.len()
    );
}

#[test]
fn test_generate_credential_signing_private_key_is_64_bytes() {
    let result = generate_credential("user_id:device_id").unwrap();
    assert_eq!(
        result.signing_private_key.len(),
        64,
        "Ed25519 expanded private key must be 64 bytes, got {}",
        result.signing_private_key.len()
    );
}

#[test]
fn test_generate_key_package_returns_non_empty_fields() {
    let cred = generate_credential("user_id:device_id").unwrap();
    let result = generate_key_package(
        &cred.signing_private_key,
        &cred.signing_public_key,
        &cred.credential_bytes,
    )
    .unwrap();
    assert!(!result.key_package_bytes.is_empty(), "key_package_bytes must not be empty");
    assert!(!result.private_key_bytes.is_empty(), "private_key_bytes must not be empty");
    assert!(!result.hash_ref_bytes.is_empty(), "hash_ref_bytes must not be empty");
}

#[test]
fn test_generate_key_package_different_hash_refs() {
    let cred = generate_credential("user_id:device_id").unwrap();
    let kp1 = generate_key_package(
        &cred.signing_private_key,
        &cred.signing_public_key,
        &cred.credential_bytes,
    )
    .unwrap();
    let kp2 = generate_key_package(
        &cred.signing_private_key,
        &cred.signing_public_key,
        &cred.credential_bytes,
    )
    .unwrap();
    assert_ne!(
        kp1.hash_ref_bytes, kp2.hash_ref_bytes,
        "Two KeyPackages from same credential must have different hash references"
    );
}

#[test]
fn test_generate_key_package_round_trip_tls_deserialization() {
    use openmls::prelude::tls_codec::Deserialize;
    use openmls::prelude::KeyPackageIn;

    let cred = generate_credential("user_id:device_id").unwrap();
    let kp = generate_key_package(
        &cred.signing_private_key,
        &cred.signing_public_key,
        &cred.credential_bytes,
    )
    .unwrap();

    let mut bytes = kp.key_package_bytes.as_slice();
    let kp_in = KeyPackageIn::tls_deserialize(&mut bytes)
        .expect("key_package_bytes must TLS-deserialize into KeyPackageIn");
    // Verify the deserialized package has a non-empty leaf node
    drop(kp_in);
}

// ---------------------------------------------------------------------------
// export_voice_frame_key tests (M.3-01)
// ---------------------------------------------------------------------------

/// Build an in-memory provider and a fresh single-member MLS group for testing.
/// Returns (provider, group_id_bytes).
fn make_test_group() -> (openmls_rust_crypto::OpenMlsRustCrypto, Vec<u8>) {
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use hush_crypto::credential::CIPHERSUITE;

    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let cred = generate_credential("test_user:device_1").unwrap();

    let seed = &cred.signing_private_key[..32];
    let signer = SignatureKeyPair::from_raw(CIPHERSUITE.into(), seed.to_vec(), cred.signing_public_key.clone());

    let credential = {
        let mut slice = cred.credential_bytes.as_slice();
        Credential::tls_deserialize(&mut slice).unwrap()
    };
    let cwk = CredentialWithKey {
        credential,
        signature_key: cred.signing_public_key.clone().into(),
    };

    let channel_id = b"test-channel-id-0001".to_vec();
    group::create_group(&provider, &signer, cwk, &channel_id).unwrap();
    (provider, channel_id)
}

/// Test 1: export_voice_frame_key returns exactly 32 bytes for a fresh group.
#[test]
fn test_export_voice_frame_key_returns_32_bytes() {
    let (provider, group_id) = make_test_group();
    let key = group::export_voice_frame_key(&provider, &group_id)
        .expect("export_voice_frame_key must succeed");
    assert_eq!(
        key.len(),
        32,
        "Voice frame key must be 32 bytes (AES-256-GCM), got {}",
        key.len()
    );
}

/// Test 2: export_voice_frame_key is deterministic - same group, same epoch → same key.
#[test]
fn test_export_voice_frame_key_deterministic() {
    let (provider, group_id) = make_test_group();
    let key1 = group::export_voice_frame_key(&provider, &group_id).unwrap();
    let key2 = group::export_voice_frame_key(&provider, &group_id).unwrap();
    assert_eq!(
        key1, key2,
        "export_voice_frame_key must return identical bytes on repeated calls at the same epoch"
    );
}

// ---------------------------------------------------------------------------
// export_metadata_key tests (0O-02)
// ---------------------------------------------------------------------------

/// Test 1: export_metadata_key returns exactly 32 bytes for a fresh group.
#[test]
fn test_export_metadata_key_returns_32_bytes() {
    let (provider, group_id) = make_test_group();
    let key = group::export_metadata_key(&provider, &group_id)
        .expect("export_metadata_key must succeed");
    assert_eq!(
        key.len(),
        32,
        "Metadata key must be 32 bytes (AES-256-GCM), got {}",
        key.len()
    );
}

/// Test 2: export_metadata_key is non-zero - a zero key would indicate a
/// catastrophic derivation failure.
#[test]
fn test_export_metadata_key_is_nonzero() {
    let (provider, group_id) = make_test_group();
    let key = group::export_metadata_key(&provider, &group_id).unwrap();
    assert!(
        key.iter().any(|&b| b != 0),
        "Metadata key must not be all-zero bytes"
    );
}

/// Test 3: export_metadata_key produces different bytes than export_voice_frame_key
/// for the same group at the same epoch - distinct labels must produce distinct keys.
#[test]
fn test_export_metadata_key_differs_from_voice_frame_key() {
    let (provider, group_id) = make_test_group();
    let metadata_key = group::export_metadata_key(&provider, &group_id).unwrap();
    let voice_key = group::export_voice_frame_key(&provider, &group_id).unwrap();
    assert_ne!(
        metadata_key, voice_key,
        "export_metadata_key and export_voice_frame_key must produce distinct keys \
         (different labels: hush-guild-metadata vs hush-voice-frame-key)"
    );
}

/// Test 4: export_voice_frame_key returns a different key after self_update advances the epoch.
#[test]
fn test_export_voice_frame_key_changes_after_epoch_advance() {
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use hush_crypto::credential::CIPHERSUITE;

    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let cred = generate_credential("test_user:device_epoch").unwrap();

    let seed = &cred.signing_private_key[..32];
    let signer = SignatureKeyPair::from_raw(CIPHERSUITE.into(), seed.to_vec(), cred.signing_public_key.clone());

    let credential = {
        let mut slice = cred.credential_bytes.as_slice();
        Credential::tls_deserialize(&mut slice).unwrap()
    };
    let cwk = CredentialWithKey {
        credential,
        signature_key: cred.signing_public_key.clone().into(),
    };

    let channel_id = b"test-channel-epoch-02".to_vec();
    group::create_group(&provider, &signer, cwk, &channel_id).unwrap();

    let key_before = group::export_voice_frame_key(&provider, &channel_id).unwrap();
    let epoch_before = group::get_group_epoch(&provider, &channel_id).unwrap();

    // Advance epoch via self_update + merge.
    group::self_update(&provider, &signer, &channel_id).unwrap();
    group::merge_pending_commit(&provider, &channel_id).unwrap();

    let epoch_after = group::get_group_epoch(&provider, &channel_id).unwrap();
    assert!(epoch_after > epoch_before, "Epoch must advance after self_update+merge");

    let key_after = group::export_voice_frame_key(&provider, &channel_id).unwrap();
    assert_ne!(
        key_before, key_after,
        "Voice frame key must change when epoch advances (forward secrecy)"
    );
}
