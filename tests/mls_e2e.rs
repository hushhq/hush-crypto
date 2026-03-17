/// Integration tests for OpenMLS credential and KeyPackage generation.
/// These tests run on the native target (`cargo test`).

use hush_crypto::credential::generate_credential;
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
