//! End-to-end integration test for the hush-crypto wrapper layer.
//! Validates: identity generation, pre-key generation with private keys,
//! X3DH initiator + responder, Double Ratchet encrypt/decrypt, bidirectional messaging.

use hush_crypto::{
    generate_identity, generate_one_time_pre_keys, generate_signed_pre_key,
    perform_x3dh, perform_x3dh_responder,
    encrypt, decrypt,
};

/// Builds a server bundle JSON string from Bob's public keys.
fn build_server_bundle_json(
    identity_key: &[u8],
    signed_pre_key: &[u8],
    signed_pre_key_signature: &[u8],
    registration_id: u32,
    one_time_pre_key_id: Option<u32>,
    one_time_pre_key: Option<&[u8]>,
) -> String {
    let mut json = format!(
        r#"{{"identityKey":{ik},"signedPreKey":{spk},"signedPreKeySignature":{sig},"registrationId":{rid}"#,
        ik = bytes_to_json_array(identity_key),
        spk = bytes_to_json_array(signed_pre_key),
        sig = bytes_to_json_array(signed_pre_key_signature),
        rid = registration_id,
    );
    if let (Some(id), Some(pk)) = (one_time_pre_key_id, one_time_pre_key) {
        json.push_str(&format!(
            r#","oneTimePreKeyId":{},"oneTimePreKey":{}"#,
            id,
            bytes_to_json_array(pk),
        ));
    }
    json.push('}');
    json
}

fn bytes_to_json_array(bytes: &[u8]) -> String {
    let nums: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", nums.join(","))
}

/// Builds AD = Encode(IK_A) || Encode(IK_B) — 66 bytes.
fn build_ad(initiator_ik: &[u8], responder_ik: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(66);
    ad.extend_from_slice(initiator_ik);
    ad.extend_from_slice(responder_ik);
    ad
}

#[test]
fn test_full_alice_bob_flow_without_opk() {
    // 1. Generate identities for Alice and Bob
    let alice_id = generate_identity().expect("Alice identity");
    let bob_id = generate_identity().expect("Bob identity");

    // 2. Bob generates SPK (private key now returned)
    let (bob_spk_pub, bob_spk_sig, bob_spk_priv) =
        generate_signed_pre_key(&bob_id.private_key, 1).expect("Bob SPK");

    // 3. Build server bundle JSON (no OPK)
    let bundle_json = build_server_bundle_json(
        &bob_id.public_key,
        &bob_spk_pub,
        &bob_spk_sig,
        bob_id.registration_id,
        None,
        None,
    );

    // 4. Alice performs X3DH initiator
    let alice_x3dh = perform_x3dh(&bundle_json, &alice_id.private_key).expect("Alice X3DH");
    assert!(!alice_x3dh.ephemeral_public.is_empty(), "ephemeral_public must be returned");
    assert_eq!(alice_x3dh.ephemeral_public.len(), 33, "ephemeral_public must be 33 bytes");

    // 5. Alice encrypts first message with AD
    let ad = build_ad(&alice_id.public_key, &bob_id.public_key);
    let plaintext = b"Hello Bob, this is Alice!";
    let (ciphertext, alice_state_after) =
        encrypt(&alice_x3dh.state.state_bytes, plaintext, &ad).expect("Alice encrypt");
    assert_ne!(ciphertext, plaintext);

    // 6. Bob performs X3DH responder
    let bob_session = perform_x3dh_responder(
        &bob_id.private_key,
        &bob_spk_priv,
        &bob_spk_pub,
        None, // no OPK
        &alice_id.public_key,
        &alice_x3dh.ephemeral_public,
    )
    .expect("Bob X3DH responder");

    // 7. Bob decrypts Alice's message with same AD
    let (bob_plaintext, bob_state_after) =
        decrypt(&bob_session.state_bytes, &ciphertext, &ad).expect("Bob decrypt");
    assert_eq!(bob_plaintext, plaintext, "Decrypted message must match");

    // 8. Bob replies
    let reply = b"Hi Alice, Bob here!";
    let (reply_ct, _bob_state_2) =
        encrypt(&bob_state_after, reply, &ad).expect("Bob encrypt reply");

    // 9. Alice decrypts Bob's reply
    let (alice_got, _alice_state_2) =
        decrypt(&alice_state_after, &reply_ct, &ad).expect("Alice decrypt reply");
    assert_eq!(alice_got, reply, "Alice must receive Bob's reply");
}

#[test]
fn test_full_alice_bob_flow_with_opk() {
    let alice_id = generate_identity().expect("Alice identity");
    let bob_id = generate_identity().expect("Bob identity");

    let (bob_spk_pub, bob_spk_sig, bob_spk_priv) =
        generate_signed_pre_key(&bob_id.private_key, 1).expect("Bob SPK");

    // Generate OPKs (private keys now returned)
    let bob_otpks = generate_one_time_pre_keys(5, 0).expect("Bob OTPKs");
    assert_eq!(bob_otpks.len(), 5);
    assert_eq!(bob_otpks[0].private_key.len(), 32, "OPK private key must be 32 bytes");
    assert_eq!(bob_otpks[0].public_key.len(), 33, "OPK public key must be 33 bytes");

    let bundle_json = build_server_bundle_json(
        &bob_id.public_key,
        &bob_spk_pub,
        &bob_spk_sig,
        bob_id.registration_id,
        Some(bob_otpks[0].key_id),
        Some(&bob_otpks[0].public_key),
    );

    let alice_x3dh = perform_x3dh(&bundle_json, &alice_id.private_key).expect("Alice X3DH with OPK");

    let ad = build_ad(&alice_id.public_key, &bob_id.public_key);
    let plaintext = b"Hello with OPK forward secrecy!";
    let (ciphertext, alice_state) =
        encrypt(&alice_x3dh.state.state_bytes, plaintext, &ad).expect("Alice encrypt");

    let bob_session = perform_x3dh_responder(
        &bob_id.private_key,
        &bob_spk_priv,
        &bob_spk_pub,
        Some(&bob_otpks[0].private_key),
        &alice_id.public_key,
        &alice_x3dh.ephemeral_public,
    )
    .expect("Bob X3DH responder with OPK");

    let (bob_plaintext, bob_state) =
        decrypt(&bob_session.state_bytes, &ciphertext, &ad).expect("Bob decrypt");
    assert_eq!(bob_plaintext, plaintext);

    // Bidirectional exchange
    let reply = b"Got your OPK message!";
    let (reply_ct, _) = encrypt(&bob_state, reply, &ad).expect("Bob reply");
    let (alice_got, _) = decrypt(&alice_state, &reply_ct, &ad).expect("Alice decrypt reply");
    assert_eq!(alice_got, reply);
}

#[test]
fn test_wrong_ad_fails_decryption() {
    let alice_id = generate_identity().expect("Alice identity");
    let bob_id = generate_identity().expect("Bob identity");

    let (bob_spk_pub, bob_spk_sig, bob_spk_priv) =
        generate_signed_pre_key(&bob_id.private_key, 1).expect("Bob SPK");

    let bundle_json = build_server_bundle_json(
        &bob_id.public_key, &bob_spk_pub, &bob_spk_sig,
        bob_id.registration_id, None, None,
    );

    let alice_x3dh = perform_x3dh(&bundle_json, &alice_id.private_key).expect("X3DH");

    let correct_ad = build_ad(&alice_id.public_key, &bob_id.public_key);
    let wrong_ad = build_ad(&bob_id.public_key, &alice_id.public_key); // swapped order

    let (ciphertext, _) = encrypt(&alice_x3dh.state.state_bytes, b"secret", &correct_ad).expect("encrypt");

    let bob_session = perform_x3dh_responder(
        &bob_id.private_key, &bob_spk_priv, &bob_spk_pub, None,
        &alice_id.public_key, &alice_x3dh.ephemeral_public,
    )
    .expect("responder");

    let result = decrypt(&bob_session.state_bytes, &ciphertext, &wrong_ad);
    assert!(result.is_err(), "Decryption with wrong AD must fail");
}
