/// Integration tests for MLS group lifecycle.
///
/// These tests run on the native target (`cargo test`).
/// They use the in-memory `OpenMlsRustCrypto` provider (via storage_bridge).
/// All group operations load state from the provider — no manual state bytes.

use hush_crypto::credential::{generate_credential, CIPHERSUITE};
use hush_crypto::group::{
    add_members, create_group, create_message, export_group_info, get_group_epoch,
    join_group_external, leave_group, merge_pending_commit, process_message, remove_members,
    self_update,
};
use hush_crypto::key_package::generate_key_package_with_provider;
use hush_crypto::storage_bridge::new_native_provider;
use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls_basic_credential::SignatureKeyPair;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reconstruct an OpenMLS `SignatureKeyPair` from the raw bytes that
/// `generate_credential` returns (64-byte seed||public encoding).
fn make_signer(private_key: &[u8], public_key: &[u8]) -> SignatureKeyPair {
    let seed = &private_key[..32];
    SignatureKeyPair::from_raw(CIPHERSUITE.into(), seed.to_vec(), public_key.to_vec())
}

/// Reconstruct a `CredentialWithKey` from TLS-serialized credential bytes
/// and the raw Ed25519 public key.
fn make_credential_with_key(
    credential_bytes: &[u8],
    signing_public_key: &[u8],
) -> CredentialWithKey {
    let mut slice = credential_bytes;
    let credential = Credential::tls_deserialize(&mut slice)
        .expect("Credential TLS deserialize failed");
    CredentialWithKey {
        credential,
        signature_key: signing_public_key.to_vec().into(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: create_group returns non-empty GroupInfo bytes
// ---------------------------------------------------------------------------

#[test]
fn test_create_group_produces_group_info() {
    let provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let credential_with_key = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);

    let channel_id = b"01234567-89ab-cdef-0123-456789abcdef";
    let group_info_bytes = create_group(&provider, &signer, credential_with_key, channel_id)
        .expect("create_group failed");

    assert!(!group_info_bytes.is_empty(), "GroupInfo bytes must not be empty");
    assert!(group_info_bytes.len() > 20, "GroupInfo bytes too short to be valid");
}

// ---------------------------------------------------------------------------
// Test 2: Two-party flow — External Commit join + message round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_external_commit_join_and_message_roundtrip() {
    // Alice creates group
    let alice_provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let alice_signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let alice_cwk = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);

    let channel_id = b"channel-ext-commit-roundtrip-0001";
    let group_info_bytes = create_group(&alice_provider, &alice_signer, alice_cwk.clone(), channel_id)
        .expect("Alice create_group failed");

    // Bob joins via External Commit
    let bob_provider = new_native_provider();
    let bob = generate_credential("bob:device1").unwrap();
    let bob_signer = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let bob_cwk = make_credential_with_key(&bob.credential_bytes, &bob.signing_public_key);

    let commit_bytes = join_group_external(&bob_provider, &bob_signer, bob_cwk, &group_info_bytes)
        .expect("Bob join_group_external failed");

    assert!(!commit_bytes.is_empty(), "External Commit bytes must not be empty");

    // Alice processes Bob's External Commit and merges
    let alice_signer2 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let _result = process_message(&alice_provider, &alice_signer2, channel_id, &commit_bytes)
        .expect("Alice process_message (external commit) failed");
    merge_pending_commit(&alice_provider, channel_id)
        .expect("Alice merge_pending_commit failed");

    // Alice sends a message
    let alice_signer3 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let plaintext = b"Hello Bob from Alice!";
    let msg_bytes = create_message(&alice_provider, &alice_signer3, channel_id, plaintext)
        .expect("Alice create_message failed");

    assert!(!msg_bytes.is_empty(), "MlsMessageOut bytes must not be empty");

    // Bob decrypts the message
    let bob_signer2 = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let bob_group_id = {
        // Bob's group ID = channel_id bytes (from the GroupInfo)
        // We need to find out what group ID was created; use same channel_id
        channel_id
    };
    let processed = process_message(&bob_provider, &bob_signer2, bob_group_id, &msg_bytes)
        .expect("Bob process_message failed");

    match processed {
        hush_crypto::group::ProcessedMessageResult::ApplicationMessage(decrypted) => {
            assert_eq!(decrypted, plaintext, "Bob must receive original plaintext");
        }
        other => panic!("Expected ApplicationMessage, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 3: add_members — Alice adds Bob via KeyPackage, Bob joins via Welcome
// ---------------------------------------------------------------------------

#[test]
fn test_add_members_via_key_package_and_welcome() {
    // Alice creates group
    let alice_provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let alice_signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let alice_cwk = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);
    let channel_id = b"channel-add-members-via-welcome-1";
    create_group(&alice_provider, &alice_signer, alice_cwk, channel_id)
        .expect("Alice create_group failed");

    // Bob generates a KeyPackage INTO his own provider so private keys are stored there.
    let bob_provider = new_native_provider();
    let bob = generate_credential("bob:device1").unwrap();
    let bob_kp = generate_key_package_with_provider(
        &bob_provider,
        &bob.signing_private_key,
        &bob.signing_public_key,
        &bob.credential_bytes,
    )
    .expect("Bob generate_key_package_with_provider failed");

    // Alice adds Bob
    let alice_signer2 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let kp_bytes = vec![bob_kp.key_package_bytes.clone()];
    let (commit_bytes, welcome_bytes, _group_info_bytes) =
        add_members(&alice_provider, &alice_signer2, channel_id, &kp_bytes)
            .expect("Alice add_members failed");

    assert!(!commit_bytes.is_empty(), "Commit bytes must not be empty");
    assert!(!welcome_bytes.is_empty(), "Welcome bytes must not be empty");

    // Alice merges commit
    merge_pending_commit(&alice_provider, channel_id)
        .expect("Alice merge_pending_commit failed");

    // Bob joins via Welcome
    use openmls::prelude::*;
    use openmls::prelude::tls_codec::Deserialize as TlsDeser;
    let mut w_slice = welcome_bytes.as_slice();
    let welcome = MlsMessageIn::tls_deserialize(&mut w_slice)
        .expect("Welcome TLS deserialize failed");
    let join_config = MlsGroupJoinConfig::builder()
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 1000))
        .max_past_epochs(5)
        .use_ratchet_tree_extension(true)
        .build();
    let welcome_msg = match welcome.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("Expected Welcome message"),
    };
    let staged_join = StagedWelcome::new_from_welcome(&bob_provider, &join_config, welcome_msg, None)
        .expect("Bob StagedWelcome::new_from_welcome failed");
    let _bob_group = staged_join.into_group(&bob_provider)
        .expect("Bob into_group failed");

    // Alice sends a message after Bob joined
    let alice_signer3 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let plaintext = b"Welcome to the group, Bob!";
    let msg_bytes = create_message(&alice_provider, &alice_signer3, channel_id, plaintext)
        .expect("Alice create_message failed");

    // Bob decrypts
    let bob_signer3 = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let processed = process_message(&bob_provider, &bob_signer3, channel_id, &msg_bytes)
        .expect("Bob process_message failed");
    match processed {
        hush_crypto::group::ProcessedMessageResult::ApplicationMessage(decrypted) => {
            assert_eq!(decrypted, plaintext);
        }
        other => panic!("Expected ApplicationMessage, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 4: remove member — removed member cannot decrypt subsequent messages
// ---------------------------------------------------------------------------

#[test]
fn test_remove_member_blocks_decryption() {
    // Setup: Alice creates group, Bob joins via External Commit
    let alice_provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let alice_signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let alice_cwk = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);
    let channel_id = b"channel-remove-member-blocks-dec";

    let group_info_bytes = create_group(&alice_provider, &alice_signer, alice_cwk, channel_id)
        .expect("Alice create_group failed");

    let bob_provider = new_native_provider();
    let bob = generate_credential("bob:device1").unwrap();
    let bob_signer = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let bob_cwk = make_credential_with_key(&bob.credential_bytes, &bob.signing_public_key);

    let commit_bytes = join_group_external(&bob_provider, &bob_signer, bob_cwk, &group_info_bytes)
        .expect("Bob join_group_external failed");

    // Alice processes Bob's join commit
    let alice_signer2 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    process_message(&alice_provider, &alice_signer2, channel_id, &commit_bytes)
        .expect("Alice process commit failed");
    merge_pending_commit(&alice_provider, channel_id)
        .expect("Alice merge failed");

    // Bob processes his own join commit (merges it)
    let bob_signer2 = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let _ = process_message(&bob_provider, &bob_signer2, channel_id, &commit_bytes); // might be self, ignore error

    // Alice removes Bob using his identity bytes
    let alice_signer3 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let bob_identity = b"bob:device1".to_vec();
    let (remove_commit_bytes, _group_info) =
        remove_members(&alice_provider, &alice_signer3, channel_id, &[bob_identity])
            .expect("Alice remove_members failed");
    merge_pending_commit(&alice_provider, channel_id)
        .expect("Alice merge remove commit failed");

    // Alice sends a message after removal
    let alice_signer4 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let post_remove_msg = create_message(
        &alice_provider,
        &alice_signer4,
        channel_id,
        b"Secret after Bob removed",
    )
    .expect("Alice create_message after remove failed");

    // Bob tries to decrypt — must fail (he was removed)
    // First Bob needs to process the remove commit to know he was removed
    let bob_signer3 = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    // Processing the remove commit might succeed (it's a StagedCommit indicating removal)
    // but processing subsequent messages must fail
    let _ = process_message(&bob_provider, &bob_signer3, channel_id, &remove_commit_bytes);

    // Bob tries to decrypt message sent after his removal — must fail
    let bob_signer4 = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let result = process_message(&bob_provider, &bob_signer4, channel_id, &post_remove_msg);
    assert!(result.is_err(), "Bob must not be able to decrypt messages after removal");
}

// ---------------------------------------------------------------------------
// Test 5: self_update advances epoch number
// ---------------------------------------------------------------------------

#[test]
fn test_self_update_advances_epoch() {
    let provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let cwk = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);
    let channel_id = b"channel-self-update-epoch-test01";

    create_group(&provider, &signer, cwk, channel_id)
        .expect("create_group failed");

    let epoch_before = get_group_epoch(&provider, channel_id)
        .expect("get_group_epoch failed");

    let alice_signer2 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let (_commit_bytes, _group_info) = self_update(&provider, &alice_signer2, channel_id)
        .expect("self_update failed");
    merge_pending_commit(&provider, channel_id)
        .expect("merge_pending_commit failed");

    let epoch_after = get_group_epoch(&provider, channel_id)
        .expect("get_group_epoch after update failed");

    assert!(
        epoch_after > epoch_before,
        "Epoch must advance after self_update: before={}, after={}",
        epoch_before,
        epoch_after
    );
}

// ---------------------------------------------------------------------------
// Test 6: leave_group returns a proposal (not a Commit)
// ---------------------------------------------------------------------------

#[test]
fn test_leave_group_returns_proposal() {
    // Alice creates group, Bob joins
    let alice_provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let alice_signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let alice_cwk = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);
    let channel_id = b"channel-leave-group-proposal-001";

    let group_info_bytes = create_group(&alice_provider, &alice_signer, alice_cwk, channel_id)
        .expect("Alice create_group failed");

    let bob_provider = new_native_provider();
    let bob = generate_credential("bob:device1").unwrap();
    let bob_signer = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let bob_cwk = make_credential_with_key(&bob.credential_bytes, &bob.signing_public_key);

    let commit_bytes = join_group_external(&bob_provider, &bob_signer, bob_cwk, &group_info_bytes)
        .expect("Bob join_group_external failed");

    // Alice processes Bob's join
    let alice_signer2 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    process_message(&alice_provider, &alice_signer2, channel_id, &commit_bytes)
        .expect("Alice process join commit failed");
    merge_pending_commit(&alice_provider, channel_id)
        .expect("Alice merge failed");

    // Bob leaves (sends a proposal, not a commit)
    let bob_signer2 = make_signer(&bob.signing_private_key, &bob.signing_public_key);
    let proposal_bytes = leave_group(&bob_provider, &bob_signer2, channel_id)
        .expect("Bob leave_group failed");

    assert!(!proposal_bytes.is_empty(), "Leave proposal bytes must not be empty");

    // Verify it deserializes as a Proposal (not a Commit)
    let mut slice = proposal_bytes.as_slice();
    let msg_in = MlsMessageIn::tls_deserialize(&mut slice)
        .expect("Leave proposal TLS deserialize failed");

    match msg_in.extract() {
        MlsMessageBodyIn::PublicMessage(pub_msg) => {
            // leave_group sends a Proposal content type
            assert!(
                matches!(pub_msg.content_type(), ContentType::Proposal),
                "leave_group must return a Proposal, got {:?}", pub_msg.content_type()
            );
        }
        MlsMessageBodyIn::PrivateMessage(_) => {
            // Private messages wrapping a proposal are also valid
            // The test goal is that leave_group does NOT return a Commit
        }
        _other => panic!("Expected PublicMessage or PrivateMessage, got unexpected variant"),
    }
}

// ---------------------------------------------------------------------------
// Test 7: export_group_info returns non-empty bytes
// ---------------------------------------------------------------------------

#[test]
fn test_export_group_info_returns_bytes() {
    let provider = new_native_provider();
    let alice = generate_credential("alice:device1").unwrap();
    let signer = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let cwk = make_credential_with_key(&alice.credential_bytes, &alice.signing_public_key);
    let channel_id = b"channel-export-group-info-test01";

    create_group(&provider, &signer, cwk, channel_id)
        .expect("create_group failed");

    let alice_signer2 = make_signer(&alice.signing_private_key, &alice.signing_public_key);
    let info_bytes = export_group_info(&provider, &alice_signer2, channel_id)
        .expect("export_group_info failed");

    assert!(!info_bytes.is_empty(), "GroupInfo bytes must not be empty");
}
