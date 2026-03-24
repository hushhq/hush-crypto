//! MLS group lifecycle: create, join external, add/remove members,
//! send, receive, self-update, leave, merge, and export GroupInfo.
//!
//! All functions accept a `&impl OpenMlsProvider` so both the native
//! in-memory provider (tests) and the WASM JS-callback bridge work
//! transparently.
//!
//! Groups are identified by a `group_id_bytes` byte slice (typically the
//! channel UUID raw bytes or ASCII representation).  Each function loads the
//! group from the `StorageProvider` via `MlsGroup::load()` — no state bytes
//! are passed in or returned; OpenMLS auto-persists through the trait.

use openmls::messages::group_info::GroupInfo;
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_basic_credential::SignatureKeyPair;

use crate::credential::CIPHERSUITE;

// ---------------------------------------------------------------------------
// Return types
// ---------------------------------------------------------------------------

/// Result of processing an incoming MLS message.
#[derive(Debug)]
pub enum ProcessedMessageResult {
    /// An application message — contains the decrypted plaintext bytes.
    ApplicationMessage(Vec<u8>),
    /// A staged commit — the group state has been updated.
    StagedCommit,
    /// A proposal — stored in the pending queue for a future commit.
    Proposal,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the standard group create config used throughout Hush.
fn make_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // SECURITY: out_of_order_tolerance — allows decrypting messages received
                  // out of order within this window. Weakens forward secrecy — a compromised
                  // key can decrypt this many additional messages. Set to 10 as a conscious
                  // tradeoff between reliability on lossy/mobile networks and FS strength.
            1000, // SECURITY: maximum_forward_distance — maximum epoch gap tolerated before
                  // requiring re-sync. Limits how far ahead a malicious commit can advance
                  // the epoch. Conscious tradeoff between availability during network
                  // partitions and FS guarantees.
        ))
        .max_past_epochs(
            5, // SECURITY: max_past_epochs — retains decryption keys for this many past
               // epochs. Weakens forward secrecy — past epoch keys remain in memory.
               // Conscious tradeoff to handle delayed messages during epoch transitions
               // (member join/leave/rotation).
        )
        .use_ratchet_tree_extension(true)
        .ciphersuite(CIPHERSUITE)
        .build()
}

/// Build the standard group join config used throughout Hush.
fn make_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // SECURITY: out_of_order_tolerance — see make_create_config for rationale.
            1000, // SECURITY: maximum_forward_distance — see make_create_config for rationale.
        ))
        .max_past_epochs(
            5, // SECURITY: max_past_epochs — see make_create_config for rationale.
        )
        .use_ratchet_tree_extension(true)
        .build()
}

/// Load an existing group from storage.  Returns an error if the group is not
/// found (e.g. storage cleared or wrong group_id).
fn load_group<P: OpenMlsProvider>(
    provider: &P,
    group_id_bytes: &[u8],
) -> Result<MlsGroup, String> {
    let group_id = GroupId::from_slice(group_id_bytes);
    MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| format!("MlsGroup::load error: {e:?}"))?
        .ok_or_else(|| format!("Group not found for id (len={})", group_id_bytes.len()))
}

/// TLS-serialize an `MlsMessageOut` to bytes.
fn serialize_msg(msg: MlsMessageOut) -> Result<Vec<u8>, String> {
    msg.tls_serialize_detached()
        .map_err(|e| format!("TLS serialize MlsMessageOut failed: {e}"))
}

/// TLS-serialize a `GroupInfo` to bytes via `MlsMessageOut`.
///
/// In OpenMLS 0.8.1, `GroupInfo` can be converted `Into<MlsMessageOut>`.
fn serialize_group_info(info: GroupInfo) -> Result<Vec<u8>, String> {
    let msg: MlsMessageOut = info.into();
    serialize_msg(msg)
}

/// Export and serialize the current `GroupInfo` for a group.
fn export_and_serialize_group_info<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, String> {
    let msg_out = group
        .export_group_info(provider.crypto(), signer, true)
        .map_err(|e| format!("export_group_info failed: {e:?}"))?;
    serialize_msg(msg_out)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new MLS group whose ID is derived from `channel_id_bytes`.
///
/// The group is persisted into `provider`'s storage automatically.
///
/// # Returns
///
/// TLS-serialized `MlsMessageOut` wrapping a `GroupInfo` — POST these bytes
/// to the server so other members can join via External Commit.
pub fn create_group<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    channel_id_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    // Persist signer so OpenMLS can verify self-signatures during later ops.
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let group_id = GroupId::from_slice(channel_id_bytes);
    let config = make_create_config();

    let mut group = MlsGroup::new_with_group_id(
        provider,
        signer,
        &config,
        group_id,
        credential_with_key,
    )
    .map_err(|e| format!("MlsGroup::new_with_group_id failed: {e:?}"))?;

    export_and_serialize_group_info(&mut group, provider, signer)
}

/// Join a group via External Commit from a serialized `GroupInfo` blob.
///
/// The new group state is persisted automatically.  The caller must POST the
/// returned Commit bytes to the server so existing members can update.
///
/// # Returns
///
/// TLS-serialized Commit bytes.
pub fn join_group_external<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    group_info_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    // Persist signer for subsequent operations.
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    // group_info_bytes is a TLS-serialized MlsMessageOut wrapping a GroupInfo.
    // Deserialize as MlsMessageIn first, then extract the VerifiableGroupInfo.
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let mls_in = {
        let mut slice = group_info_bytes;
        MlsMessageIn::tls_deserialize(&mut slice)
            .map_err(|e| format!("GroupInfo MlsMessageIn TLS deserialize failed: {e}"))?
    };
    let verifiable_gi = match mls_in.extract() {
        MlsMessageBodyIn::GroupInfo(group_info) => group_info,
        _ => return Err("Expected GroupInfo message wire format".to_string()),
    };

    let join_config = make_join_config();

    let (_group, commit_bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config)
        .build_group(provider, verifiable_gi, credential_with_key)
        .map_err(|e| format!("external_commit_builder.build_group failed: {e:?}"))?
        .leaf_node_parameters(LeafNodeParameters::default())
        .load_psks(provider.storage())
        .map_err(|e| format!("load_psks failed: {e:?}"))?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(|e| format!("commit_builder.build failed: {e:?}"))?
        .finalize(provider)
        .map_err(|e| format!("commit_builder.finalize failed: {e:?}"))?;

    let (commit_msg, _welcome, _group_info) = commit_bundle.into_contents();
    serialize_msg(commit_msg)
}

/// Add one or more members to an existing group via their KeyPackage bytes.
///
/// # Arguments
///
/// * `key_packages_bytes` — slice of TLS-serialized `KeyPackage` byte vectors.
///
/// # Returns
///
/// `(commit_bytes, welcome_bytes, group_info_bytes)`.  POST commit to all
/// existing members; send welcome to the new members.
pub fn add_members<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
    key_packages_bytes: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;

    // Deserialize and validate each KeyPackage.
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let key_packages: Vec<KeyPackage> = key_packages_bytes
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            let kp_in = {
                let mut slice = bytes.as_slice();
                KeyPackageIn::tls_deserialize(&mut slice)
                    .map_err(|e| format!("KeyPackage[{i}] TLS deserialize failed: {e}"))?
            };
            kp_in
                .validate(provider.crypto(), ProtocolVersion::default())
                .map_err(|e| format!("KeyPackage[{i}] validate failed: {e:?}"))
        })
        .collect::<Result<Vec<_>, String>>()?;

    // add_members takes a &[KeyPackage] (owned values, not references).
    let (commit_msg, welcome_msg, group_info_opt) = group
        .add_members(provider, signer, &key_packages)
        .map_err(|e| format!("group.add_members failed: {e:?}"))?;

    let commit_bytes = serialize_msg(commit_msg)?;
    // The Welcome is already wrapped in MlsMessageOut.
    let welcome_bytes = serialize_msg(welcome_msg)?;

    let group_info_bytes = match group_info_opt {
        Some(gi) => serialize_group_info(gi)?,
        None => export_and_serialize_group_info(&mut group, provider, signer)?,
    };

    Ok((commit_bytes, welcome_bytes, group_info_bytes))
}

/// Encrypt plaintext as an MLS application message.
///
/// # Returns
///
/// TLS-serialized `MlsMessageOut` bytes.  Broadcast to all channel members.
///
/// CRITICAL: The sender cannot decrypt their own message after this call.
/// Save plaintext to local storage before calling.
pub fn create_message<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;

    let msg_out = group
        .create_message(provider, signer, plaintext)
        .map_err(|e| format!("group.create_message failed: {e:?}"))?;

    serialize_msg(msg_out)
}

/// Process an incoming MLS message (application msg, commit, or proposal).
///
/// For StagedCommit messages, `merge_staged_commit` is called immediately.
/// Call `merge_pending_commit` only for commits produced by THIS member
/// (after server ACK).
///
/// # Returns
///
/// A `ProcessedMessageResult` indicating the message type and content.
pub fn process_message<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
    msg_bytes: &[u8],
) -> Result<ProcessedMessageResult, String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;

    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let mls_in = {
        let mut slice = msg_bytes;
        MlsMessageIn::tls_deserialize(&mut slice)
            .map_err(|e| format!("MlsMessageIn TLS deserialize failed: {e}"))?
    };

    let protocol_msg = mls_in
        .try_into_protocol_message()
        .map_err(|e| format!("try_into_protocol_message failed: {e:?}"))?;

    let processed = group
        .process_message(provider, protocol_msg)
        .map_err(|e| format!("group.process_message failed: {e:?}"))?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            Ok(ProcessedMessageResult::ApplicationMessage(app_msg.into_bytes()))
        }
        ProcessedMessageContent::ProposalMessage(staged_proposal) => {
            group
                .store_pending_proposal(provider.storage(), *staged_proposal)
                .map_err(|e| format!("store_pending_proposal failed: {e:?}"))?;
            Ok(ProcessedMessageResult::Proposal)
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(provider, *staged_commit)
                .map_err(|e| format!("merge_staged_commit failed: {e:?}"))?;
            Ok(ProcessedMessageResult::StagedCommit)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            Ok(ProcessedMessageResult::Proposal)
        }
    }
}

/// Remove one or more members by their credential identity bytes.
///
/// # Returns
///
/// `(commit_bytes, group_info_bytes)`.  POST commit to all members.
pub fn remove_members<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
    member_identities: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;

    // Resolve identity bytes to LeafNodeIndex values.
    let leaf_indices: Vec<LeafNodeIndex> = member_identities
        .iter()
        .map(|identity| {
            group
                .members()
                .find(|m| m.credential.serialized_content() == identity.as_slice())
                .map(|m| m.index)
                .ok_or_else(|| {
                    format!(
                        "Member not found: {:?}",
                        String::from_utf8_lossy(identity)
                    )
                })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let (commit_msg, _welcome, group_info_opt) = group
        .remove_members(provider, signer, &leaf_indices)
        .map_err(|e| format!("group.remove_members failed: {e:?}"))?;

    let commit_bytes = serialize_msg(commit_msg)?;
    let group_info_bytes = match group_info_opt {
        Some(gi) => serialize_group_info(gi)?,
        None => export_and_serialize_group_info(&mut group, provider, signer)?,
    };

    Ok((commit_bytes, group_info_bytes))
}

/// Rotate the caller's own HPKE key (post-compromise security update).
///
/// # Returns
///
/// `(commit_bytes, group_info_bytes)`.  POST commit to all members.
pub fn self_update<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;

    let bundle = group
        .self_update(provider, signer, LeafNodeParameters::default())
        .map_err(|e| format!("group.self_update failed: {e:?}"))?;

    let (commit_msg, _welcome, group_info_opt) = bundle.into_contents();
    let commit_bytes = serialize_msg(commit_msg)?;

    let group_info_bytes = match group_info_opt {
        Some(gi) => serialize_group_info(gi)?,
        None => export_and_serialize_group_info(&mut group, provider, signer)?,
    };

    Ok((commit_bytes, group_info_bytes))
}

/// Send a self-remove proposal.  The leaving member CANNOT commit their own
/// removal — another member must commit it.
///
/// # Returns
///
/// TLS-serialized proposal `MlsMessageOut` bytes.  POST to the server.
pub fn leave_group<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;

    let proposal_msg = group
        .leave_group(provider, signer)
        .map_err(|e| format!("group.leave_group failed: {e:?}"))?;

    serialize_msg(proposal_msg)
}

/// Merge the pending commit after the server has acknowledged it.
///
/// Call this after server ACK for commits produced by `add_members`,
/// `remove_members`, `self_update`, or any other Commit-producing operation.
pub fn merge_pending_commit<P: OpenMlsProvider>(
    provider: &P,
    group_id_bytes: &[u8],
) -> Result<(), String> {
    let mut group = load_group(provider, group_id_bytes)?;
    group
        .merge_pending_commit(provider)
        .map_err(|e| format!("group.merge_pending_commit failed: {e:?}"))
}

/// Re-export the current `GroupInfo` for the group.
///
/// Call this after every accepted Commit and PUT the result to the server so
/// new joiners always get up-to-date state.
///
/// # Returns
///
/// TLS-serialized `MlsMessageOut` wrapping the current `GroupInfo`.
pub fn export_group_info<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    group_id_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    signer
        .store(provider.storage())
        .map_err(|e| format!("signer.store failed: {e:?}"))?;

    let mut group = load_group(provider, group_id_bytes)?;
    export_and_serialize_group_info(&mut group, provider, signer)
}

/// Return the current epoch number for a group.
///
/// Useful for tracking which Commits have been processed.
pub fn get_group_epoch<P: OpenMlsProvider>(
    provider: &P,
    group_id_bytes: &[u8],
) -> Result<u64, String> {
    let group = load_group(provider, group_id_bytes)?;
    Ok(group.epoch().as_u64())
}

/// Derive a 32-byte AES-256-GCM frame key from the current MLS group epoch.
///
/// This is a pure derivation using `MlsGroup::export_secret` — no state
/// mutation occurs and no storage flush is needed. The key is deterministic
/// for a given group at a given epoch: calling it twice returns identical bytes.
///
/// After an epoch-advancing commit (member join/leave, self-update), the
/// derived key changes automatically — providing forward secrecy for voice
/// frame encryption without any explicit key rotation logic.
///
/// # Arguments
///
/// * `group_id_bytes` — raw group ID bytes (typically the channel UUID bytes)
///
/// # Returns
///
/// A 32-byte key suitable for LiveKit `ExternalE2EEKeyProvider.setKey()`.
///
/// # Security
///
/// Label `"hush-voice-frame-key"` is unique to this application per RFC 9420
/// section 8.4 to prevent cross-context key reuse.  The empty context slice
/// is intentional — the group ID already encodes the channel identity.
pub fn export_voice_frame_key<P: OpenMlsProvider>(
    provider: &P,
    group_id_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let group = load_group(provider, group_id_bytes)?;
    group
        .export_secret(
            provider.crypto(),
            "hush-voice-frame-key", // SECURITY: unique per-application label (RFC 9420 §8.4)
            &[],                    // empty context — group ID already encodes the channel
            32,                     // 256-bit AES-GCM key for LiveKit frame encryption
        )
        .map_err(|e| format!("export_secret failed: {e:?}"))
}

/// Derive a 32-byte AES-256-GCM key for encrypting guild metadata from the
/// current MLS group epoch.
///
/// This is a pure derivation using `MlsGroup::export_secret` — no state
/// mutation occurs and no storage flush is needed. The key is deterministic
/// for a given group at a given epoch.
///
/// The label `"hush-guild-metadata"` is intentionally distinct from
/// `"hush-voice-frame-key"` so that metadata keys and voice frame keys are
/// cryptographically independent even when derived from the same group state
/// (RFC 9420 §8.4 label separation).
///
/// # Arguments
///
/// * `group_id_bytes` — raw group ID bytes (typically the channel UUID bytes)
///
/// # Returns
///
/// A 32-byte key for AES-256-GCM encryption of guild metadata (name, icon, etc.).
///
/// # Security
///
/// Label `"hush-guild-metadata"` is unique to this application per RFC 9420
/// section 8.4 to prevent cross-context key reuse.  The empty context slice
/// is intentional — the group ID already encodes the channel/guild identity.
pub fn export_metadata_key<P: OpenMlsProvider>(
    provider: &P,
    group_id_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let group = load_group(provider, group_id_bytes)?;
    group
        .export_secret(
            provider.crypto(),
            "hush-guild-metadata", // SECURITY: unique per-application label (RFC 9420 §8.4)
            &[],                   // empty context — group ID already encodes the guild identity
            32,                    // 256-bit AES-GCM key for guild metadata encryption
        )
        .map_err(|e| format!("export_secret failed: {e:?}"))
}
