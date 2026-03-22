//! WASM bindings for the web client.
//!
//! Exports via wasm-bindgen:
//!
//! **Credential / KeyPackage (M.1)**
//!   - `generateCredential(identity)` → `{ signingPublicKey, signingPrivateKey, credentialBytes }`
//!   - `generateKeyPackage(signingPrivateKey, signingPublicKey, credentialBytes)` → `{ keyPackageBytes, privateKeyBytes, hashRefBytes }`
//!
//! **Group lifecycle (M.2) — StorageProvider-backed, no groupStateBytes returned**
//!   - `createGroup(channelIdBytes, signingPrivateKey, signingPublicKey, credentialBytes)` → `{ groupInfoBytes, epoch }`
//!   - `joinGroupExternal(groupInfoBytes, signingPrivateKey, signingPublicKey, credentialBytes)` → `{ commitBytes, epoch }`
//!   - `addMembers(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes, keyPackagesBytesJson)` → `{ commitBytes, welcomeBytes, groupInfoBytes, epoch }`
//!   - `createMessage(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes, plaintext)` → `{ messageBytes }`
//!   - `processMessage(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes, messageBytes)` → `{ type, plaintext?, epoch }`
//!   - `removeMembers(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes, memberIdentitiesJson)` → `{ commitBytes, groupInfoBytes, epoch }`
//!   - `selfUpdate(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes)` → `{ commitBytes, groupInfoBytes, epoch }`
//!   - `leaveGroup(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes)` → `{ proposalBytes }`
//!   - `mergePendingCommit(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes)` → `{ groupInfoBytes, epoch }`
//!   - `exportGroupInfo(groupIdBytes, signingPrivateKey, signingPublicKey, credentialBytes)` → `{ groupInfoBytes }`
//!
//! All group functions return `JsValue` containing the operation-specific result.
//! Group state is persisted automatically through the `JsStorageProvider` → IndexedDB bridge.

use wasm_bindgen::prelude::*;

use crate::credential;
use crate::key_package;

// ---------------------------------------------------------------------------
// M.1 exports — credential and KeyPackage generation
// ---------------------------------------------------------------------------

/// No-op initialization hook retained for backward compatibility with
/// `hushCrypto.js` callers that invoke `m.init()` after loading the WASM module.
#[wasm_bindgen]
pub fn init() {}

/// Generate an MLS credential and Ed25519 signing keypair.
///
/// # Returns
///
/// `{ signingPublicKey: Uint8Array, signingPrivateKey: Uint8Array, credentialBytes: Uint8Array }`
#[wasm_bindgen(js_name = "generateCredential")]
pub fn wasm_generate_credential(identity: &str) -> Result<JsValue, JsValue> {
    credential::generate_credential(identity)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(|out| {
            serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
        })
}

/// Generate an MLS KeyPackage from an existing credential.
///
/// # Returns
///
/// `{ keyPackageBytes: Uint8Array, privateKeyBytes: Uint8Array, hashRefBytes: Uint8Array }`
#[wasm_bindgen(js_name = "generateKeyPackage")]
pub fn wasm_generate_key_package(
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    key_package::generate_key_package(signing_private_key, signing_public_key, credential_bytes)
        .map_err(|e| JsValue::from_str(&e))
        .and_then(|out| {
            serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
        })
}

// ---------------------------------------------------------------------------
// M.2 exports — group lifecycle (WASM only)
// ---------------------------------------------------------------------------
//
// Each function:
// 1. Reconstructs the signer + credential from the provided key bytes.
// 2. Creates a JsProvider (JsStorageProvider + RustCrypto) which bridges
//    to window.mlsStorageBridge.{writeBytes, readBytes, deleteBytes}.
// 3. Delegates to the corresponding crate::group function.
// 4. Returns a serde-serialized JsValue with the operation result.
//
// Epoch is included in all mutating results so JS can track state.
// No groupStateBytes are returned — state lives in IndexedDB via the provider.

use crate::group;
use crate::storage_bridge::JsProvider;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::Serialize;

use crate::credential::CIPHERSUITE;

// ---------------------------------------------------------------------------
// Shared helper types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupInfoResult {
    group_info_bytes: Vec<u8>,
    epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitResult {
    commit_bytes: Vec<u8>,
    group_info_bytes: Vec<u8>,
    epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitAndWelcomeResult {
    commit_bytes: Vec<u8>,
    welcome_bytes: Vec<u8>,
    group_info_bytes: Vec<u8>,
    epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageResult {
    message_bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessedResult {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<Vec<u8>>,
    epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinExternalResult {
    commit_bytes: Vec<u8>,
    epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaveGroupResult {
    proposal_bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportGroupInfoResult {
    group_info_bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MergePendingCommitResult {
    group_info_bytes: Vec<u8>,
    epoch: u64,
}

// ---------------------------------------------------------------------------
// Signer reconstruction helper
// ---------------------------------------------------------------------------

fn make_wasm_signer(signing_private_key: &[u8], signing_public_key: &[u8]) -> SignatureKeyPair {
    let seed = if signing_private_key.len() >= 32 {
        &signing_private_key[..32]
    } else {
        signing_private_key
    };
    SignatureKeyPair::from_raw(CIPHERSUITE.into(), seed.to_vec(), signing_public_key.to_vec())
}

fn make_wasm_credential_with_key(
    credential_bytes: &[u8],
    signing_public_key: &[u8],
) -> Result<CredentialWithKey, JsValue> {
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let credential = {
        let mut slice = credential_bytes;
        Credential::tls_deserialize(&mut slice)
            .map_err(|e| JsValue::from_str(&format!("Credential TLS deserialize failed: {e}")))?
    };
    Ok(CredentialWithKey {
        credential,
        signature_key: signing_public_key.to_vec().into(),
    })
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn err_js(msg: String) -> JsValue {
    JsValue::from_str(&msg)
}

// ---------------------------------------------------------------------------
// createGroup
// ---------------------------------------------------------------------------

/// Create a new MLS group for the given channel.
///
/// Group state is auto-persisted to IndexedDB via `window.mlsStorageBridge`.
///
/// # Arguments
///
/// - `channel_id_bytes`: raw channel UUID bytes (used as the MLS group ID)
/// - `signing_private_key`: 64-byte key from `generateCredential`
/// - `signing_public_key`: 32-byte key from `generateCredential`
/// - `credential_bytes`: TLS-serialized credential from `generateCredential`
///
/// # Returns
///
/// `{ groupInfoBytes: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "createGroup")]
pub fn wasm_create_group(
    channel_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);
    let cwk = make_wasm_credential_with_key(credential_bytes, signing_public_key)?;

    let group_info_bytes = group::create_group(&provider, &signer, cwk, channel_id_bytes)
        .map_err(err_js)?;

    let epoch = group::get_group_epoch(&provider, channel_id_bytes)
        .map_err(err_js)?;

    to_js(&GroupInfoResult { group_info_bytes, epoch })
}

// ---------------------------------------------------------------------------
// joinGroupExternal
// ---------------------------------------------------------------------------

/// Join an MLS group via External Commit (no coordinator needed).
///
/// # Arguments
///
/// - `group_info_bytes`: TLS-serialized GroupInfo from server GET
/// - `signing_private_key`: 64-byte key from `generateCredential`
/// - `signing_public_key`: 32-byte key from `generateCredential`
/// - `credential_bytes`: TLS-serialized credential from `generateCredential`
///
/// # Returns
///
/// `{ commitBytes: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "joinGroupExternal")]
pub fn wasm_join_group_external(
    group_info_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);
    let cwk = make_wasm_credential_with_key(credential_bytes, signing_public_key)?;

    let commit_bytes =
        group::join_group_external(&provider, &signer, cwk, group_info_bytes).map_err(err_js)?;

    // After External Commit, the group is stored; load epoch from the group_id embedded in GroupInfo.
    // The group_id is the channel_id_bytes used at creation — parse from GroupInfo.
    // Since we don't know channel_id here, we return epoch 0 (server will track epoch via commit).
    // The JS side must query the server for the current epoch after the External Commit is accepted.
    // This is consistent with the M.2 design: server is authoritative on epoch for External Commits.
    let epoch = 0u64; // External Commit epoch is determined by the server; JS syncs from server ACK.

    to_js(&JoinExternalResult { commit_bytes, epoch })
}

// ---------------------------------------------------------------------------
// addMembers
// ---------------------------------------------------------------------------

/// Add one or more members to an existing group.
///
/// # Arguments
///
/// - `group_id_bytes`: raw channel UUID bytes (MLS group ID)
/// - `signing_private_key`, `signing_public_key`, `credential_bytes`: identity
/// - `key_packages_bytes_json`: JSON array of base64-encoded KeyPackage bytes
///
/// # Returns
///
/// `{ commitBytes: Uint8Array, welcomeBytes: Uint8Array, groupInfoBytes: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "addMembers")]
pub fn wasm_add_members(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
    key_packages_bytes_json: &str,
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    // Parse JSON array of base64-encoded KeyPackage bytes.
    let kp_b64_list: Vec<String> = serde_json::from_str(key_packages_bytes_json)
        .map_err(|e| err_js(format!("keyPackagesBytesJson parse failed: {e}")))?;

    let kp_bytes_list: Vec<Vec<u8>> = kp_b64_list
        .iter()
        .enumerate()
        .map(|(i, b64)| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| err_js(format!("KeyPackage[{i}] base64 decode failed: {e}")))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let (commit_bytes, welcome_bytes, group_info_bytes) =
        group::add_members(&provider, &signer, group_id_bytes, &kp_bytes_list)
            .map_err(err_js)?;

    let epoch = group::get_group_epoch(&provider, group_id_bytes).map_err(err_js)?;

    to_js(&CommitAndWelcomeResult {
        commit_bytes,
        welcome_bytes,
        group_info_bytes,
        epoch,
    })
}

// ---------------------------------------------------------------------------
// createMessage
// ---------------------------------------------------------------------------

/// Encrypt a plaintext message for the channel MLS group.
///
/// CRITICAL: Store plaintext in local cache BEFORE calling — sender cannot
/// decrypt their own ciphertext after this call (forward secrecy).
///
/// # Returns
///
/// `{ messageBytes: Uint8Array }`
#[wasm_bindgen(js_name = "createMessage")]
pub fn wasm_create_message(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    let message_bytes =
        group::create_message(&provider, &signer, group_id_bytes, plaintext).map_err(err_js)?;

    to_js(&MessageResult { message_bytes })
}

// ---------------------------------------------------------------------------
// processMessage
// ---------------------------------------------------------------------------

/// Process an incoming MLS message (application, commit, or proposal).
///
/// # Returns
///
/// `{ type: "application"|"commit"|"proposal", plaintext?: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "processMessage")]
pub fn wasm_process_message(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
    message_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    let result = group::process_message(&provider, &signer, group_id_bytes, message_bytes)
        .map_err(err_js)?;

    let epoch = group::get_group_epoch(&provider, group_id_bytes).map_err(err_js)?;

    let processed = match result {
        group::ProcessedMessageResult::ApplicationMessage(plaintext) => ProcessedResult {
            msg_type: "application".into(),
            plaintext: Some(plaintext),
            epoch,
        },
        group::ProcessedMessageResult::StagedCommit => ProcessedResult {
            msg_type: "commit".into(),
            plaintext: None,
            epoch,
        },
        group::ProcessedMessageResult::Proposal => ProcessedResult {
            msg_type: "proposal".into(),
            plaintext: None,
            epoch,
        },
    };

    to_js(&processed)
}

// ---------------------------------------------------------------------------
// removeMembers
// ---------------------------------------------------------------------------

/// Remove one or more members from the group by their identity bytes.
///
/// # Arguments
///
/// - `member_identities_json`: JSON array of base64-encoded identity byte strings
///
/// # Returns
///
/// `{ commitBytes: Uint8Array, groupInfoBytes: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "removeMembers")]
pub fn wasm_remove_members(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
    member_identities_json: &str,
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    // Parse JSON array of base64-encoded identity bytes.
    let id_b64_list: Vec<String> = serde_json::from_str(member_identities_json)
        .map_err(|e| err_js(format!("memberIdentitiesJson parse failed: {e}")))?;

    let id_bytes_list: Vec<Vec<u8>> = id_b64_list
        .iter()
        .enumerate()
        .map(|(i, b64)| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| err_js(format!("MemberIdentity[{i}] base64 decode failed: {e}")))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let (commit_bytes, group_info_bytes) =
        group::remove_members(&provider, &signer, group_id_bytes, &id_bytes_list)
            .map_err(err_js)?;

    let epoch = group::get_group_epoch(&provider, group_id_bytes).map_err(err_js)?;

    to_js(&CommitResult {
        commit_bytes,
        group_info_bytes,
        epoch,
    })
}

// ---------------------------------------------------------------------------
// selfUpdate
// ---------------------------------------------------------------------------

/// Rotate own HPKE key for post-compromise security.
///
/// # Returns
///
/// `{ commitBytes: Uint8Array, groupInfoBytes: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "selfUpdate")]
pub fn wasm_self_update(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    let (commit_bytes, group_info_bytes) =
        group::self_update(&provider, &signer, group_id_bytes).map_err(err_js)?;

    let epoch = group::get_group_epoch(&provider, group_id_bytes).map_err(err_js)?;

    to_js(&CommitResult {
        commit_bytes,
        group_info_bytes,
        epoch,
    })
}

// ---------------------------------------------------------------------------
// leaveGroup
// ---------------------------------------------------------------------------

/// Send a self-remove proposal (another member must commit it).
///
/// # Returns
///
/// `{ proposalBytes: Uint8Array }`
#[wasm_bindgen(js_name = "leaveGroup")]
pub fn wasm_leave_group(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    let proposal_bytes =
        group::leave_group(&provider, &signer, group_id_bytes).map_err(err_js)?;

    to_js(&LeaveGroupResult { proposal_bytes })
}

// ---------------------------------------------------------------------------
// mergePendingCommit
// ---------------------------------------------------------------------------

/// Merge the pending commit after server ACK.
///
/// Call after the server returns 200/204 for a commit POST.
///
/// # Returns
///
/// `{ groupInfoBytes: Uint8Array, epoch: number }`
#[wasm_bindgen(js_name = "mergePendingCommit")]
pub fn wasm_merge_pending_commit(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    group::merge_pending_commit(&provider, group_id_bytes).map_err(err_js)?;

    let group_info_bytes =
        group::export_group_info(&provider, &signer, group_id_bytes).map_err(err_js)?;
    let epoch = group::get_group_epoch(&provider, group_id_bytes).map_err(err_js)?;

    to_js(&MergePendingCommitResult {
        group_info_bytes,
        epoch,
    })
}

// ---------------------------------------------------------------------------
// exportGroupInfo
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// exportVoiceFrameKey (M.3)
// ---------------------------------------------------------------------------

/// Derive a 32-byte AES-256-GCM frame key from the current MLS voice group epoch.
///
/// This is a pure derivation — no state mutation. The key is deterministic for a
/// given group at a given epoch. Calling it twice returns the same bytes.
/// After an epoch-advancing commit the key changes, providing automatic forward
/// secrecy for voice frame encryption.
///
/// The `signing_private_key`, `signing_public_key`, and `credential_bytes` parameters
/// are accepted for API consistency with other WASM exports. `export_secret` does
/// not require the signer — these are unused inside this call but callers pass them
/// to maintain a uniform WASM call signature.
///
/// # Arguments
///
/// - `group_id_bytes`: raw voice group ID bytes
/// - `signing_private_key`: 64-byte key from `generateCredential` (unused, kept for consistency)
/// - `signing_public_key`: 32-byte key from `generateCredential` (unused, kept for consistency)
/// - `credential_bytes`: TLS-serialized credential (unused, kept for consistency)
///
/// # Returns
///
/// `{ frameKeyBytes: Uint8Array(32), epoch: number }`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportVoiceKeyResult {
    frame_key_bytes: Vec<u8>,
    epoch: u64,
}

#[wasm_bindgen(js_name = "exportVoiceFrameKey")]
pub fn wasm_export_voice_frame_key(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    // Suppress unused-parameter warnings — these params exist for API consistency
    // with other WASM exports; export_secret does not require the signer.
    let _ = (signing_private_key, signing_public_key, credential_bytes);

    let provider = JsProvider::default();
    let frame_key_bytes = group::export_voice_frame_key(&provider, group_id_bytes)
        .map_err(err_js)?;
    let epoch = group::get_group_epoch(&provider, group_id_bytes).map_err(err_js)?;
    to_js(&ExportVoiceKeyResult { frame_key_bytes, epoch })
}

// ---------------------------------------------------------------------------
// exportGroupInfo
// ---------------------------------------------------------------------------

/// Re-export current GroupInfo (call after merging a commit, PUT to server).
///
/// # Returns
///
/// `{ groupInfoBytes: Uint8Array }`
#[wasm_bindgen(js_name = "exportGroupInfo")]
pub fn wasm_export_group_info(
    group_id_bytes: &[u8],
    signing_private_key: &[u8],
    signing_public_key: &[u8],
    credential_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let provider = JsProvider::default();
    let signer = make_wasm_signer(signing_private_key, signing_public_key);

    let group_info_bytes =
        group::export_group_info(&provider, &signer, group_id_bytes).map_err(err_js)?;

    to_js(&ExportGroupInfoResult { group_info_bytes })
}
