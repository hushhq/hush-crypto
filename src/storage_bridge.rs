//! StorageProvider bridge for MLS group state persistence.
//!
//! # Native builds
//!
//! `new_native_provider()` returns `OpenMlsRustCrypto` — the standard in-memory
//! provider used in integration tests.  Group state is heap-allocated and lost
//! when the provider is dropped.
//!
//! # WASM builds
//!
//! `JsStorageProvider` implements `StorageProvider` by calling synchronous JS
//! callbacks exposed on `window.mlsStorageBridge`.  The JS side is expected to
//! maintain a write-back cache (a synchronous `Map`) that is flushed to IndexedDB
//! asynchronously after each WASM call returns.  This is the standard pattern for
//! bridging OpenMLS's synchronous trait to IndexedDB's async API.
//!
//! The `JsProvider` wrapper implements `OpenMlsProvider` by combining
//! `JsStorageProvider` (storage) with `openmls_rust_crypto::RustCrypto` (crypto + rand).

// ---------------------------------------------------------------------------
// Native
// ---------------------------------------------------------------------------

/// Returns a fresh in-memory provider for use in native tests.
///
/// The returned value satisfies `OpenMlsProvider` through the blanket impl
/// provided by `openmls_rust_crypto`.
#[cfg(not(target_arch = "wasm32"))]
pub fn new_native_provider() -> openmls_rust_crypto::OpenMlsRustCrypto {
    openmls_rust_crypto::OpenMlsRustCrypto::default()
}

// ---------------------------------------------------------------------------
// WASM — JS-callback bridge
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod wasm_bridge {
    use js_sys::Uint8Array;
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::storage::{traits, CURRENT_VERSION, StorageProvider};
    use openmls_traits::OpenMlsProvider;
    use serde_json;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsValue;

    // -----------------------------------------------------------------------
    // JS-side imports
    // All three functions are synchronous from Rust's perspective.
    // The JS side uses a sync Map cache that flushes to IndexedDB on
    // the microtask boundary after each WASM call returns.
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    extern "C" {
        /// Write `value` bytes to `store_name` under the composite `key`.
        #[wasm_bindgen(js_namespace = mlsStorageBridge, catch)]
        fn writeBytes(store_name: &str, key: &[u8], value: &[u8]) -> Result<(), JsValue>;

        /// Read bytes from `store_name` for `key`.
        /// Returns a `Uint8Array` if the key exists, or `null` / `undefined` otherwise.
        #[wasm_bindgen(js_namespace = mlsStorageBridge, catch)]
        fn readBytes(store_name: &str, key: &[u8]) -> Result<JsValue, JsValue>;

        /// Delete the entry for `key` from `store_name`.
        #[wasm_bindgen(js_namespace = mlsStorageBridge, catch)]
        fn deleteBytes(store_name: &str, key: &[u8]) -> Result<(), JsValue>;

        /// Read a list of byte sequences from `store_name` for `key`.
        /// Returns a JS array of `Uint8Array`, or an empty array.
        #[wasm_bindgen(js_namespace = mlsStorageBridge, catch)]
        fn readList(store_name: &str, key: &[u8]) -> Result<JsValue, JsValue>;

        /// Append `value` to a list stored under `key` in `store_name`.
        #[wasm_bindgen(js_namespace = mlsStorageBridge, catch)]
        fn appendToList(store_name: &str, key: &[u8], value: &[u8]) -> Result<(), JsValue>;

        /// Remove a specific `value` from the list stored under `key` in `store_name`.
        #[wasm_bindgen(js_namespace = mlsStorageBridge, catch)]
        fn removeFromList(store_name: &str, key: &[u8], value: &[u8]) -> Result<(), JsValue>;
    }

    // -----------------------------------------------------------------------
    // Error type
    // -----------------------------------------------------------------------

    #[derive(Debug)]
    pub struct JsStorageError(String);

    impl std::fmt::Display for JsStorageError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "JsStorageError: {}", self.0)
        }
    }

    impl std::error::Error for JsStorageError {}

    impl From<JsValue> for JsStorageError {
        fn from(v: JsValue) -> Self {
            JsStorageError(
                v.as_string()
                    .unwrap_or_else(|| format!("{:?}", v)),
            )
        }
    }

    impl From<serde_json::Error> for JsStorageError {
        fn from(e: serde_json::Error) -> Self {
            JsStorageError(e.to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Store name constants — each maps to an IndexedDB object store
    // -----------------------------------------------------------------------

    const STORE_KEY_PACKAGES: &str = "mls_key_packages";
    const STORE_PSK: &str = "mls_psk";
    const STORE_ENCRYPTION_KEY_PAIRS: &str = "mls_encryption_key_pairs";
    const STORE_EPOCH_KEY_PAIRS: &str = "mls_epoch_key_pairs";
    const STORE_SIGNATURE_KEY_PAIRS: &str = "mls_signature_key_pairs";
    const STORE_TREE_SYNC: &str = "mls_tree_sync";
    const STORE_GROUP_CONTEXT: &str = "mls_group_context";
    const STORE_INTERIM_TRANSCRIPT_HASH: &str = "mls_interim_transcript_hash";
    const STORE_CONFIRMATION_TAG: &str = "mls_confirmation_tag";
    const STORE_JOIN_CONFIG: &str = "mls_join_config";
    const STORE_OWN_LEAF_NODES: &str = "mls_own_leaf_nodes";
    const STORE_GROUP_STATE: &str = "mls_group_state";
    const STORE_QUEUED_PROPOSALS: &str = "mls_queued_proposals";
    const STORE_PROPOSAL_QUEUE_REFS: &str = "mls_proposal_queue_refs";
    const STORE_OWN_LEAF_INDEX: &str = "mls_own_leaf_index";
    const STORE_EPOCH_SECRETS: &str = "mls_epoch_secrets";
    const STORE_RESUMPTION_PSK: &str = "mls_resumption_psk";
    const STORE_MESSAGE_SECRETS: &str = "mls_message_secrets";

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Serialize a key to JSON bytes, then prepend the VERSION as a 2-byte
    /// big-endian prefix so keys from different StorageProvider versions are
    /// never confused.
    fn make_key<K: serde::Serialize>(key: &K) -> Result<Vec<u8>, JsStorageError> {
        let mut out = CURRENT_VERSION.to_be_bytes().to_vec();
        out.extend(serde_json::to_vec(key)?);
        Ok(out)
    }

    fn js_write<K: serde::Serialize, V: serde::Serialize>(
        store: &str,
        key: &K,
        value: &V,
    ) -> Result<(), JsStorageError> {
        let k = make_key(key)?;
        let v = serde_json::to_vec(value)?;
        writeBytes(store, &k, &v).map_err(JsStorageError::from)
    }

    fn js_read<K: serde::Serialize, V: serde::de::DeserializeOwned>(
        store: &str,
        key: &K,
    ) -> Result<Option<V>, JsStorageError> {
        let k = make_key(key)?;
        let js_val = readBytes(store, &k).map_err(JsStorageError::from)?;
        if js_val.is_null() || js_val.is_undefined() {
            return Ok(None);
        }
        let bytes = Uint8Array::from(js_val).to_vec();
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    fn js_delete<K: serde::Serialize>(store: &str, key: &K) -> Result<(), JsStorageError> {
        let k = make_key(key)?;
        deleteBytes(store, &k).map_err(JsStorageError::from)
    }

    fn js_read_list<K: serde::Serialize, V: serde::de::DeserializeOwned>(
        store: &str,
        key: &K,
    ) -> Result<Vec<V>, JsStorageError> {
        let k = make_key(key)?;
        let js_val = readList(store, &k).map_err(JsStorageError::from)?;
        if js_val.is_null() || js_val.is_undefined() {
            return Ok(vec![]);
        }
        let arr = js_sys::Array::from(&js_val);
        let mut result = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            let item = arr.get(i);
            let bytes = Uint8Array::from(item).to_vec();
            let v: V = serde_json::from_slice(&bytes)?;
            result.push(v);
        }
        Ok(result)
    }

    fn js_append_to_list<K: serde::Serialize, V: serde::Serialize>(
        store: &str,
        key: &K,
        value: &V,
    ) -> Result<(), JsStorageError> {
        let k = make_key(key)?;
        let v = serde_json::to_vec(value)?;
        appendToList(store, &k, &v).map_err(JsStorageError::from)
    }

    fn js_remove_from_list<K: serde::Serialize, V: serde::Serialize>(
        store: &str,
        key: &K,
        value: &V,
    ) -> Result<(), JsStorageError> {
        let k = make_key(key)?;
        let v = serde_json::to_vec(value)?;
        removeFromList(store, &k, &v).map_err(JsStorageError::from)
    }

    // -----------------------------------------------------------------------
    // JsStorageProvider struct
    // -----------------------------------------------------------------------

    /// WASM storage provider backed by JS callbacks to `window.mlsStorageBridge`.
    #[derive(Default)]
    pub struct JsStorageProvider;

    impl StorageProvider<CURRENT_VERSION> for JsStorageProvider {
        type Error = JsStorageError;

        // --- Group state writes ---

        fn write_mls_join_config<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            config: &MlsGroupJoinConfig,
        ) -> Result<(), Self::Error> {
            js_write(STORE_JOIN_CONFIG, group_id, config)
        }

        fn append_own_leaf_node<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNode: traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            leaf_node: &LeafNode,
        ) -> Result<(), Self::Error> {
            js_append_to_list(STORE_OWN_LEAF_NODES, group_id, leaf_node)
        }

        fn queue_proposal<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
            proposal: &QueuedProposal,
        ) -> Result<(), Self::Error> {
            // Write proposal keyed by (group_id, proposal_ref)
            let compound_key = (group_id, proposal_ref);
            js_write(STORE_QUEUED_PROPOSALS, &compound_key, proposal)?;
            // Append proposal_ref to the per-group list
            js_append_to_list(STORE_PROPOSAL_QUEUE_REFS, group_id, proposal_ref)
        }

        fn write_tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            TreeSync: traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            tree: &TreeSync,
        ) -> Result<(), Self::Error> {
            js_write(STORE_TREE_SYNC, group_id, tree)
        }

        fn write_interim_transcript_hash<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            interim_transcript_hash: &InterimTranscriptHash,
        ) -> Result<(), Self::Error> {
            js_write(STORE_INTERIM_TRANSCRIPT_HASH, group_id, interim_transcript_hash)
        }

        fn write_context<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupContext: traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_context: &GroupContext,
        ) -> Result<(), Self::Error> {
            js_write(STORE_GROUP_CONTEXT, group_id, group_context)
        }

        fn write_confirmation_tag<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            confirmation_tag: &ConfirmationTag,
        ) -> Result<(), Self::Error> {
            js_write(STORE_CONFIRMATION_TAG, group_id, confirmation_tag)
        }

        fn write_group_state<
            GroupState: traits::GroupState<CURRENT_VERSION>,
            GroupId: traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_state: &GroupState,
        ) -> Result<(), Self::Error> {
            js_write(STORE_GROUP_STATE, group_id, group_state)
        }

        fn write_message_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            message_secrets: &MessageSecrets,
        ) -> Result<(), Self::Error> {
            js_write(STORE_MESSAGE_SECRETS, group_id, message_secrets)
        }

        fn write_resumption_psk_store<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            resumption_psk_store: &ResumptionPskStore,
        ) -> Result<(), Self::Error> {
            js_write(STORE_RESUMPTION_PSK, group_id, resumption_psk_store)
        }

        fn write_own_leaf_index<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            own_leaf_index: &LeafNodeIndex,
        ) -> Result<(), Self::Error> {
            js_write(STORE_OWN_LEAF_INDEX, group_id, own_leaf_index)
        }

        fn write_group_epoch_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epoch_secrets: &GroupEpochSecrets,
        ) -> Result<(), Self::Error> {
            js_write(STORE_EPOCH_SECRETS, group_id, group_epoch_secrets)
        }

        // --- Crypto object writes ---

        fn write_signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
            signature_key_pair: &SignatureKeyPair,
        ) -> Result<(), Self::Error> {
            js_write(STORE_SIGNATURE_KEY_PAIRS, public_key, signature_key_pair)
        }

        fn write_encryption_key_pair<
            EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
            key_pair: &HpkeKeyPair,
        ) -> Result<(), Self::Error> {
            js_write(STORE_ENCRYPTION_KEY_PAIRS, public_key, key_pair)
        }

        fn write_encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
            key_pairs: &[HpkeKeyPair],
        ) -> Result<(), Self::Error> {
            let compound_key = (group_id, epoch, leaf_index);
            js_write(STORE_EPOCH_KEY_PAIRS, &compound_key, &key_pairs.to_vec())
        }

        fn write_key_package<
            HashReference: traits::HashReference<CURRENT_VERSION>,
            KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &HashReference,
            key_package: &KeyPackage,
        ) -> Result<(), Self::Error> {
            js_write(STORE_KEY_PACKAGES, hash_ref, key_package)
        }

        fn write_psk<
            PskId: traits::PskId<CURRENT_VERSION>,
            PskBundle: traits::PskBundle<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
            psk: &PskBundle,
        ) -> Result<(), Self::Error> {
            js_write(STORE_PSK, psk_id, psk)
        }

        // --- Group state reads ---

        fn mls_group_join_config<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
            js_read(STORE_JOIN_CONFIG, group_id)
        }

        fn own_leaf_nodes<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNode: traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<LeafNode>, Self::Error> {
            js_read_list(STORE_OWN_LEAF_NODES, group_id)
        }

        fn queued_proposal_refs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<ProposalRef>, Self::Error> {
            js_read_list(STORE_PROPOSAL_QUEUE_REFS, group_id)
        }

        fn queued_proposals<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
            let refs: Vec<ProposalRef> = self.queued_proposal_refs(group_id)?;
            refs.into_iter()
                .map(|proposal_ref| {
                    let compound_key = (group_id, &proposal_ref);
                    let proposal: QueuedProposal = js_read(STORE_QUEUED_PROPOSALS, &compound_key)?
                        .ok_or_else(|| JsStorageError("proposal not found".into()))?;
                    Ok((proposal_ref, proposal))
                })
                .collect()
        }

        fn tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            TreeSync: traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<TreeSync>, Self::Error> {
            js_read(STORE_TREE_SYNC, group_id)
        }

        fn group_context<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupContext: traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupContext>, Self::Error> {
            js_read(STORE_GROUP_CONTEXT, group_id)
        }

        fn interim_transcript_hash<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
            js_read(STORE_INTERIM_TRANSCRIPT_HASH, group_id)
        }

        fn confirmation_tag<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ConfirmationTag>, Self::Error> {
            js_read(STORE_CONFIRMATION_TAG, group_id)
        }

        fn group_state<
            GroupState: traits::GroupState<CURRENT_VERSION>,
            GroupId: traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupState>, Self::Error> {
            js_read(STORE_GROUP_STATE, group_id)
        }

        fn message_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MessageSecrets>, Self::Error> {
            js_read(STORE_MESSAGE_SECRETS, group_id)
        }

        fn resumption_psk_store<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ResumptionPskStore>, Self::Error> {
            js_read(STORE_RESUMPTION_PSK, group_id)
        }

        fn own_leaf_index<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<LeafNodeIndex>, Self::Error> {
            js_read(STORE_OWN_LEAF_INDEX, group_id)
        }

        fn group_epoch_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
            js_read(STORE_EPOCH_SECRETS, group_id)
        }

        // --- Crypto object reads ---

        fn signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
        ) -> Result<Option<SignatureKeyPair>, Self::Error> {
            js_read(STORE_SIGNATURE_KEY_PAIRS, public_key)
        }

        fn encryption_key_pair<
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
            EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<Option<HpkeKeyPair>, Self::Error> {
            js_read(STORE_ENCRYPTION_KEY_PAIRS, public_key)
        }

        fn encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
        ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
            let compound_key = (group_id, epoch, leaf_index);
            Ok(js_read::<_, Vec<HpkeKeyPair>>(STORE_EPOCH_KEY_PAIRS, &compound_key)?
                .unwrap_or_default())
        }

        fn key_package<
            KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
            KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<KeyPackage>, Self::Error> {
            js_read(STORE_KEY_PACKAGES, hash_ref)
        }

        fn psk<
            PskBundle: traits::PskBundle<CURRENT_VERSION>,
            PskId: traits::PskId<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
        ) -> Result<Option<PskBundle>, Self::Error> {
            js_read(STORE_PSK, psk_id)
        }

        // --- Group state deletes ---

        fn remove_proposal<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
        ) -> Result<(), Self::Error> {
            // Remove from per-group list
            js_remove_from_list(STORE_PROPOSAL_QUEUE_REFS, group_id, proposal_ref)?;
            // Delete the proposal itself
            let compound_key = (group_id, proposal_ref);
            js_delete(STORE_QUEUED_PROPOSALS, &compound_key)
        }

        fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_OWN_LEAF_NODES, group_id)
        }

        fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_JOIN_CONFIG, group_id)
        }

        fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_TREE_SYNC, group_id)
        }

        fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_CONFIRMATION_TAG, group_id)
        }

        fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_GROUP_STATE, group_id)
        }

        fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_GROUP_CONTEXT, group_id)
        }

        fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_INTERIM_TRANSCRIPT_HASH, group_id)
        }

        fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_MESSAGE_SECRETS, group_id)
        }

        fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_RESUMPTION_PSK, group_id)
        }

        fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_OWN_LEAF_INDEX, group_id)
        }

        fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_EPOCH_SECRETS, group_id)
        }

        fn clear_proposal_queue<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            // Delete all individual proposals, then clear the refs list
            let refs: Vec<ProposalRef> = self.queued_proposal_refs(group_id)?;
            for proposal_ref in &refs {
                let compound_key = (group_id, proposal_ref);
                let _ = js_delete(STORE_QUEUED_PROPOSALS, &compound_key);
            }
            js_delete(STORE_PROPOSAL_QUEUE_REFS, group_id)
        }

        // --- Crypto object deletes ---

        fn delete_signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_SIGNATURE_KEY_PAIRS, public_key)
        }

        fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_ENCRYPTION_KEY_PAIRS, public_key)
        }

        fn delete_encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
        ) -> Result<(), Self::Error> {
            let compound_key = (group_id, epoch, leaf_index);
            js_delete(STORE_EPOCH_KEY_PAIRS, &compound_key)
        }

        fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_KEY_PACKAGES, hash_ref)
        }

        fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
            &self,
            psk_id: &PskKey,
        ) -> Result<(), Self::Error> {
            js_delete(STORE_PSK, psk_id)
        }
    }

    // -----------------------------------------------------------------------
    // JsProvider — combines JsStorageProvider with RustCrypto
    // -----------------------------------------------------------------------

    /// Full `OpenMlsProvider` backed by JS callbacks (storage) + RustCrypto (crypto/rand).
    ///
    /// Construct with `JsProvider::default()`.
    #[derive(Default)]
    pub struct JsProvider {
        crypto: RustCrypto,
        storage: JsStorageProvider,
    }

    impl OpenMlsProvider for JsProvider {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type StorageProvider = JsStorageProvider;

        fn storage(&self) -> &Self::StorageProvider {
            &self.storage
        }

        fn crypto(&self) -> &Self::CryptoProvider {
            &self.crypto
        }

        fn rand(&self) -> &Self::RandProvider {
            &self.crypto
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_bridge::{JsProvider, JsStorageProvider};
