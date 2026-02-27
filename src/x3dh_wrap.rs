//! X3DH key agreement: initiator (Alice) and responder (Bob) flows.

use libsignal_dezire::ratchet::{init_receiver_state, init_sender_state};
use libsignal_dezire::x3dh::{x3dh_initiator, x3dh_responder, OneTimePreKey, PreKeyBundle, SignedPreKey};
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::session::SessionState;

/// Server bundle format (matches GET /api/keys/:userId/:deviceId response).
/// JS normalizes Go's camelCase + base64 to snake_case + arrays before passing here.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ServerBundle {
    pub identity_key: Vec<u8>,
    pub signed_pre_key: Vec<u8>,
    pub signed_pre_key_signature: Vec<u8>,
    pub registration_id: u32,
    #[serde(default)]
    pub one_time_pre_key_id: Option<u32>,
    #[serde(default)]
    pub one_time_pre_key: Option<Vec<u8>>,
}

/// Result of X3DH initiator: session state + metadata for the initial message envelope.
pub struct X3DHInitiatorResult {
    pub state: SessionState,
    pub ephemeral_public: Vec<u8>,
    pub used_opk_id: Option<u32>,
}

fn try_array_33(v: &[u8]) -> Result<[u8; 33], ()> {
    if v.len() != 33 {
        return Err(());
    }
    let mut a = [0u8; 33];
    a.copy_from_slice(v);
    Ok(a)
}

fn try_array_96(v: &[u8]) -> Result<[u8; 96], ()> {
    if v.len() != 96 {
        return Err(());
    }
    let mut a = [0u8; 96];
    a.copy_from_slice(v);
    Ok(a)
}

fn try_array_32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into().map_err(|_| format!("expected 32 bytes, got {}", v.len()))
}

/// Performs X3DH as initiator (Alice): takes server bundle and our identity private key,
/// returns session state + ephemeral public key (for the initial message envelope).
pub fn perform_x3dh(
    server_bundle_json: &str,
    identity_private: &[u8],
) -> Result<X3DHInitiatorResult, String> {
    let server: ServerBundle =
        serde_json::from_str(server_bundle_json).map_err(|e| e.to_string())?;
    let identity_key: [u8; 32] = try_array_32(identity_private)?;

    let signed_prekey = SignedPreKey {
        id: 1,
        public_key: try_array_33(&server.signed_pre_key)
            .map_err(|_| "signed_pre_key must be 33 bytes")?,
        signature: try_array_96(&server.signed_pre_key_signature)
            .map_err(|_| "signed_pre_key_signature must be 96 bytes")?,
    };
    let one_time = server.one_time_pre_key_id.and_then(|id| {
        server.one_time_pre_key.as_ref().and_then(|pk| {
            try_array_33(pk)
                .ok()
                .map(|public_key| OneTimePreKey { id, public_key })
        })
    });
    let used_opk_id = one_time.as_ref().map(|otk| otk.id);

    let bundle = PreKeyBundle {
        identity_key: try_array_33(&server.identity_key)
            .map_err(|_| "identity_key must be 33 bytes")?,
        signed_prekey,
        one_time_prekey: one_time,
    };

    let result =
        x3dh_initiator(&identity_key, &bundle).map_err(|e| format!("x3dh_initiator: {:?}", e))?;

    // Use Bob's SPK as the receiver DH public key for init_sender_state (NOT the ephemeral key).
    let bob_spk_decoded = libsignal_dezire::utils::decode_public_key(
        &try_array_33(&server.signed_pre_key).map_err(|_| "signed_pre_key must be 33 bytes")?,
    )
    .map_err(|_| "decode signed_pre_key")?;

    let state = init_sender_state(result.shared_secret, PublicKey::from(bob_spk_decoded))
        .map_err(|e| format!("init_sender_state: {:?}", e))?;
    let state_bytes = serde_json::to_vec(&state).map_err(|e| e.to_string())?;

    Ok(X3DHInitiatorResult {
        state: SessionState { state_bytes },
        ephemeral_public: result.ephemeral_public.to_vec(),
        used_opk_id,
    })
}

/// Performs X3DH as responder (Bob): takes Alice's initial message keys and Bob's private keys,
/// returns session state for encrypt/decrypt.
pub fn perform_x3dh_responder(
    identity_private: &[u8],
    spk_private: &[u8],
    spk_public: &[u8],
    opk_private: Option<&[u8]>,
    alice_identity_public: &[u8],
    alice_ephemeral_public: &[u8],
) -> Result<SessionState, String> {
    let ik_priv: [u8; 32] = try_array_32(identity_private)?;
    let spk_priv: [u8; 32] = try_array_32(spk_private)?;
    let alice_ik: [u8; 33] =
        try_array_33(alice_identity_public).map_err(|_| "alice_identity_public must be 33 bytes")?;
    let alice_ek: [u8; 33] = try_array_33(alice_ephemeral_public)
        .map_err(|_| "alice_ephemeral_public must be 33 bytes")?;

    let opk_priv_arr: Option<[u8; 32]> = opk_private
        .map(|v| try_array_32(v))
        .transpose()?;

    let shared_secret = x3dh_responder(
        &ik_priv,
        &spk_priv,
        opk_priv_arr.as_ref(),
        &alice_ik,
        &alice_ek,
    )
    .map_err(|e| format!("x3dh_responder: {:?}", e))?;

    // Build the ratchet KeyPair for Bob's SPK: (StaticSecret, PublicKey)
    let spk_secret = StaticSecret::from(spk_priv);
    let spk_pub_decoded = libsignal_dezire::utils::decode_public_key(
        &try_array_33(spk_public).map_err(|_| "spk_public must be 33 bytes")?,
    )
    .map_err(|_| "decode spk_public")?;

    let state = init_receiver_state(shared_secret, (spk_secret, PublicKey::from(spk_pub_decoded)));
    let state_bytes = serde_json::to_vec(&state).map_err(|e| e.to_string())?;

    Ok(SessionState { state_bytes })
}
