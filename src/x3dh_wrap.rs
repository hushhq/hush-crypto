//! X3DH key agreement: build bundle from server response and perform initiator flow.

use libsignal_dezire::ratchet::init_sender_state;
use libsignal_dezire::x3dh::{x3dh_initiator, PreKeyBundle, SignedPreKey, OneTimePreKey};
use serde::{Deserialize, Serialize};

/// Server bundle format (matches GET /api/keys/:userId/:deviceId response).
#[derive(Deserialize)]
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

/// Result of X3DH: serializable session state for persistence.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub state_bytes: Vec<u8>,
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

/// Performs X3DH as initiator (Alice): takes server bundle and our identity private key,
/// returns session state for encrypt/decrypt.
pub fn perform_x3dh(
    server_bundle_json: &str,
    identity_private: &[u8],
) -> Result<SessionState, String> {
    let server: ServerBundle = serde_json::from_str(server_bundle_json).map_err(|e| e.to_string())?;
    if identity_private.len() != 32 {
        return Err("identity_private must be 32 bytes".into());
    }
    let identity_key: [u8; 32] = identity_private.try_into().map_err(|_| "identity_private len")?;

    let signed_prekey = SignedPreKey {
        id: 1,
        public_key: try_array_33(&server.signed_pre_key).map_err(|_| "signed_pre_key must be 33 bytes")?,
        signature: try_array_96(&server.signed_pre_key_signature).map_err(|_| "signed_pre_key_signature must be 96 bytes")?,
    };
    let one_time = server.one_time_pre_key_id.and_then(|id| {
        server.one_time_pre_key.as_ref().and_then(|pk| {
            try_array_33(pk).ok().map(|public_key| OneTimePreKey { id, public_key })
        })
    });
    let bundle = PreKeyBundle {
        identity_key: try_array_33(&server.identity_key).map_err(|_| "identity_key must be 33 bytes")?,
        signed_prekey,
        one_time_prekey: one_time,
    };

    let result = x3dh_initiator(&identity_key, &bundle).map_err(|e| format!("x3dh_initiator: {:?}", e))?;
    let receiver_public = libsignal_dezire::utils::decode_public_key(&result.ephemeral_public).map_err(|_| "decode receiver public")?;
    let state = init_sender_state(result.shared_secret, receiver_public.into()).map_err(|e| format!("init_sender_state: {:?}", e))?;
    let state_bytes = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
    Ok(SessionState { state_bytes })
}
