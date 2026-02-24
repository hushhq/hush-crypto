//! Double Ratchet encrypt/decrypt with serializable session state.

use libsignal_dezire::ratchet::RatchetState;
use serde::{Deserialize, Serialize};

/// Session state for persistence (IndexedDB).
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub state_bytes: Vec<u8>,
}

/// Encrypts plaintext; returns (ciphertext_with_header, updated_state_bytes).
pub fn encrypt(
    state_bytes: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut state: RatchetState = serde_json::from_slice(state_bytes).map_err(|e| e.to_string())?;
    let (header, ciphertext) = libsignal_dezire::ratchet::encrypt(&mut state, plaintext, associated_data).map_err(|e| format!("{:?}", e))?;
    let new_state = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok((out, new_state))
}

/// Decrypts ciphertext (header + body); returns (plaintext, updated_state_bytes).
pub fn decrypt(
    state_bytes: &[u8],
    ciphertext_with_header: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if ciphertext_with_header.len() < 64 {
        return Err("ciphertext too short".into());
    }
    let (header, ciphertext) = ciphertext_with_header.split_at(64);
    let mut state: RatchetState = serde_json::from_slice(state_bytes).map_err(|e| e.to_string())?;
    let plaintext = libsignal_dezire::ratchet::decrypt(&mut state, header, ciphertext, associated_data).map_err(|e| format!("{:?}", e))?;
    let new_state = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
    Ok((plaintext, new_state))
}
