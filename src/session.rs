//! Double Ratchet encrypt/decrypt with serializable session state.
//!
//! Wire format: [4 bytes: header_len LE][header bytes][ciphertext bytes]
//! This self-describing format avoids hardcoding the encrypted header size.

use libsignal_dezire::ratchet::RatchetState;
use serde::{Deserialize, Serialize};

/// Session state for persistence (IndexedDB).
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub state_bytes: Vec<u8>,
}

const HEADER_LEN_BYTES: usize = 4;

/// Encrypts plaintext; returns (wire_bytes, updated_state_bytes).
/// Wire format: [4: header_len LE][header][ciphertext]
pub fn encrypt(
    state_bytes: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut state: RatchetState =
        serde_json::from_slice(state_bytes).map_err(|e| e.to_string())?;
    let (header, ciphertext) =
        libsignal_dezire::ratchet::encrypt(&mut state, plaintext, associated_data)
            .map_err(|e| format!("{:?}", e))?;
    let new_state = serde_json::to_vec(&state).map_err(|e| e.to_string())?;

    let header_len = header.len() as u32;
    let mut out = Vec::with_capacity(HEADER_LEN_BYTES + header.len() + ciphertext.len());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok((out, new_state))
}

/// Decrypts wire bytes; returns (plaintext, updated_state_bytes).
/// Wire format: [4: header_len LE][header][ciphertext]
pub fn decrypt(
    state_bytes: &[u8],
    wire_bytes: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if wire_bytes.len() < HEADER_LEN_BYTES {
        return Err("wire bytes too short".into());
    }
    let header_len =
        u32::from_le_bytes(wire_bytes[..HEADER_LEN_BYTES].try_into().unwrap()) as usize;
    if wire_bytes.len() < HEADER_LEN_BYTES + header_len {
        return Err(format!(
            "wire bytes too short for header: need {} but got {}",
            HEADER_LEN_BYTES + header_len,
            wire_bytes.len()
        ));
    }
    let header = &wire_bytes[HEADER_LEN_BYTES..HEADER_LEN_BYTES + header_len];
    let ciphertext = &wire_bytes[HEADER_LEN_BYTES + header_len..];

    let mut state: RatchetState =
        serde_json::from_slice(state_bytes).map_err(|e| e.to_string())?;
    let plaintext =
        libsignal_dezire::ratchet::decrypt(&mut state, header, ciphertext, associated_data)
            .map_err(|e| format!("{:?}", e))?;
    let new_state = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
    Ok((plaintext, new_state))
}
