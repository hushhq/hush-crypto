//! Identity key pair generation.

use serde::{Deserialize, Serialize};

/// Identity key pair: public (33 bytes, 0x05-prefixed) and private (32 bytes).
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub registration_id: u32,
}

/// Generates a new identity key pair and registration ID.
pub fn generate_identity() -> Result<IdentityKeyPair, getrandom::Error> {
    let mut private_bytes = [0u8; 32];
    getrandom::getrandom(&mut private_bytes)?;
    let secret = x25519_dalek::StaticSecret::from(private_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    let public_bytes = public.as_bytes();
    let mut public_33 = vec![0x05u8];
    public_33.extend_from_slice(public_bytes);

    let mut reg_id_bytes = [0u8; 4];
    getrandom::getrandom(&mut reg_id_bytes)?;
    let registration_id = u32::from_le_bytes(reg_id_bytes) & 0x3FFF; // 14-bit as in Signal

    Ok(IdentityKeyPair {
        public_key: public_33,
        private_key: private_bytes.to_vec(),
        registration_id,
    })
}
