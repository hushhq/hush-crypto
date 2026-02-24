//! Pre-key generation for upload to the server.

use serde::{Deserialize, Serialize};

/// One entry for one-time pre-key generation. Contains both public (for upload) and private (for local storage).
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyEntry {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Bundle payload for POST /api/keys/upload (matches server PreKeyUploadRequest).
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundleForUpload {
    pub identity_key: Vec<u8>,
    pub signed_pre_key: Vec<u8>,
    pub signed_pre_key_signature: Vec<u8>,
    pub registration_id: u32,
    pub one_time_pre_keys: Vec<OneTimePreKeyEntry>,
}

/// Generates a signed pre-key (key pair + VXEdDSA signature with identity key).
/// Returns (public_key_33, signature, private_key_32).
pub fn generate_signed_pre_key(
    identity_private: &[u8],
    _signed_pre_key_id: u32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ()> {
    if identity_private.len() != 32 {
        return Err(());
    }
    let kp = libsignal_dezire::vxeddsa::gen_keypair();
    let public_33: Vec<u8> = kp.public.to_vec();
    let private_32: Vec<u8> = kp.secret.to_vec();

    let k: [u8; 32] = identity_private.try_into().map_err(|_| ())?;
    let out = libsignal_dezire::vxeddsa::vxeddsa_sign(&k, &public_33)?;
    Ok((public_33, out.signature.to_vec(), private_32))
}

/// Generates n one-time pre-keys. Both public (for upload) and private (for local storage) are returned.
/// Private keys must be persisted client-side and deleted after X3DH responder consumption.
pub fn generate_one_time_pre_keys(n: usize, start_id: u32) -> Result<Vec<OneTimePreKeyEntry>, getrandom::Error> {
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let kp = libsignal_dezire::vxeddsa::gen_keypair();
        keys.push(OneTimePreKeyEntry {
            key_id: start_id.wrapping_add(i as u32),
            public_key: kp.public.to_vec(),
            private_key: kp.secret.to_vec(),
        });
    }
    Ok(keys)
}
