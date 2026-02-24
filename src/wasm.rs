//! WASM bindings for the web client.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::identity::generate_identity;
use crate::prekey::{generate_one_time_pre_keys, generate_signed_pre_key};
use crate::session::{decrypt as session_decrypt, encrypt as session_encrypt};
use crate::x3dh_wrap::perform_x3dh;

#[wasm_bindgen(js_name = "init")]
pub fn wasm_init() {
    // No-op; optional future setup (e.g. panic hook for debug).
}

#[wasm_bindgen(js_name = "generateIdentity")]
pub fn wasm_generate_identity() -> Result<JsValue, JsValue> {
    let pair = generate_identity().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let out = IdentityOut {
        public_key: pair.public_key,
        private_key: pair.private_key,
        registration_id: pair.registration_id,
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
struct IdentityOut {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub registration_id: u32,
}

#[wasm_bindgen(js_name = "generatePreKeyBundle")]
pub fn wasm_generate_pre_key_bundle(
    identity_public: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    num_one_time: usize,
) -> Result<JsValue, JsValue> {
    let (signed_pk, sig) = generate_signed_pre_key(identity_private, 1).map_err(|_| JsValue::from_str("signed prekey failed"))?;
    let one_time = generate_one_time_pre_keys(num_one_time, 0).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let one_time_entries: Vec<_> = one_time
        .into_iter()
        .map(|k| OneTimeOut { key_id: k.key_id, public_key: k.public_key })
        .collect();
    let bundle = PreKeyBundleOut {
        identity_key: identity_public.to_vec(),
        signed_pre_key: signed_pk,
        signed_pre_key_signature: sig,
        registration_id,
        one_time_pre_keys: one_time_entries,
    };
    serde_wasm_bindgen::to_value(&bundle).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
struct OneTimeOut {
    key_id: u32,
    public_key: Vec<u8>,
}

#[derive(Serialize)]
struct PreKeyBundleOut {
    identity_key: Vec<u8>,
    signed_pre_key: Vec<u8>,
    signed_pre_key_signature: Vec<u8>,
    registration_id: u32,
    one_time_pre_keys: Vec<OneTimeOut>,
}

#[wasm_bindgen(js_name = "performX3DH")]
pub fn wasm_perform_x3dh(remote_bundle_json: &str, identity_private: &[u8]) -> Result<Vec<u8>, JsValue> {
    let state = perform_x3dh(remote_bundle_json, identity_private).map_err(|e| JsValue::from_str(&e))?;
    Ok(state.state_bytes)
}

#[wasm_bindgen(js_name = "encrypt")]
pub fn wasm_encrypt(state_bytes: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<JsValue, JsValue> {
    let (ciphertext, new_state) = session_encrypt(state_bytes, plaintext, associated_data).map_err(|e| JsValue::from_str(&e))?;
    let out = EncryptOut { ciphertext, updated_state: new_state };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
struct EncryptOut {
    ciphertext: Vec<u8>,
    updated_state: Vec<u8>,
}

#[wasm_bindgen(js_name = "decrypt")]
pub fn wasm_decrypt(state_bytes: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<JsValue, JsValue> {
    let (plaintext, new_state) = session_decrypt(state_bytes, ciphertext, associated_data).map_err(|e| JsValue::from_str(&e))?;
    let out = DecryptOut { plaintext, updated_state: new_state };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
struct DecryptOut {
    plaintext: Vec<u8>,
    updated_state: Vec<u8>,
}
