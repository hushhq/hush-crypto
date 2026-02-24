//! Hush Signal Protocol wrapper: X3DH, Double Ratchet, session management.
//! Builds as native lib and as WASM (wasm-pack --target web) for the web client.

mod identity;
mod prekey;
mod session;
mod x3dh_wrap;

pub use identity::{generate_identity, IdentityKeyPair};
pub use prekey::{generate_one_time_pre_keys, generate_signed_pre_key, PreKeyBundleForUpload};
pub use session::{decrypt, encrypt, SessionState};
pub use x3dh_wrap::{perform_x3dh, perform_x3dh_responder};

#[cfg(target_arch = "wasm32")]
mod wasm;
