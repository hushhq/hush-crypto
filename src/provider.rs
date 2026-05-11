//! Hybrid OpenMLS provider.
//!
//! Hush creates new groups and KeyPackages with the post-quantum X-Wing
//! ciphersuite.  Existing local MLS groups may still use the pre-PQ
//! RustCrypto-supported suites, so this provider keeps legacy decrypt/process
//! paths available while routing X-Wing HPKE operations to libcrux.

use openmls::prelude::tls_codec::SecretVLBytes;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCrypto;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

/// OpenMLS crypto backend that supports both legacy Hush MLS groups and new
/// X-Wing groups.
pub struct HybridCryptoProvider {
    legacy: RustCrypto,
    post_quantum: LibcruxCrypto,
}

impl Default for HybridCryptoProvider {
    fn default() -> Self {
        Self {
            legacy: RustCrypto::default(),
            post_quantum: LibcruxCrypto::new()
                .expect("libcrux OpenMLS crypto provider must initialize"),
        }
    }
}

impl HybridCryptoProvider {
    fn is_xwing(config: &HpkeConfig) -> bool {
        config.0 == HpkeKemType::XWingKemDraft6
    }

    fn hpke_provider(&self, config: &HpkeConfig) -> &dyn OpenMlsCrypto {
        if Self::is_xwing(config) {
            &self.post_quantum
        } else {
            &self.legacy
        }
    }
}

impl OpenMlsCrypto for HybridCryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 {
            self.post_quantum.supports(ciphersuite)
        } else {
            self.legacy.supports(ciphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        let mut ciphersuites = self.legacy.supported_ciphersuites();
        let xwing = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
        if !ciphersuites.contains(&xwing) {
            ciphersuites.push(xwing);
        }
        ciphersuites
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.legacy.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.legacy.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.legacy.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.legacy.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.legacy.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.legacy.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.legacy.signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.legacy.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.legacy.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.hpke_provider(&config)
            .hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.hpke_provider(&config)
            .hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.hpke_provider(&config).hpke_setup_sender_and_export(
            config,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.hpke_provider(&config).hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        self.hpke_provider(&config).derive_hpke_keypair(config, ikm)
    }
}
