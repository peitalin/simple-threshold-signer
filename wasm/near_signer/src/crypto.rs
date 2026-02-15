use crate::encoders::{base64_url_decode, base64_url_encode};
use crate::error::KdfError;
use crate::types::EncryptedDataChaCha20Response;
use getrandom::getrandom;
use log::debug;

/// Ephemeral wrap key material derived in the SecureConfirm worker and delivered to the signer.
/// Holds the base64url-encoded WrapKeySeed and its salt, and exposes a helper to derive KEK.
#[derive(Clone)]
pub struct WrapKey {
    pub(crate) wrap_key_seed: String,
    pub(crate) wrap_key_salt: String,
}

impl WrapKey {
    /// Derive KEK from the stored WrapKeySeed + wrap_key_salt using the shared HKDF helper.
    pub fn derive_kek(&self) -> Result<Vec<u8>, String> {
        derive_kek_from_wrap_key_seed(&self.wrap_key_seed, &self.wrap_key_salt)
            .map_err(|e| format!("WrapKeySeed → KEK derivation failed: {}", e))
    }

    /// Return the base64url-encoded wrap_key_salt associated with this wrap key.
    pub fn salt_b64u(&self) -> &str {
        &self.wrap_key_salt
    }
}

impl std::fmt::Debug for WrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapKey")
            .field("wrap_key_seed", &"***")
            .field("wrap_key_salt", &self.wrap_key_salt)
            .finish()
    }
}

/// Derive KEK from WrapKeySeed + wrap_key_salt (HKDF)
pub(crate) fn derive_kek_from_wrap_key_seed(
    wrap_key_seed_b64u: &str,
    wrap_key_salt_b64u: &str,
) -> Result<Vec<u8>, KdfError> {
    signer_platform_web::near_crypto::derive_kek_from_wrap_key_seed_b64u(
        wrap_key_seed_b64u,
        wrap_key_salt_b64u,
    )
    .map_err(|e| {
        let message = e.to_string();
        if message.starts_with("Base64 decode error:") {
            return KdfError::Base64DecodeError(message);
        }
        if message == "HKDF operation failed" {
            return KdfError::HkdfError;
        }
        KdfError::InvalidInput(message)
    })
}

// === CHACHA20POLY1305 ENCRYPTION/DECRYPTION ===

/// Encrypt data using ChaCha20Poly1305
pub(crate) fn encrypt_data_chacha20(
    plain_text_data_str: &str,
    key_bytes: &[u8],
) -> Result<EncryptedDataChaCha20Response, String> {
    let mut nonce_bytes = [0u8; signer_platform_web::near_crypto::CHACHA20_NONCE_SIZE];
    getrandom(&mut nonce_bytes).map_err(|e| format!("Failed to generate nonce: {}", e))?;
    let ciphertext = signer_platform_web::near_crypto::encrypt_data_chacha20(
        plain_text_data_str,
        key_bytes,
        &nonce_bytes,
    )
    .map_err(|e| e.to_string())?;

    Ok(EncryptedDataChaCha20Response {
        encrypted_near_key_data_b64u: base64_url_encode(&ciphertext),
        chacha20_nonce_b64u: base64_url_encode(&nonce_bytes),
        wrap_key_salt_b64u: None,
    })
}

/// Decrypt data using ChaCha20Poly1305
pub(crate) fn decrypt_data_chacha20(
    encrypted_data_b64u: &str,
    chacha20_nonce_b64u: &str,
    key_bytes: &[u8],
) -> Result<String, String> {
    let nonce_bytes = base64_url_decode(chacha20_nonce_b64u)
        .map_err(|e| format!("Base64 decode error for ChaCha20 nonce: {}", e))?;

    let encrypted_data = base64_url_decode(encrypted_data_b64u)
        .map_err(|e| format!("Base64 decode error for encrypted data: {}", e))?;

    signer_platform_web::near_crypto::decrypt_data_chacha20(
        encrypted_data.as_slice(),
        nonce_bytes.as_slice(),
        key_bytes,
    )
    .map_err(|e| e.to_string())
}

// === KEY GENERATION ===

/// Secure Ed25519 key derivation from PRF output (prf.results.second)
/// Pure PRF-based Ed25519 key derivation for signing purposes only
pub(crate) fn derive_ed25519_key_from_prf_output(
    prf_output_base64: &str,
    account_id: &str,
) -> Result<(String, String), KdfError> {
    let out = signer_platform_web::near_ed25519::derive_ed25519_key_from_prf_output(
        prf_output_base64,
        account_id,
    )
    .map_err(|e| KdfError::InvalidInput(e.to_string()))?;
    debug!(
        "Successfully derived Ed25519 key for account: {}",
        account_id
    );
    Ok(out)
}

// === RESPONSE HELPERS ===

impl EncryptedDataChaCha20Response {
    pub fn with_wrap_key_salt(mut self, wrap_key_salt: &[u8]) -> Self {
        self.wrap_key_salt_b64u = Some(base64_url_encode(wrap_key_salt));
        self
    }
}
