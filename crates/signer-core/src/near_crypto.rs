use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{CoreResult, SignerCoreError};

pub const CHACHA20_NONCE_SIZE: usize = 12;
pub const CHACHA20_KEY_SIZE: usize = 32;
pub const ERROR_INVALID_KEY_SIZE: &str = "Invalid key size for ChaCha20Poly1305";
pub const NEAR_KEK_INFO: &[u8] = b"near-kek";

pub fn base64_url_decode(input: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| SignerCoreError::decode_error(format!("Base64 decode error: {}", e)))
}

pub fn derive_kek_from_wrap_key_seed_b64u(
    wrap_key_seed_b64u: &str,
    wrap_key_salt_b64u: &str,
) -> CoreResult<Vec<u8>> {
    let wrap_key_seed = base64_url_decode(wrap_key_seed_b64u)?;
    if wrap_key_seed.is_empty() {
        return Err(SignerCoreError::invalid_input("Empty WrapKeySeed"));
    }
    let wrap_key_salt = base64_url_decode(wrap_key_salt_b64u)?;
    let hk = Hkdf::<Sha256>::new(Some(&wrap_key_salt), &wrap_key_seed);
    let mut kek = vec![0u8; CHACHA20_KEY_SIZE];
    hk.expand(NEAR_KEK_INFO, &mut kek)
        .map_err(|_| SignerCoreError::hkdf_error("HKDF operation failed"))?;
    Ok(kek)
}

pub fn encrypt_data_chacha20(
    plain_text_data_str: &str,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
) -> CoreResult<Vec<u8>> {
    if key_bytes.len() != CHACHA20_KEY_SIZE {
        return Err(SignerCoreError::invalid_length(ERROR_INVALID_KEY_SIZE));
    }
    if nonce_bytes.len() != CHACHA20_NONCE_SIZE {
        return Err(SignerCoreError::invalid_length(format!(
            "ChaCha20 nonce must be {} bytes.",
            CHACHA20_NONCE_SIZE
        )));
    }

    let key_array: [u8; CHACHA20_KEY_SIZE] = key_bytes
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(ERROR_INVALID_KEY_SIZE))?;
    let key: chacha20poly1305::Key = key_array.into();
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce_array: [u8; CHACHA20_NONCE_SIZE] = nonce_bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!(
            "ChaCha20 nonce must be {} bytes.",
            CHACHA20_NONCE_SIZE
        ))
    })?;
    let nonce: Nonce = nonce_array.into();

    cipher
        .encrypt(&nonce, plain_text_data_str.as_bytes())
        .map_err(|e| SignerCoreError::crypto_error(format!("Encryption error: {}", e)))
}

pub fn decrypt_data_chacha20(
    encrypted_data: &[u8],
    nonce_bytes: &[u8],
    key_bytes: &[u8],
) -> CoreResult<String> {
    if key_bytes.len() != CHACHA20_KEY_SIZE {
        return Err(SignerCoreError::invalid_length(ERROR_INVALID_KEY_SIZE));
    }
    if nonce_bytes.len() != CHACHA20_NONCE_SIZE {
        return Err(SignerCoreError::invalid_length(format!(
            "Decryption ChaCha20 nonce must be {} bytes.",
            CHACHA20_NONCE_SIZE
        )));
    }

    let key_array: [u8; CHACHA20_KEY_SIZE] = key_bytes
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(ERROR_INVALID_KEY_SIZE))?;
    let key: chacha20poly1305::Key = key_array.into();
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce_array: [u8; CHACHA20_NONCE_SIZE] = nonce_bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!(
            "Decryption ChaCha20 nonce must be {} bytes.",
            CHACHA20_NONCE_SIZE
        ))
    })?;
    let nonce: Nonce = nonce_array.into();

    let decrypted_bytes = cipher
        .decrypt(&nonce, encrypted_data)
        .map_err(|e| SignerCoreError::crypto_error(format!("Decryption error: {}", e)))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| SignerCoreError::utf8_error(format!("UTF-8 decoding error: {}", e)))
}
