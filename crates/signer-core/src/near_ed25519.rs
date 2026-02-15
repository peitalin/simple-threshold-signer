use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{CoreResult, SignerCoreError};

pub const ED25519_HKDF_KEY_INFO: &str = "ed25519-signing-key-dual-prf-v1";
const NEAR_KEY_DERIVATION_SALT_PREFIX: &str = "near-key-derivation:";
const ED25519_PRIVATE_KEY_SIZE: usize = 32;

pub fn near_key_salt_for_account(account_id: &str) -> String {
    format!("{}{}", NEAR_KEY_DERIVATION_SALT_PREFIX, account_id)
}

pub fn base64_url_decode(input: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| SignerCoreError::decode_error(format!("Base64 decode error: {}", e)))
}

pub fn derive_ed25519_key_from_prf_output(
    prf_output_base64: &str,
    account_id: &str,
) -> CoreResult<(String, String)> {
    let prf_output = base64_url_decode(prf_output_base64)?;
    if prf_output.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "Invalid input: Empty PRF output",
        ));
    }

    let ed25519_salt = near_key_salt_for_account(account_id);
    let hk = Hkdf::<Sha256>::new(Some(ed25519_salt.as_bytes()), &prf_output);
    let mut ed25519_key_material = [0u8; ED25519_PRIVATE_KEY_SIZE];
    hk.expand(ED25519_HKDF_KEY_INFO.as_bytes(), &mut ed25519_key_material)
        .map_err(|_| SignerCoreError::hkdf_error("HKDF operation failed"))?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_key_material);
    let verifying_key = signing_key.verifying_key();
    let seed_bytes = signing_key.to_bytes();
    let public_key_bytes = verifying_key.to_bytes();

    let mut near_private_key_bytes = Vec::with_capacity(64);
    near_private_key_bytes.extend_from_slice(&seed_bytes);
    near_private_key_bytes.extend_from_slice(&public_key_bytes);

    let private_key_b58 = bs58::encode(&near_private_key_bytes).into_string();
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();

    Ok((
        format!("ed25519:{}", private_key_b58),
        format!("ed25519:{}", public_key_b58),
    ))
}

pub fn parse_near_private_key_secret_key_bytes(private_key: &str) -> CoreResult<[u8; 32]> {
    let decoded = bs58::decode(private_key.strip_prefix("ed25519:").unwrap_or(private_key))
        .into_vec()
        .map_err(|e| SignerCoreError::decode_error(format!("Invalid private key base58: {}", e)))?;

    if decoded.len() < ED25519_PRIVATE_KEY_SIZE {
        return Err(SignerCoreError::invalid_length(
            "Decoded private key too short",
        ));
    }

    decoded[0..ED25519_PRIVATE_KEY_SIZE]
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length("Invalid secret key length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_near_private_key_secret_key_bytes_accepts_ed25519_prefix() {
        let seed = [9u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut keypair = Vec::with_capacity(64);
        keypair.extend_from_slice(&seed);
        keypair.extend_from_slice(&public_key);
        let private_key = format!("ed25519:{}", bs58::encode(keypair).into_string());

        let parsed =
            parse_near_private_key_secret_key_bytes(private_key.as_str()).expect("private key");
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parse_near_private_key_secret_key_bytes_rejects_short_key() {
        let short_private_key = format!("ed25519:{}", bs58::encode([1u8; 31]).into_string());
        let err = parse_near_private_key_secret_key_bytes(short_private_key.as_str())
            .expect_err("short key should fail");
        assert!(err.message.contains("Decoded private key too short"));
    }
}
