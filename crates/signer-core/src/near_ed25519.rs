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
