use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use num_bigint::BigUint;
use num_traits::Num;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

use crate::errors::js_err;

const THRESHOLD_SECP256K1_CLIENT_SHARE_SALT_V1: &[u8] =
    b"tatchi/lite/threshold-secp256k1-ecdsa/client-share:v1";
const EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1: &[u8] = b"secp256k1-signing-key-dual-prf-v1";
const EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1: &str = "evm-key-derivation:";
const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn reduce_hkdf_output_to_nonzero_secp256k1_scalar(okm64: &[u8]) -> Result<[u8; 32], JsValue> {
    let order = BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16)
        .map_err(|_| js_err("failed to parse secp256k1 group order"))?;
    let reduced =
        (BigUint::from_bytes_be(okm64) % (&order - BigUint::from(1u8))) + BigUint::from(1u8);
    let reduced_bytes = reduced.to_bytes_be();
    if reduced_bytes.len() > 32 {
        return Err(js_err(format!(
            "derived secp256k1 scalar exceeds 32 bytes (got {})",
            reduced_bytes.len()
        )));
    }

    let mut out = [0u8; 32];
    let offset = out.len() - reduced_bytes.len();
    out[offset..].copy_from_slice(&reduced_bytes);
    Ok(out)
}

pub fn derive_threshold_secp256k1_client_share(
    prf_first32: Vec<u8>,
    user_id: String,
    derivation_path: u32,
) -> Result<Vec<u8>, JsValue> {
    if prf_first32.len() != 32 {
        return Err(js_err(format!(
            "prf_first32 must be 32 bytes (got {})",
            prf_first32.len()
        )));
    }

    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(js_err("user_id must be non-empty"));
    }

    let mut info = Vec::with_capacity(user_id.len() + 1 + 4);
    info.extend_from_slice(user_id.as_bytes());
    info.push(0);
    info.extend_from_slice(&derivation_path.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(THRESHOLD_SECP256K1_CLIENT_SHARE_SALT_V1), &prf_first32);
    let mut okm64 = [0u8; 64];
    hk.expand(&info, &mut okm64)
        .map_err(|_| js_err("HKDF expand failed for threshold secp256k1 client share"))?;

    let client_signing_share32 = reduce_hkdf_output_to_nonzero_secp256k1_scalar(&okm64)?;
    let secret_key = SecretKey::from_slice(&client_signing_share32)
        .map_err(|_| js_err("derived client signing share is not a valid secp256k1 secret key"))?;
    let client_verifying_share33 = secret_key.public_key().to_encoded_point(true);
    let client_verifying_share33 = client_verifying_share33.as_bytes();
    if client_verifying_share33.len() != 33 {
        return Err(js_err(format!(
            "derived client verifying share must be 33 bytes (got {})",
            client_verifying_share33.len()
        )));
    }

    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&client_signing_share32);
    out.extend_from_slice(client_verifying_share33);
    Ok(out)
}

pub fn derive_secp256k1_keypair_from_prf_second(
    prf_second: Vec<u8>,
    near_account_id: String,
) -> Result<Vec<u8>, JsValue> {
    if prf_second.is_empty() {
        return Err(js_err("prf_second must be non-empty"));
    }

    let near_account_id = near_account_id.trim();
    if near_account_id.is_empty() {
        return Err(js_err("near_account_id must be non-empty"));
    }

    let mut hkdf_salt = Vec::with_capacity(
        EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.len() + near_account_id.len(),
    );
    hkdf_salt.extend_from_slice(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.as_bytes());
    hkdf_salt.extend_from_slice(near_account_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), &prf_second);
    let mut okm64 = [0u8; 64];
    hk.expand(EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1, &mut okm64)
        .map_err(|_| js_err("HKDF expand failed for secp256k1 PRF.second key derivation"))?;

    let private_key32 = reduce_hkdf_output_to_nonzero_secp256k1_scalar(&okm64)?;
    let secret_key = SecretKey::from_slice(&private_key32)
        .map_err(|_| js_err("derived secp256k1 private key is invalid"))?;

    let public_key_compressed = secret_key.public_key().to_encoded_point(true);
    let public_key_compressed = public_key_compressed.as_bytes();
    if public_key_compressed.len() != 33 {
        return Err(js_err(format!(
            "derived compressed secp256k1 public key must be 33 bytes (got {})",
            public_key_compressed.len()
        )));
    }

    let public_key_uncompressed = secret_key.public_key().to_encoded_point(false);
    let public_key_uncompressed = public_key_uncompressed.as_bytes();
    if public_key_uncompressed.len() != 65 || public_key_uncompressed[0] != 0x04 {
        return Err(js_err(format!(
            "derived uncompressed secp256k1 public key must be 65 bytes with 0x04 prefix (got {})",
            public_key_uncompressed.len()
        )));
    }

    let mut hasher = Keccak256::new();
    hasher.update(&public_key_uncompressed[1..]);
    let digest = hasher.finalize();
    let address20 = &digest[digest.len() - 20..];

    let mut out = Vec::with_capacity(85);
    out.extend_from_slice(&private_key32);
    out.extend_from_slice(public_key_compressed);
    out.extend_from_slice(address20);
    Ok(out)
}
