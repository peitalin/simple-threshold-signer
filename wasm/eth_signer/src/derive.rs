use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use num_bigint::BigUint;
use num_traits::Num;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

use crate::errors::js_err;

const THRESHOLD_SECP256K1_CLIENT_SHARE_SALT_V1: &[u8] =
    b"tatchi/lite/threshold-secp256k1-ecdsa/client-share:v1";
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
