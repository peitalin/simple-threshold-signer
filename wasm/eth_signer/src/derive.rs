use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, SecretKey};
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
const THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID: u32 = 1;
const THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID: u32 = 2;
const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn secp256k1_order() -> Result<BigUint, JsValue> {
    BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16)
        .map_err(|_| js_err("failed to parse secp256k1 group order"))
}

fn reduce_hkdf_output_to_nonzero_secp256k1_scalar(okm64: &[u8]) -> Result<[u8; 32], JsValue> {
    let order = secp256k1_order()?;
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

pub fn map_additive_share_to_threshold_signatures_share_2p(
    additive_share32: Vec<u8>,
    participant_id: u32,
) -> Result<Vec<u8>, JsValue> {
    if additive_share32.len() != 32 {
        return Err(js_err(format!(
            "additive_share32 must be 32 bytes (got {})",
            additive_share32.len()
        )));
    }

    let order = secp256k1_order()?;
    let additive = BigUint::from_bytes_be(&additive_share32);
    if additive == BigUint::from(0u8) || additive >= order {
        return Err(js_err("additive share must be in (0, n)"));
    }

    let lambda = match participant_id {
        THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID => BigUint::from(3u8),
        THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID => &order - BigUint::from(2u8),
        _ => {
            return Err(js_err(format!(
                "unsupported participant_id for 2P mapping: {}",
                participant_id
            )))
        }
    };
    // secp256k1 order is prime => inv(a) = a^(n-2) mod n.
    let inv_lambda = lambda.modpow(&(&order - BigUint::from(2u8)), &order);
    let mapped = (additive * inv_lambda) % &order;
    if mapped == BigUint::from(0u8) {
        return Err(js_err("mapped threshold share is zero (unexpected)"));
    }

    let mapped_bytes = mapped.to_bytes_be();
    if mapped_bytes.len() > 32 {
        return Err(js_err(format!(
            "mapped threshold share exceeds 32 bytes (got {})",
            mapped_bytes.len()
        )));
    }
    let mut out = vec![0u8; 32];
    let offset = out.len() - mapped_bytes.len();
    out[offset..].copy_from_slice(&mapped_bytes);
    Ok(out)
}

pub fn validate_secp256k1_public_key_33(public_key33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    if public_key33.len() != 33 {
        return Err(js_err(format!(
            "public_key33 must be 33 bytes (got {})",
            public_key33.len()
        )));
    }
    let key = PublicKey::from_sec1_bytes(&public_key33)
        .map_err(|_| js_err("invalid compressed secp256k1 public key"))?;
    let encoded = key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(js_err(format!(
            "compressed secp256k1 public key must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

pub fn add_secp256k1_public_keys_33(left33: Vec<u8>, right33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let left = PublicKey::from_sec1_bytes(&left33)
        .map_err(|_| js_err("left33 is not a valid compressed secp256k1 public key"))?;
    let right = PublicKey::from_sec1_bytes(&right33)
        .map_err(|_| js_err("right33 is not a valid compressed secp256k1 public key"))?;

    let sum = (ProjectivePoint::from(*left.as_affine()) + ProjectivePoint::from(*right.as_affine()))
        .to_affine();
    let encoded = sum.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(js_err(format!(
            "sum of secp256k1 public keys must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_32_bytes(value: &BigUint) -> Vec<u8> {
        let bytes = value.to_bytes_be();
        let mut out = vec![0u8; 32];
        let offset = out.len() - bytes.len();
        out[offset..].copy_from_slice(&bytes);
        out
    }

    #[test]
    fn map_additive_share_roundtrips_for_client_participant() {
        let order = secp256k1_order().expect("order");
        let additive = BigUint::from(42u8);
        let mapped = map_additive_share_to_threshold_signatures_share_2p(
            to_32_bytes(&additive),
            THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
        )
        .expect("map client");
        let mapped_big = BigUint::from_bytes_be(&mapped);
        let restored = (mapped_big * BigUint::from(3u8)) % &order;
        assert_eq!(restored, additive);
    }

    #[test]
    fn map_additive_share_roundtrips_for_relayer_participant() {
        let order = secp256k1_order().expect("order");
        let additive = BigUint::from(77u8);
        let mapped = map_additive_share_to_threshold_signatures_share_2p(
            to_32_bytes(&additive),
            THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
        )
        .expect("map relayer");
        let mapped_big = BigUint::from_bytes_be(&mapped);
        let lambda = &order - BigUint::from(2u8);
        let restored = (mapped_big * lambda) % &order;
        assert_eq!(restored, additive);
    }

    #[test]
    fn add_secp256k1_public_keys_matches_scalar_sum() {
        let mut sk1_bytes = [0u8; 32];
        sk1_bytes[31] = 1;
        let mut sk2_bytes = [0u8; 32];
        sk2_bytes[31] = 2;
        let mut sk3_bytes = [0u8; 32];
        sk3_bytes[31] = 3;

        let sk1 = SecretKey::from_slice(&sk1_bytes).expect("sk1");
        let sk2 = SecretKey::from_slice(&sk2_bytes).expect("sk2");
        let sk3 = SecretKey::from_slice(&sk3_bytes).expect("sk3");

        let pk1 = sk1.public_key().to_encoded_point(true).as_bytes().to_vec();
        let pk2 = sk2.public_key().to_encoded_point(true).as_bytes().to_vec();
        let expected = sk3.public_key().to_encoded_point(true).as_bytes().to_vec();

        let summed = add_secp256k1_public_keys_33(pk1.clone(), pk2).expect("sum");
        assert_eq!(summed, expected);

        let validated = validate_secp256k1_public_key_33(pk1).expect("validate");
        assert_eq!(validated.len(), 33);
    }
}
