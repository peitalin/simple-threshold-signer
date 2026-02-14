use hkdf::Hkdf;
use k256::ecdsa::{RecoveryId, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, SecretKey};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

use crate::error::{CoreResult, SignerCoreError};

const THRESHOLD_SECP256K1_CLIENT_SHARE_SALT_V1: &[u8] =
    b"tatchi/lite/threshold-secp256k1-ecdsa/client-share:v1";
const EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1: &[u8] = b"secp256k1-signing-key-dual-prf-v1";
const EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1: &str = "evm-key-derivation:";
pub const THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID: u32 = 1;
pub const THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID: u32 = 2;
const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn secp256k1_order() -> CoreResult<BigUint> {
    BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16)
        .map_err(|_| SignerCoreError::internal("failed to parse secp256k1 group order"))
}

fn reduce_hkdf_output_to_nonzero_secp256k1_scalar(okm64: &[u8]) -> CoreResult<[u8; 32]> {
    let order = secp256k1_order()?;
    let reduced =
        (BigUint::from_bytes_be(okm64) % (&order - BigUint::from(1u8))) + BigUint::from(1u8);
    let reduced_bytes = reduced.to_bytes_be();
    if reduced_bytes.len() > 32 {
        return Err(SignerCoreError::internal(format!(
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
    prf_first32: &[u8],
    user_id: &str,
    derivation_path: u32,
) -> CoreResult<Vec<u8>> {
    if prf_first32.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "prf_first32 must be 32 bytes (got {})",
            prf_first32.len()
        )));
    }

    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(SignerCoreError::invalid_input("user_id must be non-empty"));
    }

    let mut info = Vec::with_capacity(user_id.len() + 1 + 4);
    info.extend_from_slice(user_id.as_bytes());
    info.push(0);
    info.extend_from_slice(&derivation_path.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(THRESHOLD_SECP256K1_CLIENT_SHARE_SALT_V1), prf_first32);
    let mut okm64 = [0u8; 64];
    hk.expand(&info, &mut okm64).map_err(|_| {
        SignerCoreError::hkdf_error("HKDF expand failed for threshold secp256k1 client share")
    })?;

    let client_signing_share32 = reduce_hkdf_output_to_nonzero_secp256k1_scalar(&okm64)?;
    let secret_key = SecretKey::from_slice(&client_signing_share32).map_err(|_| {
        SignerCoreError::crypto_error(
            "derived client signing share is not a valid secp256k1 secret key",
        )
    })?;
    let client_verifying_share33 = secret_key.public_key().to_encoded_point(true);
    let client_verifying_share33 = client_verifying_share33.as_bytes();
    if client_verifying_share33.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
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
    prf_second: &[u8],
    near_account_id: &str,
) -> CoreResult<Vec<u8>> {
    if prf_second.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "prf_second must be non-empty",
        ));
    }

    let near_account_id = near_account_id.trim();
    if near_account_id.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "near_account_id must be non-empty",
        ));
    }

    let mut hkdf_salt =
        Vec::with_capacity(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.len() + near_account_id.len());
    hkdf_salt.extend_from_slice(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.as_bytes());
    hkdf_salt.extend_from_slice(near_account_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), prf_second);
    let mut okm64 = [0u8; 64];
    hk.expand(EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1, &mut okm64)
        .map_err(|_| {
            SignerCoreError::hkdf_error(
                "HKDF expand failed for secp256k1 PRF.second key derivation",
            )
        })?;

    let private_key32 = reduce_hkdf_output_to_nonzero_secp256k1_scalar(&okm64)?;
    let secret_key = SecretKey::from_slice(&private_key32)
        .map_err(|_| SignerCoreError::crypto_error("derived secp256k1 private key is invalid"))?;

    let public_key_compressed = secret_key.public_key().to_encoded_point(true);
    let public_key_compressed = public_key_compressed.as_bytes();
    if public_key_compressed.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "derived compressed secp256k1 public key must be 33 bytes (got {})",
            public_key_compressed.len()
        )));
    }

    let public_key_uncompressed = secret_key.public_key().to_encoded_point(false);
    let public_key_uncompressed = public_key_uncompressed.as_bytes();
    if public_key_uncompressed.len() != 65 || public_key_uncompressed[0] != 0x04 {
        return Err(SignerCoreError::invalid_length(format!(
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
    additive_share32: &[u8],
    participant_id: u32,
) -> CoreResult<Vec<u8>> {
    if additive_share32.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "additive_share32 must be 32 bytes (got {})",
            additive_share32.len()
        )));
    }

    let order = secp256k1_order()?;
    let additive = BigUint::from_bytes_be(additive_share32);
    if additive == BigUint::from(0u8) || additive >= order {
        return Err(SignerCoreError::invalid_input(
            "additive share must be in (0, n)",
        ));
    }

    let lambda = match participant_id {
        THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID => BigUint::from(3u8),
        THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID => &order - BigUint::from(2u8),
        _ => {
            return Err(SignerCoreError::unsupported(format!(
                "unsupported participant_id for 2P mapping: {}",
                participant_id
            )))
        }
    };

    let inv_lambda = lambda.modpow(&(&order - BigUint::from(2u8)), &order);
    let mapped = (additive * inv_lambda) % &order;
    if mapped == BigUint::from(0u8) {
        return Err(SignerCoreError::internal(
            "mapped threshold share is zero (unexpected)",
        ));
    }

    let mapped_bytes = mapped.to_bytes_be();
    if mapped_bytes.len() > 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "mapped threshold share exceeds 32 bytes (got {})",
            mapped_bytes.len()
        )));
    }
    let mut out = vec![0u8; 32];
    let offset = out.len() - mapped_bytes.len();
    out[offset..].copy_from_slice(&mapped_bytes);
    Ok(out)
}

pub fn validate_secp256k1_public_key_33(public_key33: &[u8]) -> CoreResult<Vec<u8>> {
    if public_key33.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "public_key33 must be 33 bytes (got {})",
            public_key33.len()
        )));
    }
    let key = PublicKey::from_sec1_bytes(public_key33)
        .map_err(|_| SignerCoreError::decode_error("invalid compressed secp256k1 public key"))?;
    let encoded = key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "compressed secp256k1 public key must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

pub fn add_secp256k1_public_keys_33(left33: &[u8], right33: &[u8]) -> CoreResult<Vec<u8>> {
    let left = PublicKey::from_sec1_bytes(left33).map_err(|_| {
        SignerCoreError::decode_error("left33 is not a valid compressed secp256k1 public key")
    })?;
    let right = PublicKey::from_sec1_bytes(right33).map_err(|_| {
        SignerCoreError::decode_error("right33 is not a valid compressed secp256k1 public key")
    })?;

    let sum = (ProjectivePoint::from(*left.as_affine())
        + ProjectivePoint::from(*right.as_affine()))
    .to_affine();
    let encoded = sum.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "sum of secp256k1 public keys must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

pub fn sign_secp256k1_recoverable(digest32: &[u8], private_key32: &[u8]) -> CoreResult<Vec<u8>> {
    if digest32.len() != 32 {
        return Err(SignerCoreError::invalid_length("digest32 must be 32 bytes"));
    }
    if private_key32.len() != 32 {
        return Err(SignerCoreError::invalid_length(
            "privateKey must be 32 bytes",
        ));
    }

    let sk = SecretKey::from_slice(private_key32)
        .map_err(|_| SignerCoreError::crypto_error("invalid secp256k1 private key"))?;
    let signing_key: SigningKey = sk.into();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest32)
        .map_err(|_| SignerCoreError::crypto_error("secp256k1 signing failed"))?;

    // Ethereum requires low-s normalized signatures (EIP-2).
    // When normalizing s -> n-s, the recovery id flips parity.
    let (sig, recid) = match sig.normalize_s() {
        Some(normalized) => {
            let flipped = RecoveryId::from_byte(recid.to_byte() ^ 1)
                .ok_or_else(|| SignerCoreError::internal("invalid recovery id"))?;
            (normalized, flipped)
        }
        None => (sig, recid),
    };

    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    out.push(recid.to_byte());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature, VerifyingKey};

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
            &to_32_bytes(&additive),
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
            &to_32_bytes(&additive),
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

        let summed = add_secp256k1_public_keys_33(&pk1, &pk2).expect("sum");
        assert_eq!(summed, expected);

        let validated = validate_secp256k1_public_key_33(&pk1).expect("validate");
        assert_eq!(validated.len(), 33);
    }

    #[test]
    fn sign_secp256k1_recoverable_produces_low_s_and_valid_recovery_id() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let mut digest = [0u8; 32];
        digest[31] = 9;

        let out = sign_secp256k1_recoverable(digest.as_slice(), sk_bytes.as_slice()).expect("sign");
        assert_eq!(out.len(), 65);

        let sig = Signature::from_slice(&out[..64])
            .expect("signature bytes must decode into secp256k1 sig");
        let recid = RecoveryId::from_byte(out[64]).expect("recovery id");
        assert!(
            sig.normalize_s().is_none(),
            "signature should already be low-s normalized",
        );

        let recovered =
            VerifyingKey::recover_from_prehash(&digest, &sig, recid).expect("recover key from sig");
        let expected = SecretKey::from_slice(&sk_bytes)
            .expect("sk")
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        assert_eq!(
            recovered.to_encoded_point(true).as_bytes().to_vec(),
            expected,
            "recovered key must match signer key",
        );
    }
}
