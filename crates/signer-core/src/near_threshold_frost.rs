use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar as CurveScalar;
use curve25519_dalek::traits::Identity;
use frost_ed25519::Group;
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::{CoreResult, SignerCoreError};
use crate::near_threshold_ed25519::{
    self, CommitmentsWire, parse_near_public_key_to_bytes, signature_share_to_b64u,
};

const THRESHOLD_RELAYER_SHARE_INFO_PREFIX_V1: &[u8] = b"w3a/threshold/relayer_share_v1";
const THRESHOLD_DERIVE_NONZERO_SCALAR_MAX_TRIES_V1: u32 = 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519KeygenFromClientVerifyingShareArgs {
    #[serde(default)]
    pub client_participant_id: Option<u16>,
    #[serde(default)]
    pub relayer_participant_id: Option<u16>,
    pub client_verifying_share_b64u: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519KeygenFromMasterSecretArgs {
    #[serde(default)]
    pub client_participant_id: Option<u16>,
    #[serde(default)]
    pub relayer_participant_id: Option<u16>,
    pub master_secret_b64u: String,
    pub near_account_id: String,
    pub rp_id: String,
    pub client_verifying_share_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519KeygenOutput {
    pub relayer_key_id: String,
    pub public_key: String,
    pub relayer_signing_share_b64u: String,
    pub relayer_verifying_share_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519Round1CommitOutput {
    pub relayer_nonces_b64u: String,
    pub relayer_commitments: CommitmentsWire,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519Round2SignArgs {
    #[serde(default)]
    pub client_participant_id: Option<u16>,
    #[serde(default)]
    pub relayer_participant_id: Option<u16>,
    pub relayer_signing_share_b64u: String,
    pub relayer_nonces_b64u: String,
    pub group_public_key: String,
    pub signing_digest_b64u: String,
    pub client_commitments: CommitmentsWire,
    pub relayer_commitments: CommitmentsWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519Round2SignOutput {
    pub relayer_signature_share_b64u: String,
}

fn decode_base64_url(input: &str, label: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(input.trim())
        .map_err(|e| SignerCoreError::decode_error(format!("Invalid {label}: {e}")))
}

fn decode_base64_url_32(input: &str, label: &str) -> CoreResult<[u8; 32]> {
    let bytes = decode_base64_url(input, label)?;
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{label} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes.as_slice().try_into().expect("checked length above"))
}

fn decode_master_secret_32(input: &str) -> CoreResult<[u8; 32]> {
    decode_base64_url_32(input, "THRESHOLD_ED25519_MASTER_SECRET_B64U")
}

fn normalize_rp_id(rp_id: &str) -> String {
    rp_id.trim().to_ascii_lowercase()
}

fn deterministic_rejection_sample_nonzero_scalar_v1<F>(
    mut derive_candidate: F,
    exhausted_error: &str,
) -> CoreResult<CurveScalar>
where
    F: FnMut(u32) -> CoreResult<CurveScalar>,
{
    for ctr in 0u32..THRESHOLD_DERIVE_NONZERO_SCALAR_MAX_TRIES_V1 {
        let scalar = derive_candidate(ctr)?;
        if scalar != CurveScalar::ZERO {
            return Ok(scalar);
        }
    }
    Err(SignerCoreError::crypto_error(exhausted_error))
}

fn derive_threshold_relayer_share_scalar_v1(
    master_secret_bytes: &[u8; 32],
    near_account_id: &str,
    rp_id: &str,
    client_verifying_share_bytes: &[u8; 32],
) -> CoreResult<CurveScalar> {
    let rp_id = normalize_rp_id(rp_id);
    let salt = Sha256::digest(client_verifying_share_bytes);
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), master_secret_bytes);

    let near_account_id = near_account_id.trim();
    let mut info: Vec<u8> = Vec::with_capacity(
        THRESHOLD_RELAYER_SHARE_INFO_PREFIX_V1.len()
            + 1
            + near_account_id.len()
            + 1
            + rp_id.len()
            + 1
            + 8
            + 4,
    );
    info.extend_from_slice(THRESHOLD_RELAYER_SHARE_INFO_PREFIX_V1);
    info.push(0);
    info.extend_from_slice(near_account_id.as_bytes());
    info.push(0);
    info.extend_from_slice(rp_id.as_bytes());
    info.push(0);
    info.extend_from_slice(&0u64.to_le_bytes());
    info.extend_from_slice(&0u32.to_le_bytes());
    let ctr_offset = info.len() - 4;

    let mut okm = [0u8; 64];
    deterministic_rejection_sample_nonzero_scalar_v1(
        |ctr| {
            info[ctr_offset..].copy_from_slice(&ctr.to_le_bytes());
            hk.expand(&info, &mut okm)
                .map_err(|_| SignerCoreError::hkdf_error("HKDF expand failed"))?;
            Ok(CurveScalar::from_bytes_mod_order_wide(&okm))
        },
        "Derived relayer signing share is zero; retry with a different master secret",
    )
}

fn decompress_verifying_share_point(
    bytes: [u8; 32],
    label: &str,
) -> CoreResult<curve25519_dalek::edwards::EdwardsPoint> {
    CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| SignerCoreError::decode_error(format!("Invalid {label} point")))
}

fn resolve_participant_ids(
    client_participant_id: Option<u16>,
    relayer_participant_id: Option<u16>,
) -> CoreResult<(u16, u16)> {
    let client_id = client_participant_id.unwrap_or(1);
    let relayer_id = relayer_participant_id.unwrap_or(2);
    if client_id == 0 {
        return Err(SignerCoreError::invalid_input(
            "clientParticipantId must be an integer in [1,65535]",
        ));
    }
    if relayer_id == 0 {
        return Err(SignerCoreError::invalid_input(
            "relayerParticipantId must be an integer in [1,65535]",
        ));
    }
    near_threshold_ed25519::validate_threshold_ed25519_participant_ids_2p(
        Some(client_id),
        Some(relayer_id),
        &[],
    )?;
    Ok((client_id, relayer_id))
}

fn scalar_to_verifying_share_bytes(signing_share_bytes: &[u8; 32]) -> [u8; 32] {
    let scalar = CurveScalar::from_bytes_mod_order(*signing_share_bytes);
    (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes()
}

pub fn compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
    client_verifying_share_bytes: &[u8; 32],
    relayer_verifying_share_bytes: &[u8; 32],
    client_participant_id: u16,
    relayer_participant_id: u16,
) -> CoreResult<[u8; 32]> {
    let (client_participant_id, relayer_participant_id) =
        resolve_participant_ids(Some(client_participant_id), Some(relayer_participant_id))?;
    let client_point =
        decompress_verifying_share_point(*client_verifying_share_bytes, "client verifying share")?;
    let relayer_point = decompress_verifying_share_point(
        *relayer_verifying_share_bytes,
        "relayer verifying share",
    )?;

    let xc = CurveScalar::from(client_participant_id as u64);
    let xr = CurveScalar::from(relayer_participant_id as u64);
    let denom_c = xr - xc;
    let denom_r = xc - xr;
    if denom_c == CurveScalar::ZERO || denom_r == CurveScalar::ZERO {
        return Err(SignerCoreError::invalid_input(
            "clientParticipantId must differ from relayerParticipantId",
        ));
    }
    let lambda_c = xr * denom_c.invert();
    let lambda_r = xc * denom_r.invert();
    let group_point = client_point * lambda_c + relayer_point * lambda_r;
    Ok(group_point.compress().to_bytes())
}

pub fn threshold_ed25519_keygen_from_client_verifying_share(
    args: ThresholdEd25519KeygenFromClientVerifyingShareArgs,
) -> CoreResult<ThresholdEd25519KeygenOutput> {
    let (client_participant_id, relayer_participant_id) =
        resolve_participant_ids(args.client_participant_id, args.relayer_participant_id)?;
    let client_bytes =
        decode_base64_url_32(&args.client_verifying_share_b64u, "clientVerifyingShareB64u")?;
    let _client_point = decompress_verifying_share_point(client_bytes, "client verifying share")?;

    let mut rng = frost_ed25519::rand_core::OsRng;
    let relayer_scalar: CurveScalar = loop {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let scalar = CurveScalar::from_bytes_mod_order_wide(&wide);
        if scalar != CurveScalar::ZERO {
            break scalar;
        }
    };

    let relayer_signing_share_bytes = relayer_scalar.to_bytes();
    let relayer_verifying_share_bytes = scalar_to_verifying_share_bytes(&relayer_signing_share_bytes);
    let group_pk_bytes = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_bytes,
        &relayer_verifying_share_bytes,
        client_participant_id,
        relayer_participant_id,
    )?;

    let public_key = format!("ed25519:{}", bs58::encode(group_pk_bytes).into_string());
    Ok(ThresholdEd25519KeygenOutput {
        relayer_key_id: public_key.clone(),
        public_key,
        relayer_signing_share_b64u: Base64UrlUnpadded::encode_string(&relayer_signing_share_bytes),
        relayer_verifying_share_b64u: Base64UrlUnpadded::encode_string(&relayer_verifying_share_bytes),
    })
}

pub fn threshold_ed25519_keygen_from_master_secret_and_client_verifying_share(
    args: ThresholdEd25519KeygenFromMasterSecretArgs,
) -> CoreResult<ThresholdEd25519KeygenOutput> {
    let (client_participant_id, relayer_participant_id) =
        resolve_participant_ids(args.client_participant_id, args.relayer_participant_id)?;
    let master_secret_bytes = decode_master_secret_32(&args.master_secret_b64u)?;
    let client_bytes =
        decode_base64_url_32(&args.client_verifying_share_b64u, "clientVerifyingShareB64u")?;
    let _client_point = decompress_verifying_share_point(client_bytes, "client verifying share")?;

    let relayer_scalar = derive_threshold_relayer_share_scalar_v1(
        &master_secret_bytes,
        args.near_account_id.as_str(),
        args.rp_id.as_str(),
        &client_bytes,
    )?;
    let relayer_signing_share_bytes = relayer_scalar.to_bytes();
    let relayer_verifying_share_bytes = scalar_to_verifying_share_bytes(&relayer_signing_share_bytes);
    let group_pk_bytes = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_bytes,
        &relayer_verifying_share_bytes,
        client_participant_id,
        relayer_participant_id,
    )?;
    let public_key = format!("ed25519:{}", bs58::encode(group_pk_bytes).into_string());

    Ok(ThresholdEd25519KeygenOutput {
        relayer_key_id: public_key.clone(),
        public_key,
        relayer_signing_share_b64u: Base64UrlUnpadded::encode_string(&relayer_signing_share_bytes),
        relayer_verifying_share_b64u: Base64UrlUnpadded::encode_string(&relayer_verifying_share_bytes),
    })
}

pub fn threshold_ed25519_round1_commit(
    relayer_signing_share_b64u: &str,
) -> CoreResult<ThresholdEd25519Round1CommitOutput> {
    let share_bytes = decode_base64_url_32(relayer_signing_share_b64u, "relayerSigningShareB64u")?;
    let signing_share =
        frost_ed25519::keys::SigningShare::deserialize(&share_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!("Invalid relayer signing share: {e}"))
        })?;

    let mut rng = frost_ed25519::rand_core::OsRng;
    let (nonces, commitments) = frost_ed25519::round1::commit(&signing_share, &mut rng);
    let nonces_bytes = nonces.serialize().map_err(|e| {
        SignerCoreError::encode_error(format!("Failed to serialize signing nonces: {e}"))
    })?;
    let commitments_wire = near_threshold_ed25519::commitments_to_wire(&commitments)?;

    Ok(ThresholdEd25519Round1CommitOutput {
        relayer_nonces_b64u: Base64UrlUnpadded::encode_string(&nonces_bytes),
        relayer_commitments: commitments_wire,
    })
}

fn build_relayer_round2_context(
    args: &ThresholdEd25519Round2SignArgs,
) -> CoreResult<(
    frost_ed25519::round1::SigningNonces,
    frost_ed25519::SigningPackage,
    frost_ed25519::keys::KeyPackage,
    frost_ed25519::Identifier,
    frost_ed25519::VerifyingKey,
)> {
    let (client_id, relayer_id) =
        resolve_participant_ids(args.client_participant_id, args.relayer_participant_id)?;

    let share_bytes = decode_base64_url_32(&args.relayer_signing_share_b64u, "relayerSigningShareB64u")?;
    let nonces_bytes = decode_base64_url(&args.relayer_nonces_b64u, "relayerNoncesB64u")?;
    let nonces =
        frost_ed25519::round1::SigningNonces::deserialize(&nonces_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!("Invalid relayer signing nonces: {e}"))
        })?;

    let message = decode_base64_url(&args.signing_digest_b64u, "signingDigestB64u")?;
    let group_pk_bytes = parse_near_public_key_to_bytes(args.group_public_key.as_str())?;
    let verifying_key = frost_ed25519::VerifyingKey::deserialize(&group_pk_bytes).map_err(|e| {
        SignerCoreError::decode_error(format!("Invalid group public key: {e}"))
    })?;

    let relayer_signing_share =
        frost_ed25519::keys::SigningShare::deserialize(&share_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!("Invalid relayer signing share: {e}"))
        })?;
    let relayer_verifying_share_bytes = scalar_to_verifying_share_bytes(&share_bytes);
    let relayer_verifying_share =
        frost_ed25519::keys::VerifyingShare::deserialize(&relayer_verifying_share_bytes)
            .map_err(|e| {
                SignerCoreError::decode_error(format!("Invalid relayer verifying share: {e}"))
            })?;

    let relayer_identifier: frost_ed25519::Identifier = relayer_id
        .try_into()
        .map_err(|_| SignerCoreError::invalid_input("Invalid relayer identifier"))?;
    let client_identifier: frost_ed25519::Identifier = client_id
        .try_into()
        .map_err(|_| SignerCoreError::invalid_input("Invalid client identifier"))?;

    let key_package = frost_ed25519::keys::KeyPackage::new(
        relayer_identifier,
        relayer_signing_share,
        relayer_verifying_share,
        verifying_key.clone(),
        2,
    );

    let client_commitments = near_threshold_ed25519::commitments_from_wire(&args.client_commitments)?;
    let relayer_commitments =
        near_threshold_ed25519::commitments_from_wire(&args.relayer_commitments)?;

    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(client_identifier, client_commitments);
    commitments_map.insert(relayer_identifier, relayer_commitments);
    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message.as_slice());

    Ok((
        nonces,
        signing_package,
        key_package,
        relayer_identifier,
        verifying_key,
    ))
}

pub fn threshold_ed25519_round2_sign(
    args: ThresholdEd25519Round2SignArgs,
) -> CoreResult<ThresholdEd25519Round2SignOutput> {
    let (nonces, signing_package, key_package, _relayer_identifier, _verifying_key) =
        build_relayer_round2_context(&args)?;
    let share =
        near_threshold_ed25519::client_round2_signature_share(&signing_package, &nonces, &key_package)?;
    let relayer_signature_share_b64u = signature_share_to_b64u(&share)?;
    Ok(ThresholdEd25519Round2SignOutput {
        relayer_signature_share_b64u,
    })
}

pub fn threshold_ed25519_round2_sign_cosigner(
    args: ThresholdEd25519Round2SignArgs,
) -> CoreResult<ThresholdEd25519Round2SignOutput> {
    let (client_id, relayer_id) =
        resolve_participant_ids(args.client_participant_id, args.relayer_participant_id)?;
    let share_bytes = decode_base64_url_32(&args.relayer_signing_share_b64u, "relayerSigningShareB64u")?;
    let share_scalar = Option::<CurveScalar>::from(CurveScalar::from_canonical_bytes(share_bytes))
        .ok_or_else(|| SignerCoreError::decode_error("Invalid relayer signing share scalar"))?;

    let nonces_bytes = decode_base64_url(&args.relayer_nonces_b64u, "relayerNoncesB64u")?;
    let nonces =
        frost_ed25519::round1::SigningNonces::deserialize(&nonces_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!("Invalid relayer signing nonces: {e}"))
        })?;

    let hiding_bytes = nonces.hiding().serialize();
    if hiding_bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(
            "Invalid hiding nonce encoding",
        ));
    }
    let binding_bytes = nonces.binding().serialize();
    if binding_bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(
            "Invalid binding nonce encoding",
        ));
    }
    let hiding_scalar = Option::<CurveScalar>::from(CurveScalar::from_canonical_bytes(
        hiding_bytes
            .as_slice()
            .try_into()
            .expect("checked length above"),
    ))
    .ok_or_else(|| SignerCoreError::decode_error("Invalid hiding nonce scalar"))?;
    let binding_scalar = Option::<CurveScalar>::from(CurveScalar::from_canonical_bytes(
        binding_bytes
            .as_slice()
            .try_into()
            .expect("checked length above"),
    ))
    .ok_or_else(|| SignerCoreError::decode_error("Invalid binding nonce scalar"))?;

    let message = decode_base64_url(&args.signing_digest_b64u, "signingDigestB64u")?;
    let group_pk_bytes = parse_near_public_key_to_bytes(args.group_public_key.as_str())?;
    let verifying_key = frost_ed25519::VerifyingKey::deserialize(&group_pk_bytes).map_err(|e| {
        SignerCoreError::decode_error(format!("Invalid group public key: {e}"))
    })?;

    let relayer_identifier: frost_ed25519::Identifier = relayer_id
        .try_into()
        .map_err(|_| SignerCoreError::invalid_input("Invalid relayer identifier"))?;
    let client_identifier: frost_ed25519::Identifier = client_id
        .try_into()
        .map_err(|_| SignerCoreError::invalid_input("Invalid client identifier"))?;

    let client_commitments = near_threshold_ed25519::commitments_from_wire(&args.client_commitments)?;
    let relayer_commitments =
        near_threshold_ed25519::commitments_from_wire(&args.relayer_commitments)?;

    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(client_identifier, client_commitments);
    commitments_map.insert(relayer_identifier, relayer_commitments);
    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message.as_slice());

    let preimages = signing_package
        .binding_factor_preimages(&verifying_key, &[])
        .map_err(|e| {
            SignerCoreError::crypto_error(format!(
                "Failed to compute binding factor preimages: {e}"
            ))
        })?;
    let mut rho_by_id: BTreeMap<frost_ed25519::Identifier, CurveScalar> = BTreeMap::new();
    for (id, preimage) in preimages {
        let rho =
            <frost_ed25519::Ed25519Sha512 as frost_ed25519::Ciphersuite>::H1(preimage.as_slice());
        rho_by_id.insert(id, rho);
    }
    let rho_relayer = rho_by_id
        .get(&relayer_identifier)
        .ok_or_else(|| SignerCoreError::internal("Missing relayer binding factor"))?;

    let mut group_commitment: EdwardsPoint = EdwardsPoint::identity();
    for (id, commitment) in signing_package.signing_commitments() {
        let hiding_bytes = commitment.hiding().serialize().map_err(|e| {
            SignerCoreError::encode_error(format!("Invalid hiding commitment: {e}"))
        })?;
        if hiding_bytes.len() != 32 {
            return Err(SignerCoreError::invalid_length(
                "Invalid hiding commitment encoding",
            ));
        }
        let hiding = frost_ed25519::Ed25519Group::deserialize(
            hiding_bytes
                .as_slice()
                .try_into()
                .expect("checked length above"),
        )
        .map_err(|e| SignerCoreError::decode_error(format!("Invalid hiding commitment: {e}")))?;

        let binding_bytes = commitment.binding().serialize().map_err(|e| {
            SignerCoreError::encode_error(format!("Invalid binding commitment: {e}"))
        })?;
        if binding_bytes.len() != 32 {
            return Err(SignerCoreError::invalid_length(
                "Invalid binding commitment encoding",
            ));
        }
        let binding = frost_ed25519::Ed25519Group::deserialize(
            binding_bytes
                .as_slice()
                .try_into()
                .expect("checked length above"),
        )
        .map_err(|e| SignerCoreError::decode_error(format!("Invalid binding commitment: {e}")))?;

        let rho = rho_by_id.get(id).ok_or_else(|| {
            SignerCoreError::internal("Missing binding factor for commitment")
        })?;
        group_commitment = group_commitment + hiding + (binding * (*rho));
    }
    let group_commitment_bytes = frost_ed25519::Ed25519Group::serialize(&group_commitment)
        .map_err(|e| SignerCoreError::encode_error(format!("Invalid group commitment: {e}")))?;
    let verifying_key_bytes = verifying_key
        .serialize()
        .map_err(|e| SignerCoreError::encode_error(format!("Invalid verifying key: {e}")))?;

    let mut challenge_preimage = Vec::new();
    challenge_preimage.extend_from_slice(group_commitment_bytes.as_ref());
    challenge_preimage.extend_from_slice(verifying_key_bytes.as_ref());
    challenge_preimage.extend_from_slice(message.as_slice());
    let challenge = <frost_ed25519::Ed25519Sha512 as frost_ed25519::Ciphersuite>::H2(
        challenge_preimage.as_slice(),
    );

    let xc = CurveScalar::from(client_id as u64);
    let xr = CurveScalar::from(relayer_id as u64);
    let denom = xc - xr;
    if denom == CurveScalar::ZERO {
        return Err(SignerCoreError::invalid_input(
            "Invalid participant identifiers",
        ));
    }
    let lambda_relayer = xc * denom.invert();
    let z = hiding_scalar
        + (binding_scalar * (*rho_relayer))
        + (lambda_relayer * share_scalar * challenge);
    Ok(ThresholdEd25519Round2SignOutput {
        relayer_signature_share_b64u: Base64UrlUnpadded::encode_string(z.to_bytes().as_ref()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64u(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    #[test]
    fn deterministic_master_secret_keygen_is_stable_and_normalizes_rp_id() {
        let client_scalar = CurveScalar::from(5u64);
        let client_point = ED25519_BASEPOINT_POINT * client_scalar;
        let client_bytes = client_point.compress().to_bytes();

        let args = ThresholdEd25519KeygenFromMasterSecretArgs {
            client_participant_id: Some(1),
            relayer_participant_id: Some(2),
            master_secret_b64u: b64u(&[7u8; 32]),
            near_account_id: "alice.near".to_string(),
            rp_id: "Example.Com".to_string(),
            client_verifying_share_b64u: b64u(&client_bytes),
        };

        let out1 = threshold_ed25519_keygen_from_master_secret_and_client_verifying_share(
            args.clone(),
        )
        .expect("keygen should succeed");
        let out2 = threshold_ed25519_keygen_from_master_secret_and_client_verifying_share(
            args.clone(),
        )
        .expect("keygen should succeed");
        assert_eq!(out1.relayer_signing_share_b64u, out2.relayer_signing_share_b64u);
        assert_eq!(out1.public_key, out2.public_key);

        let mut args_lower = args;
        args_lower.rp_id = "example.com".to_string();
        let out3 = threshold_ed25519_keygen_from_master_secret_and_client_verifying_share(
            args_lower,
        )
        .expect("keygen should succeed");
        assert_eq!(out1.relayer_signing_share_b64u, out3.relayer_signing_share_b64u);
    }

    #[test]
    fn compute_group_public_key_rejects_same_participant_ids() {
        let client_bytes = (ED25519_BASEPOINT_POINT * CurveScalar::from(2u64))
            .compress()
            .to_bytes();
        let relayer_bytes = (ED25519_BASEPOINT_POINT * CurveScalar::from(3u64))
            .compress()
            .to_bytes();
        let err = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
            &client_bytes,
            &relayer_bytes,
            1,
            1,
        )
        .expect_err("same participant ids should fail");
        assert!(err.message.contains("must differ"));
    }

    #[test]
    fn round1_commit_rejects_invalid_share_length() {
        let err = threshold_ed25519_round1_commit(&b64u(&[1u8; 31]))
            .expect_err("invalid length should fail");
        assert!(err.message.contains("32 bytes"));
    }
}
