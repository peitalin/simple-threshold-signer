use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar as CurveScalar;
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::{CoreResult, SignerCoreError};

pub const THRESHOLD_CLIENT_SHARE_SALT_V1: &[u8] = b"tatchi/lite/threshold-ed25519/client-share:v1";

fn decode_wrap_key_seed_b64u(wrap_key_seed_b64u: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(wrap_key_seed_b64u)
        .map_err(|e| SignerCoreError::decode_error(format!("Base64 decode error: {}", e)))
}

fn decode_base64_url(input: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| SignerCoreError::decode_error(format!("Base64 decode error: {}", e)))
}

fn encode_base64_url(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}

pub fn base64_url_encode(input: &[u8]) -> String {
    encode_base64_url(input)
}

pub fn parse_near_public_key_to_bytes(public_key: &str) -> CoreResult<[u8; 32]> {
    let decoded = bs58::decode(public_key.strip_prefix("ed25519:").unwrap_or(public_key))
        .into_vec()
        .map_err(|e| SignerCoreError::decode_error(format!("Invalid public key base58: {e}")))?;
    if decoded.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "Invalid public key length: expected 32 bytes, got {}",
            decoded.len()
        )));
    }
    Ok(decoded.as_slice().try_into().expect("checked length above"))
}

fn derive_threshold_client_share_scalar_v1_from_wrap_key_seed(
    wrap_key_seed: &[u8],
    near_account_id: &str,
) -> CoreResult<CurveScalar> {
    if wrap_key_seed.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "threshold-signer: invalid WrapKeySeed length: expected 32 bytes, got {}",
            wrap_key_seed.len()
        )));
    }

    let hk = Hkdf::<Sha256>::new(Some(THRESHOLD_CLIENT_SHARE_SALT_V1), wrap_key_seed);
    let mut okm = [0u8; 64];

    // v1: info = nearAccountId || 0x00 || u32be(derivationPath=0)
    let mut info = Vec::with_capacity(near_account_id.len() + 1 + 4);
    info.extend_from_slice(near_account_id.as_bytes());
    info.push(0);
    info.extend_from_slice(&0u32.to_be_bytes());

    hk.expand(&info, &mut okm)
        .map_err(|_| SignerCoreError::hkdf_error("threshold-signer: HKDF expand failed"))?;

    let scalar = CurveScalar::from_bytes_mod_order_wide(&okm);
    if scalar == CurveScalar::ZERO {
        return Err(SignerCoreError::crypto_error(
            "threshold-signer: derived client signing share is zero",
        ));
    }
    Ok(scalar)
}

pub fn derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed(
    wrap_key_seed: &[u8],
    near_account_id: &str,
) -> CoreResult<[u8; 32]> {
    Ok(
        derive_threshold_client_share_scalar_v1_from_wrap_key_seed(wrap_key_seed, near_account_id)?
            .to_bytes(),
    )
}

pub fn derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
    wrap_key_seed_b64u: &str,
    near_account_id: &str,
) -> CoreResult<[u8; 32]> {
    let wrap_key_seed = decode_wrap_key_seed_b64u(wrap_key_seed_b64u)?;
    derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed(
        wrap_key_seed.as_slice(),
        near_account_id,
    )
}

pub fn derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed(
    wrap_key_seed: &[u8],
    near_account_id: &str,
) -> CoreResult<[u8; 32]> {
    let scalar =
        derive_threshold_client_share_scalar_v1_from_wrap_key_seed(wrap_key_seed, near_account_id)?;
    Ok((ED25519_BASEPOINT_POINT * scalar).compress().to_bytes())
}

pub fn derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed_b64u(
    wrap_key_seed_b64u: &str,
    near_account_id: &str,
) -> CoreResult<[u8; 32]> {
    let wrap_key_seed = decode_wrap_key_seed_b64u(wrap_key_seed_b64u)?;
    derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed(
        wrap_key_seed.as_slice(),
        near_account_id,
    )
}

pub fn derive_threshold_client_verifying_share_b64u_v1_from_wrap_key_seed_b64u(
    wrap_key_seed_b64u: &str,
    near_account_id: &str,
) -> CoreResult<String> {
    let bytes = derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed_b64u(
        wrap_key_seed_b64u,
        near_account_id,
    )?;
    Ok(encode_base64_url(&bytes))
}

pub fn derive_client_key_package_from_wrap_key_seed_b64u(
    wrap_key_seed_b64u: &str,
    near_account_id: &str,
    near_public_key_bytes: &[u8; 32],
    client_identifier: frost_ed25519::Identifier,
) -> CoreResult<frost_ed25519::keys::KeyPackage> {
    let signing_share_bytes =
        derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
            wrap_key_seed_b64u,
            near_account_id,
        )?;
    let signing_share = frost_ed25519::keys::SigningShare::deserialize(&signing_share_bytes)
        .map_err(|e| {
            SignerCoreError::decode_error(format!(
                "threshold-signer: invalid derived signing share: {e}"
            ))
        })?;

    let verifying_share_bytes =
        derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed_b64u(
            wrap_key_seed_b64u,
            near_account_id,
        )?;
    let verifying_share = frost_ed25519::keys::VerifyingShare::deserialize(&verifying_share_bytes)
        .map_err(|e| {
            SignerCoreError::decode_error(format!("threshold-signer: invalid verifying share: {e}"))
        })?;

    let verifying_key =
        frost_ed25519::VerifyingKey::deserialize(near_public_key_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!(
                "threshold-signer: invalid group public key: {e}"
            ))
        })?;

    Ok(frost_ed25519::keys::KeyPackage::new(
        client_identifier,
        signing_share,
        verifying_share,
        verifying_key,
        2,
    ))
}

pub fn compute_nep413_signing_digest_from_nonce_base64(
    message: &str,
    recipient: &str,
    nonce_base64: &str,
    state: Option<&str>,
) -> CoreResult<[u8; 32]> {
    let nonce_bytes = Base64::decode_vec(nonce_base64.trim())
        .map_err(|e| SignerCoreError::decode_error(format!("Invalid nonce (base64): {e}")))?;
    if nonce_bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "Invalid nonce length: expected 32 bytes, got {}",
            nonce_bytes.len()
        )));
    }
    let nonce_array: [u8; 32] = nonce_bytes
        .as_slice()
        .try_into()
        .expect("checked length above");
    compute_nep413_signing_digest_from_nonce_bytes(message, recipient, nonce_array, state)
}

pub fn compute_nep413_signing_digest_from_nonce_bytes(
    message: &str,
    recipient: &str,
    nonce: [u8; 32],
    state: Option<&str>,
) -> CoreResult<[u8; 32]> {
    #[derive(borsh::BorshSerialize)]
    struct Nep413PayloadBorsh {
        message: String,
        recipient: String,
        nonce: [u8; 32],
        state: Option<String>,
    }

    let payload_borsh = Nep413PayloadBorsh {
        message: message.to_string(),
        recipient: recipient.to_string(),
        nonce,
        state: state.map(|s| s.to_string()),
    };

    let serialized = borsh::to_vec(&payload_borsh)
        .map_err(|e| SignerCoreError::encode_error(format!("Borsh serialization failed: {e}")))?;
    let prefix: u32 = 2_147_484_061;
    let mut prefixed = prefix.to_le_bytes().to_vec();
    prefixed.extend_from_slice(&serialized);

    let mut hasher = Sha256::new();
    hasher.update(&prefixed);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn join_participant_ids(ids: &[u16]) -> String {
    ids.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

pub fn normalize_participant_ids(ids: Option<&Vec<u16>>) -> Vec<u16> {
    let mut out: Vec<u16> = ids
        .map(|values| values.iter().copied().filter(|n| *n > 0).collect())
        .unwrap_or_default();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn validate_threshold_ed25519_participant_ids_2p(
    client_id_opt: Option<u16>,
    relayer_id_opt: Option<u16>,
    participant_ids_norm: &[u16],
) -> CoreResult<(u16, u16)> {
    let (client_id, relayer_id) = match (client_id_opt, relayer_id_opt) {
        (Some(c), Some(r)) => {
            if c == r {
                return Err(SignerCoreError::invalid_input(
                    "threshold-signer: clientParticipantId must differ from relayerParticipantId",
                ));
            }
            if !participant_ids_norm.is_empty() {
                if participant_ids_norm.len() < 2 {
                    return Err(SignerCoreError::invalid_input(
                        "threshold-signer: participantIds must contain at least 2 ids",
                    ));
                }
                if !participant_ids_norm.contains(&c) || !participant_ids_norm.contains(&r) {
                    let mut expected = vec![c, r];
                    expected.sort_unstable();
                    expected.dedup();
                    return Err(SignerCoreError::invalid_input(format!(
                        "threshold-signer: participantIds must include clientParticipantId/relayerParticipantId (expected to include participantIds=[{}], got participantIds=[{}])",
                        join_participant_ids(&expected),
                        join_participant_ids(participant_ids_norm),
                    )));
                }
            }
            (c, r)
        }
        (None, None) => {
            if participant_ids_norm.is_empty() {
                (1u16, 2u16)
            } else if participant_ids_norm.len() == 2 {
                (participant_ids_norm[0], participant_ids_norm[1])
            } else if participant_ids_norm.len() > 2 {
                return Err(SignerCoreError::invalid_input(
                    "threshold-signer: participantIds contains more than 2 ids; set clientParticipantId and relayerParticipantId to select the signer set",
                ));
            } else {
                return Err(SignerCoreError::invalid_input(
                    "threshold-signer: participantIds must contain at least 2 ids",
                ));
            }
        }
        _ => {
            return Err(SignerCoreError::invalid_input(
                "threshold-signer: clientParticipantId and relayerParticipantId must be set together",
            ));
        }
    };

    Ok((client_id, relayer_id))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitmentsWire {
    pub hiding: String,
    pub binding: String,
}

pub struct ClientRound1State {
    pub nonces: frost_ed25519::round1::SigningNonces,
    pub commitments: frost_ed25519::round1::SigningCommitments,
    pub commitments_wire: CommitmentsWire,
}

pub fn client_round1_commit(
    key_package: &frost_ed25519::keys::KeyPackage,
) -> CoreResult<ClientRound1State> {
    let (nonces, commitments) =
        frost_ed25519::round1::commit(key_package.signing_share(), &mut OsRng);
    let commitments_wire = commitments_to_wire(&commitments)?;
    Ok(ClientRound1State {
        nonces,
        commitments,
        commitments_wire,
    })
}

pub fn commitments_to_wire(
    commitments: &frost_ed25519::round1::SigningCommitments,
) -> CoreResult<CommitmentsWire> {
    let hiding_bytes = commitments.hiding().serialize().map_err(|e| {
        SignerCoreError::encode_error(format!(
            "threshold-signer: serialize hiding commitment: {e}"
        ))
    })?;
    let binding_bytes = commitments.binding().serialize().map_err(|e| {
        SignerCoreError::encode_error(format!(
            "threshold-signer: serialize binding commitment: {e}"
        ))
    })?;
    Ok(CommitmentsWire {
        hiding: encode_base64_url(&hiding_bytes),
        binding: encode_base64_url(&binding_bytes),
    })
}

pub fn commitments_from_wire(
    wire: &CommitmentsWire,
) -> CoreResult<frost_ed25519::round1::SigningCommitments> {
    let hiding_bytes = decode_base64_url(wire.hiding.trim()).map_err(|e| {
        SignerCoreError::decode_error(format!(
            "threshold-signer: invalid commitments.hiding: {}",
            e.message
        ))
    })?;
    let binding_bytes = decode_base64_url(wire.binding.trim()).map_err(|e| {
        SignerCoreError::decode_error(format!(
            "threshold-signer: invalid commitments.binding: {}",
            e.message
        ))
    })?;

    let hiding =
        frost_ed25519::round1::NonceCommitment::deserialize(&hiding_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!(
                "threshold-signer: invalid hiding commitment: {e}"
            ))
        })?;
    let binding =
        frost_ed25519::round1::NonceCommitment::deserialize(&binding_bytes).map_err(|e| {
            SignerCoreError::decode_error(format!(
                "threshold-signer: invalid binding commitment: {e}"
            ))
        })?;
    Ok(frost_ed25519::round1::SigningCommitments::new(
        hiding, binding,
    ))
}

pub fn build_signing_package(
    message: &[u8],
    commitments_by_id: BTreeMap<
        frost_ed25519::Identifier,
        frost_ed25519::round1::SigningCommitments,
    >,
) -> frost_ed25519::SigningPackage {
    frost_ed25519::SigningPackage::new(commitments_by_id, message)
}

pub fn client_round2_signature_share(
    signing_package: &frost_ed25519::SigningPackage,
    nonces: &frost_ed25519::round1::SigningNonces,
    key_package: &frost_ed25519::keys::KeyPackage,
) -> CoreResult<frost_ed25519::round2::SignatureShare> {
    frost_ed25519::round2::sign(signing_package, nonces, key_package).map_err(|e| {
        SignerCoreError::crypto_error(format!("threshold-signer: round2 sign failed: {e}"))
    })
}

pub fn signature_share_to_b64u(
    share: &frost_ed25519::round2::SignatureShare,
) -> CoreResult<String> {
    Ok(encode_base64_url(&share.serialize()))
}

pub fn signature_share_from_b64u(b64u: &str) -> CoreResult<frost_ed25519::round2::SignatureShare> {
    let bytes = decode_base64_url(b64u.trim()).map_err(|e| {
        SignerCoreError::decode_error(format!(
            "threshold-signer: invalid signature share: {}",
            e.message
        ))
    })?;
    frost_ed25519::round2::SignatureShare::deserialize(&bytes).map_err(|e| {
        SignerCoreError::decode_error(format!("threshold-signer: invalid signature share: {e}"))
    })
}

pub fn verifying_share_from_b64u(b64u: &str) -> CoreResult<frost_ed25519::keys::VerifyingShare> {
    let bytes = decode_base64_url(b64u.trim()).map_err(|e| {
        SignerCoreError::decode_error(format!(
            "threshold-signer: invalid verifying share: {}",
            e.message
        ))
    })?;
    frost_ed25519::keys::VerifyingShare::deserialize(&bytes).map_err(|e| {
        SignerCoreError::decode_error(format!("threshold-signer: invalid verifying share: {e}"))
    })
}

pub fn aggregate_signature(
    signing_package: &frost_ed25519::SigningPackage,
    verifying_key: frost_ed25519::VerifyingKey,
    verifying_shares: BTreeMap<frost_ed25519::Identifier, frost_ed25519::keys::VerifyingShare>,
    signature_shares: BTreeMap<frost_ed25519::Identifier, frost_ed25519::round2::SignatureShare>,
) -> CoreResult<[u8; 64]> {
    let pubkey_package =
        frost_ed25519::keys::PublicKeyPackage::new(verifying_shares, verifying_key);
    let group_signature =
        frost_ed25519::aggregate(signing_package, &signature_shares, &pubkey_package).map_err(
            |e| SignerCoreError::crypto_error(format!("threshold-signer: aggregate failed: {e}")),
        )?;
    let bytes = group_signature.serialize().map_err(|e| {
        SignerCoreError::encode_error(format!(
            "threshold-signer: signature serialization failed: {e}"
        ))
    })?;
    if bytes.len() != 64 {
        return Err(SignerCoreError::invalid_length(format!(
            "threshold-signer: invalid signature length from aggregation: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64u(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    #[test]
    fn derive_client_share_is_deterministic_and_matches_verifying_share() {
        let wrap_key_seed_b64u = b64u(&[7u8; 32]);

        let s1 = derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
            &wrap_key_seed_b64u,
            "alice.near",
        )
        .expect("signing share should derive");
        let s2 = derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
            &wrap_key_seed_b64u,
            "alice.near",
        )
        .expect("signing share should derive");
        assert_eq!(s1, s2);

        let v1 = derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed_b64u(
            &wrap_key_seed_b64u,
            "alice.near",
        )
        .expect("verifying share should derive");
        let scalar = CurveScalar::from_bytes_mod_order(s1);
        let expected = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
        assert_eq!(v1, expected);

        let different_account =
            derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
                &wrap_key_seed_b64u,
                "bob.near",
            )
            .expect("signing share should derive");
        assert_ne!(s1, different_account);
    }

    #[test]
    fn derive_client_share_rejects_invalid_seed_length() {
        let wrap_key_seed_b64u = b64u(&[1u8; 31]);
        let err = derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
            &wrap_key_seed_b64u,
            "alice.near",
        )
        .expect_err("invalid seed length should fail");

        assert!(
            err.message.contains("expected 32 bytes"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn participant_ids_default_to_1_2() {
        let ids = normalize_participant_ids(None);
        let (client, relayer) =
            validate_threshold_ed25519_participant_ids_2p(None, None, ids.as_slice())
                .expect("default ids");
        assert_eq!((client, relayer), (1, 2));
    }

    #[test]
    fn participant_ids_reject_mismatch_when_explicit_pair_missing_from_list() {
        let ids = vec![3, 4];
        let err = validate_threshold_ed25519_participant_ids_2p(Some(1), Some(2), ids.as_slice())
            .expect_err("mismatch should fail");
        assert!(err
            .message
            .contains("must include clientParticipantId/relayerParticipantId"));
    }

    #[test]
    fn parse_near_public_key_accepts_ed25519_prefix() {
        let expected = [11u8; 32];
        let key = format!("ed25519:{}", bs58::encode(expected).into_string());
        let parsed = parse_near_public_key_to_bytes(&key).expect("valid key");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn compute_nep413_digest_rejects_short_nonce() {
        let nonce_b64 = Base64::encode_string(&[7u8; 16]);
        let err = compute_nep413_signing_digest_from_nonce_base64(
            "hello",
            "example.near",
            &nonce_b64,
            None,
        )
        .expect_err("short nonce should fail");
        assert!(err.message.contains("expected 32 bytes"));
    }
}
