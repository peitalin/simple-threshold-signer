use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes};
use rand_core::OsRng;
use threshold_signatures::ecdsa::ot_based_ecdsa::{
    presign::presign,
    triples::{generate_triple_many, TriplePub, TripleShare},
    PresignArguments, PresignOutput, RerandomizedPresignOutput,
};
use threshold_signatures::ecdsa::{
    KeygenOutput, RerandomizationArguments, Scalar as TsScalar, Secp256K1Sha256,
    Signature as TsSignature, Tweak,
};
use threshold_signatures::errors::{InitializationError, ProtocolError};
use threshold_signatures::frost_secp256k1::{
    keys::SigningShare, Field, Secp256K1ScalarField, VerifyingKey,
};
use threshold_signatures::participants::{Participant, ParticipantList};
use threshold_signatures::protocol::{Action, Protocol};

use crate::error::{CoreResult, SignerCoreError};

fn map_proto_err(e: ProtocolError) -> SignerCoreError {
    SignerCoreError::crypto_error(format!("protocol failed: {e:?}"))
}

fn map_init_err(e: InitializationError) -> SignerCoreError {
    SignerCoreError::invalid_input(format!("protocol init failed: {e:?}"))
}

fn parse_scalar_32(bytes: &[u8], field_name: &str) -> CoreResult<TsScalar> {
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(format!("{field_name} must be 32 bytes")))?;
    Option::<TsScalar>::from(TsScalar::from_repr(arr.into())).ok_or_else(|| {
        SignerCoreError::invalid_input(format!("{field_name} is not a valid secp256k1 scalar"))
    })
}

fn parse_nonzero_scalar_32(bytes: &[u8], field_name: &str) -> CoreResult<TsScalar> {
    let scalar = parse_scalar_32(bytes, field_name)?;
    if bool::from(scalar.is_zero()) {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-zero"
        )));
    }
    Ok(scalar)
}

fn parse_digest_32(bytes: &[u8], field_name: &str) -> CoreResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    bytes
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(format!("{field_name} must be 32 bytes")))
}

fn parse_affine_point_33(bytes: &[u8], field_name: &str) -> CoreResult<AffinePoint> {
    if bytes.len() != 33 && bytes.len() != 65 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 33 (compressed) or 65 (uncompressed) bytes (got {})",
            bytes.len()
        )));
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| {
        SignerCoreError::decode_error(format!("{field_name} is not valid SEC1 bytes"))
    })?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).ok_or_else(|| {
        SignerCoreError::invalid_input(format!("{field_name} is not a valid secp256k1 point"))
    })
}

fn build_participant_list(ids: &[u32]) -> CoreResult<(Vec<Participant>, ParticipantList)> {
    if ids.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "participantIds must be non-empty",
        ));
    }
    let participants: Vec<Participant> = ids.iter().map(|id| Participant::from(*id)).collect();
    let list = ParticipantList::new(&participants).ok_or_else(|| {
        SignerCoreError::invalid_input("participantIds must not contain duplicates")
    })?;
    Ok((participants, list))
}

fn x_coordinate_scalar(point: &AffinePoint) -> TsScalar {
    <TsScalar as Reduce<U256>>::reduce_bytes(&point.x())
}

type TripleManyOutput = Vec<(TripleShare, TriplePub)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresignStage {
    Triples,
    TriplesDone,
    Presign,
    Done,
}

impl PresignStage {
    fn as_str(&self) -> &'static str {
        match self {
            PresignStage::Triples => "triples",
            PresignStage::TriplesDone => "triples_done",
            PresignStage::Presign => "presign",
            PresignStage::Done => "done",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThresholdEcdsaPresignProgress {
    pub stage: String,
    pub event: String,
    pub outgoing: Vec<Vec<u8>>,
}

pub struct ThresholdEcdsaPresignSession {
    stage: PresignStage,
    participants: Vec<Participant>,
    me: Participant,
    threshold: usize,
    keygen_out: KeygenOutput,
    triple_protocol: Option<Box<dyn Protocol<Output = TripleManyOutput>>>,
    triples_output: Option<TripleManyOutput>,
    presign_protocol: Option<Box<dyn Protocol<Output = PresignOutput>>>,
    presign_output: Option<PresignOutput>,
}

impl ThresholdEcdsaPresignSession {
    pub fn new(
        participant_ids: &[u32],
        me: u32,
        threshold: u32,
        private_share32: &[u8],
        public_key_sec1: &[u8],
    ) -> CoreResult<Self> {
        let (participants, participants_list) = build_participant_list(participant_ids)?;
        let me = Participant::from(me);
        if !participants_list.contains(me) {
            return Err(SignerCoreError::invalid_input(
                "me must be included in participantIds",
            ));
        }
        let threshold_usize = usize::try_from(threshold)
            .map_err(|_| SignerCoreError::invalid_input("threshold out of range"))?;
        if threshold_usize < 2 {
            return Err(SignerCoreError::invalid_input("threshold must be >= 2"));
        }
        if threshold_usize > participants.len() {
            return Err(SignerCoreError::invalid_input(
                "threshold must be <= number of participants",
            ));
        }

        let private_share_scalar = parse_nonzero_scalar_32(private_share32, "private_share32")?;
        let signing_share = SigningShare::new(private_share_scalar);

        let pk_affine = parse_affine_point_33(public_key_sec1, "public_key_sec1")?;
        let verifying_key = VerifyingKey::new(pk_affine.into());

        let keygen_out = KeygenOutput {
            private_share: signing_share,
            public_key: verifying_key,
        };

        let protocol = generate_triple_many::<2>(&participants, me, threshold_usize, OsRng)
            .map_err(map_init_err)?;

        Ok(Self {
            stage: PresignStage::Triples,
            participants,
            me,
            threshold: threshold_usize,
            keygen_out,
            triple_protocol: Some(Box::new(protocol)),
            triples_output: None,
            presign_protocol: None,
            presign_output: None,
        })
    }

    pub fn stage(&self) -> &'static str {
        self.stage.as_str()
    }

    pub fn is_done(&self) -> bool {
        self.stage == PresignStage::Done
    }

    pub fn poll(&mut self) -> CoreResult<ThresholdEcdsaPresignProgress> {
        let mut outgoing: Vec<Vec<u8>> = Vec::new();
        let mut event = "none";

        loop {
            match self.stage {
                PresignStage::Triples => {
                    let proto = self
                        .triple_protocol
                        .as_mut()
                        .ok_or_else(|| SignerCoreError::internal("missing triple protocol"))?;
                    match proto.poke().map_err(map_proto_err)? {
                        Action::Wait => break,
                        Action::SendMany(data) => outgoing.push(data),
                        Action::SendPrivate(_, data) => outgoing.push(data),
                        Action::Return(output) => {
                            self.triples_output = Some(output);
                            self.triple_protocol = None;
                            self.stage = PresignStage::TriplesDone;
                            event = "triples_done";
                            break;
                        }
                    }
                }
                PresignStage::Presign => {
                    let proto = self
                        .presign_protocol
                        .as_mut()
                        .ok_or_else(|| SignerCoreError::internal("missing presign protocol"))?;
                    match proto.poke().map_err(map_proto_err)? {
                        Action::Wait => break,
                        Action::SendMany(data) => outgoing.push(data),
                        Action::SendPrivate(_, data) => outgoing.push(data),
                        Action::Return(output) => {
                            self.presign_output = Some(output);
                            self.presign_protocol = None;
                            self.stage = PresignStage::Done;
                            event = "presign_done";
                            break;
                        }
                    }
                }
                PresignStage::TriplesDone | PresignStage::Done => break,
            }
        }

        Ok(ThresholdEcdsaPresignProgress {
            stage: self.stage.as_str().to_string(),
            event: event.to_string(),
            outgoing,
        })
    }

    pub fn message(&mut self, from: u32, data: &[u8]) -> CoreResult<()> {
        let from = Participant::from(from);
        match self.stage {
            PresignStage::Triples => {
                let proto = self
                    .triple_protocol
                    .as_mut()
                    .ok_or_else(|| SignerCoreError::internal("missing triple protocol"))?;
                proto.message(from, data.to_vec());
                Ok(())
            }
            PresignStage::Presign => {
                let proto = self
                    .presign_protocol
                    .as_mut()
                    .ok_or_else(|| SignerCoreError::internal("missing presign protocol"))?;
                proto.message(from, data.to_vec());
                Ok(())
            }
            PresignStage::TriplesDone | PresignStage::Done => Err(SignerCoreError::invalid_input(
                "cannot accept messages: presign session is not in an active protocol stage",
            )),
        }
    }

    pub fn start_presign(&mut self) -> CoreResult<()> {
        if self.stage != PresignStage::TriplesDone {
            return Err(SignerCoreError::invalid_input(
                "start_presign is only valid after triples stage completes",
            ));
        }
        let triples = self
            .triples_output
            .take()
            .ok_or_else(|| SignerCoreError::internal("missing triples output"))?;
        if triples.len() < 2 {
            return Err(SignerCoreError::invalid_input(
                "triples output must contain at least 2 triples",
            ));
        }

        let args = PresignArguments {
            triple0: triples[0].clone(),
            triple1: triples[1].clone(),
            keygen_out: self.keygen_out.clone(),
            threshold: self.threshold,
        };
        let protocol = presign(&self.participants, self.me, args).map_err(map_init_err)?;
        self.presign_protocol = Some(Box::new(protocol));
        self.stage = PresignStage::Presign;
        Ok(())
    }

    pub fn take_presignature_97(&mut self) -> CoreResult<Vec<u8>> {
        if self.stage != PresignStage::Done {
            return Err(SignerCoreError::invalid_input(
                "presign session is not done",
            ));
        }
        let out = self
            .presign_output
            .take()
            .ok_or_else(|| SignerCoreError::internal("missing presign output"))?;

        let mut bytes = Vec::with_capacity(97);
        bytes.extend_from_slice(out.big_r.to_encoded_point(true).as_bytes());
        bytes.extend_from_slice(&<Secp256K1ScalarField as Field>::serialize(&out.k));
        bytes.extend_from_slice(&<Secp256K1ScalarField as Field>::serialize(&out.sigma));
        Ok(bytes)
    }
}

pub fn threshold_ecdsa_compute_signature_share(
    participant_ids: &[u32],
    me: u32,
    public_key_sec1: &[u8],
    presign_big_r_sec1: &[u8],
    presign_k_share32: &[u8],
    presign_sigma_share32: &[u8],
    digest32: &[u8],
    entropy32: &[u8],
) -> CoreResult<Vec<u8>> {
    let (_participants, participants_list) = build_participant_list(participant_ids)?;
    let me = Participant::from(me);
    if !participants_list.contains(me) {
        return Err(SignerCoreError::invalid_input(
            "me must be included in participantIds",
        ));
    }

    let pk = parse_affine_point_33(public_key_sec1, "public_key_sec1")?;
    let presign_big_r = parse_affine_point_33(presign_big_r_sec1, "presign_big_r_sec1")?;
    let k = parse_scalar_32(presign_k_share32, "presign_k_share32")?;
    let sigma = parse_scalar_32(presign_sigma_share32, "presign_sigma_share32")?;
    let digest_arr = parse_digest_32(digest32, "digest32")?;
    let entropy_arr = parse_digest_32(entropy32, "entropy32")?;

    let args = RerandomizationArguments::new(
        pk,
        Tweak::new(TsScalar::ZERO),
        digest_arr,
        presign_big_r,
        participants_list.clone(),
        entropy_arr,
    );
    let presign = PresignOutput {
        big_r: presign_big_r,
        k,
        sigma,
    };
    let rerand =
        RerandomizedPresignOutput::rerandomize_presign(&presign, &args).map_err(map_proto_err)?;

    let lambda = participants_list
        .lagrange::<Secp256K1Sha256>(me)
        .map_err(map_proto_err)?;
    let k_i = lambda * rerand.k;
    let sigma_i = lambda * rerand.sigma;

    let h = <TsScalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(digest_arr));
    let r = x_coordinate_scalar(&rerand.big_r);
    let s_i = h * k_i + r * sigma_i;
    Ok(<Secp256K1ScalarField as Field>::serialize(&s_i).to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn threshold_ecdsa_finalize_signature(
    participant_ids: &[u32],
    relayer_id: u32,
    public_key_sec1: &[u8],
    presign_big_r_sec1: &[u8],
    relayer_k_share32: &[u8],
    relayer_sigma_share32: &[u8],
    digest32: &[u8],
    entropy32: &[u8],
    client_signature_share32: &[u8],
) -> CoreResult<Vec<u8>> {
    let (_participants, participants_list) = build_participant_list(participant_ids)?;
    let relayer = Participant::from(relayer_id);
    if !participants_list.contains(relayer) {
        return Err(SignerCoreError::invalid_input(
            "relayer_id must be included in participantIds",
        ));
    }

    let pk = parse_affine_point_33(public_key_sec1, "public_key_sec1")?;
    let presign_big_r = parse_affine_point_33(presign_big_r_sec1, "presign_big_r_sec1")?;
    let k = parse_scalar_32(relayer_k_share32, "relayer_k_share32")?;
    let sigma = parse_scalar_32(relayer_sigma_share32, "relayer_sigma_share32")?;
    let digest_arr = parse_digest_32(digest32, "digest32")?;
    let entropy_arr = parse_digest_32(entropy32, "entropy32")?;
    let client_share = parse_scalar_32(client_signature_share32, "client_signature_share32")?;

    let args = RerandomizationArguments::new(
        pk,
        Tweak::new(TsScalar::ZERO),
        digest_arr,
        presign_big_r,
        participants_list.clone(),
        entropy_arr,
    );
    let presign = PresignOutput {
        big_r: presign_big_r,
        k,
        sigma,
    };
    let rerand =
        RerandomizedPresignOutput::rerandomize_presign(&presign, &args).map_err(map_proto_err)?;

    let lambda = participants_list
        .lagrange::<Secp256K1Sha256>(relayer)
        .map_err(map_proto_err)?;
    let k_i = lambda * rerand.k;
    let sigma_i = lambda * rerand.sigma;
    let h = <TsScalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(digest_arr));
    let r_scalar = x_coordinate_scalar(&rerand.big_r);
    let relayer_share = h * k_i + r_scalar * sigma_i;

    let mut s = client_share + relayer_share;
    if bool::from(s.is_high()) {
        s = -s;
    }

    let full_sig = TsSignature {
        big_r: rerand.big_r,
        s,
    };
    if !full_sig.verify(&pk, &h) {
        return Err(SignerCoreError::crypto_error(
            "final signature failed to verify",
        ));
    }

    let sig = K256Signature::from_scalars(
        <Secp256K1ScalarField as Field>::serialize(&r_scalar),
        <Secp256K1ScalarField as Field>::serialize(&s),
    )
    .map_err(|_| SignerCoreError::crypto_error("failed to build ECDSA signature"))?;

    let expected_vk = K256VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| SignerCoreError::invalid_input("invalid public_key_sec1"))?;

    let mut recid_out: Option<u8> = None;
    for id in 0u8..=3u8 {
        let Some(recid) = RecoveryId::from_byte(id) else {
            continue;
        };
        let recovered = K256VerifyingKey::recover_from_prehash(&digest_arr, &sig, recid);
        if let Ok(vk) = recovered {
            if vk.to_encoded_point(true).as_bytes() == expected_vk.to_encoded_point(true).as_bytes()
            {
                recid_out = Some(id);
                break;
            }
        }
    }

    let recid = recid_out.ok_or_else(|| {
        SignerCoreError::crypto_error("failed to recover public key (no valid recId found)")
    })?;

    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(sig.r().to_bytes().as_ref());
    out.extend_from_slice(sig.s().to_bytes().as_ref());
    out.push(recid);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SignerCoreErrorCode;

    #[test]
    fn compute_signature_share_requires_participants() {
        let err = threshold_ecdsa_compute_signature_share(&[], 1, &[], &[], &[], &[], &[], &[])
            .expect_err("missing participants should fail");
        assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
    }

    #[test]
    fn finalize_signature_requires_participants() {
        let err = threshold_ecdsa_finalize_signature(&[], 2, &[], &[], &[], &[], &[], &[], &[])
            .expect_err("missing participants should fail");
        assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
    }
}
