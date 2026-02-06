use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

use js_sys::{Array, Object, Reflect, Uint8Array};
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint};
use rand_core::OsRng;
use threshold_signatures::ecdsa::{
    ot_based_ecdsa::{
        presign::presign,
        triples::{generate_triple_many, TriplePub, TripleShare},
        PresignArguments, PresignOutput, RerandomizedPresignOutput,
    },
    KeygenOutput, RerandomizationArguments, Scalar as TsScalar, Secp256K1Sha256,
    Signature as TsSignature, Tweak,
};
use threshold_signatures::errors::{InitializationError, ProtocolError};
use threshold_signatures::frost_secp256k1::{
    keys::SigningShare, Field, Secp256K1ScalarField, VerifyingKey,
};
use threshold_signatures::participants::{Participant, ParticipantList};
use threshold_signatures::protocol::{Action, Protocol};

#[wasm_bindgen]
pub fn init_eth_signer() {
    // no-op; reserved for future logger initialization
}

fn js_err(msg: impl Into<String>) -> JsValue {
    JsValue::from_str(&msg.into())
}

fn parse_scalar_32(bytes: &[u8], field_name: &str) -> Result<TsScalar, JsValue> {
    if bytes.len() != 32 {
        return Err(js_err(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| js_err(format!("{field_name} must be 32 bytes")))?;
    let scalar = Option::<TsScalar>::from(TsScalar::from_repr(arr.into()))
        .ok_or_else(|| js_err(format!("{field_name} is not a valid secp256k1 scalar")))?;
    Ok(scalar)
}

fn parse_nonzero_scalar_32(bytes: &[u8], field_name: &str) -> Result<TsScalar, JsValue> {
    let scalar = parse_scalar_32(bytes, field_name)?;
    if bool::from(scalar.is_zero()) {
        return Err(js_err(format!("{field_name} must be non-zero")));
    }
    Ok(scalar)
}

fn parse_digest_32(bytes: &[u8], field_name: &str) -> Result<[u8; 32], JsValue> {
    if bytes.len() != 32 {
        return Err(js_err(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes
        .try_into()
        .map_err(|_| js_err(format!("{field_name} must be 32 bytes")))?)
}

fn parse_affine_point_33(bytes: &[u8], field_name: &str) -> Result<AffinePoint, JsValue> {
    if bytes.len() != 33 && bytes.len() != 65 {
        return Err(js_err(format!(
            "{field_name} must be 33 (compressed) or 65 (uncompressed) bytes (got {})",
            bytes.len()
        )));
    }
    let encoded =
        EncodedPoint::from_bytes(bytes).map_err(|_| js_err(format!("{field_name} is not valid SEC1 bytes")))?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| js_err(format!("{field_name} is not a valid secp256k1 point")))?;
    Ok(point)
}

fn build_participant_list(ids: &[u32]) -> Result<(Vec<Participant>, ParticipantList), JsValue> {
    if ids.is_empty() {
        return Err(js_err("participantIds must be non-empty"));
    }
    let participants: Vec<Participant> = ids.iter().map(|id| Participant::from(*id)).collect();
    let list = ParticipantList::new(&participants)
        .ok_or_else(|| js_err("participantIds must not contain duplicates"))?;
    Ok((participants, list))
}

fn map_init_err(e: InitializationError) -> JsValue {
    js_err(format!("protocol init failed: {e:?}"))
}

fn map_proto_err(e: ProtocolError) -> JsValue {
    js_err(format!("protocol failed: {e:?}"))
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

#[wasm_bindgen]
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

#[wasm_bindgen]
impl ThresholdEcdsaPresignSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        participant_ids: Vec<u32>,
        me: u32,
        threshold: u32,
        private_share32: Vec<u8>,
        public_key_sec1: Vec<u8>,
    ) -> Result<ThresholdEcdsaPresignSession, JsValue> {
        let (participants, participants_list) = build_participant_list(&participant_ids)?;
        let me = Participant::from(me);
        if !participants_list.contains(me) {
            return Err(js_err("me must be included in participantIds"));
        }
        let threshold_usize = usize::try_from(threshold).map_err(|_| js_err("threshold out of range"))?;
        if threshold_usize < 2 {
            return Err(js_err("threshold must be >= 2"));
        }
        if threshold_usize > participants.len() {
            return Err(js_err("threshold must be <= number of participants"));
        }

        let private_share_scalar = parse_nonzero_scalar_32(&private_share32, "private_share32")?;
        let signing_share = SigningShare::new(private_share_scalar);

        let pk_affine = parse_affine_point_33(&public_key_sec1, "public_key_sec1")?;
        let pk_proj: ProjectivePoint = pk_affine.into();
        let verifying_key = VerifyingKey::new(pk_proj);

        let keygen_out = KeygenOutput {
            private_share: signing_share,
            public_key: verifying_key,
        };

        let protocol = generate_triple_many::<2>(&participants, me, threshold_usize, OsRng)
            .map_err(map_init_err)?;

        Ok(ThresholdEcdsaPresignSession {
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

    #[wasm_bindgen]
    pub fn stage(&self) -> String {
        self.stage.as_str().to_string()
    }

    #[wasm_bindgen]
    pub fn is_done(&self) -> bool {
        self.stage == PresignStage::Done
    }

    #[wasm_bindgen]
    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        let mut outgoing: Vec<Vec<u8>> = Vec::new();
        let mut event: &'static str = "none";

        loop {
            match self.stage {
                PresignStage::Triples => {
                    let proto = self
                        .triple_protocol
                        .as_mut()
                        .ok_or_else(|| js_err("missing triple protocol"))?;
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
                        .ok_or_else(|| js_err("missing presign protocol"))?;
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

        let obj = Object::new();
        Reflect::set(&obj, &JsValue::from_str("stage"), &JsValue::from_str(self.stage.as_str()))?;
        Reflect::set(&obj, &JsValue::from_str("event"), &JsValue::from_str(event))?;

        let arr = Array::new();
        for msg in outgoing {
            let u8 = Uint8Array::from(msg.as_slice());
            arr.push(&u8);
        }
        Reflect::set(&obj, &JsValue::from_str("outgoing"), &arr)?;

        Ok(obj.into())
    }

    #[wasm_bindgen]
    pub fn message(&mut self, from: u32, data: Vec<u8>) -> Result<(), JsValue> {
        let from = Participant::from(from);
        match self.stage {
            PresignStage::Triples => {
                let proto = self
                    .triple_protocol
                    .as_mut()
                    .ok_or_else(|| js_err("missing triple protocol"))?;
                proto.message(from, data);
                Ok(())
            }
            PresignStage::Presign => {
                let proto = self
                    .presign_protocol
                    .as_mut()
                    .ok_or_else(|| js_err("missing presign protocol"))?;
                proto.message(from, data);
                Ok(())
            }
            PresignStage::TriplesDone | PresignStage::Done => Err(js_err(
                "cannot accept messages: presign session is not in an active protocol stage",
            )),
        }
    }

    #[wasm_bindgen]
    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        if self.stage != PresignStage::TriplesDone {
            return Err(js_err("start_presign is only valid after triples stage completes"));
        }
        let triples = self
            .triples_output
            .take()
            .ok_or_else(|| js_err("missing triples output"))?;
        if triples.len() < 2 {
            return Err(js_err("triples output must contain at least 2 triples"));
        }
        let triple0 = triples[0].clone();
        let triple1 = triples[1].clone();

        let args = PresignArguments {
            triple0: (triple0.0, triple0.1),
            triple1: (triple1.0, triple1.1),
            keygen_out: self.keygen_out.clone(),
            threshold: self.threshold,
        };
        let protocol = presign(&self.participants, self.me, args).map_err(map_init_err)?;
        self.presign_protocol = Some(Box::new(protocol));
        self.stage = PresignStage::Presign;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, JsValue> {
        if self.stage != PresignStage::Done {
            return Err(js_err("presign session is not done"));
        }
        let out = self
            .presign_output
            .take()
            .ok_or_else(|| js_err("missing presign output"))?;

        let mut bytes = Vec::with_capacity(97);
        bytes.extend_from_slice(out.big_r.to_encoded_point(true).as_bytes());
        bytes.extend_from_slice(&<Secp256K1ScalarField as Field>::serialize(&out.k));
        bytes.extend_from_slice(&<Secp256K1ScalarField as Field>::serialize(&out.sigma));
        Ok(bytes)
    }
}

#[wasm_bindgen]
pub fn threshold_ecdsa_compute_signature_share(
    participant_ids: Vec<u32>,
    me: u32,
    public_key_sec1: Vec<u8>,
    presign_big_r_sec1: Vec<u8>,
    presign_k_share32: Vec<u8>,
    presign_sigma_share32: Vec<u8>,
    digest32: Vec<u8>,
    entropy32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let (_participants, participants_list) = build_participant_list(&participant_ids)?;
    let me = Participant::from(me);
    if !participants_list.contains(me) {
        return Err(js_err("me must be included in participantIds"));
    }

    let pk = parse_affine_point_33(&public_key_sec1, "public_key_sec1")?;
    let presign_big_r = parse_affine_point_33(&presign_big_r_sec1, "presign_big_r_sec1")?;
    let k = parse_scalar_32(&presign_k_share32, "presign_k_share32")?;
    let sigma = parse_scalar_32(&presign_sigma_share32, "presign_sigma_share32")?;
    let digest_arr = parse_digest_32(&digest32, "digest32")?;
    let entropy_arr = parse_digest_32(&entropy32, "entropy32")?;

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

#[wasm_bindgen]
pub fn threshold_ecdsa_finalize_signature(
    participant_ids: Vec<u32>,
    relayer_id: u32,
    public_key_sec1: Vec<u8>,
    presign_big_r_sec1: Vec<u8>,
    relayer_k_share32: Vec<u8>,
    relayer_sigma_share32: Vec<u8>,
    digest32: Vec<u8>,
    entropy32: Vec<u8>,
    client_signature_share32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let (_participants, participants_list) = build_participant_list(&participant_ids)?;
    let relayer = Participant::from(relayer_id);
    if !participants_list.contains(relayer) {
        return Err(js_err("relayer_id must be included in participantIds"));
    }

    let pk = parse_affine_point_33(&public_key_sec1, "public_key_sec1")?;
    let presign_big_r = parse_affine_point_33(&presign_big_r_sec1, "presign_big_r_sec1")?;
    let k = parse_scalar_32(&relayer_k_share32, "relayer_k_share32")?;
    let sigma = parse_scalar_32(&relayer_sigma_share32, "relayer_sigma_share32")?;
    let digest_arr = parse_digest_32(&digest32, "digest32")?;
    let entropy_arr = parse_digest_32(&entropy32, "entropy32")?;
    let client_share = parse_scalar_32(&client_signature_share32, "client_signature_share32")?;

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
        return Err(js_err("final signature failed to verify"));
    }

    // Convert to k256 ECDSA signature for recovery-id derivation.
    let sig = k256::ecdsa::Signature::from_scalars(
        <Secp256K1ScalarField as Field>::serialize(&r_scalar),
        <Secp256K1ScalarField as Field>::serialize(&s),
    )
    .map_err(|_| js_err("failed to build ECDSA signature"))?;

    let expected_vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_sec1)
        .map_err(|_| js_err("invalid public_key_sec1"))?;

    let mut recid_out: Option<u8> = None;
    for id in 0u8..=3u8 {
        let Some(recid) = k256::ecdsa::RecoveryId::from_byte(id) else {
            continue;
        };
        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest_arr, &sig, recid);
        if let Ok(vk) = recovered {
            if vk.to_encoded_point(true).as_bytes() == expected_vk.to_encoded_point(true).as_bytes() {
                recid_out = Some(id);
                break;
            }
        }
    }

    let recid = recid_out.ok_or_else(|| js_err("failed to recover public key (no valid recId found)"))?;

    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(sig.r().to_bytes().as_ref());
    out.extend_from_slice(sig.s().to_bytes().as_ref());
    out.push(recid);
    Ok(out)
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let raw = s.trim();
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.is_empty() {
        return Ok(vec![]);
    }
    if hex.len() % 2 != 0 {
        return Err("invalid hex (odd length)".to_string());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "invalid hex".to_string())?;
        out.push(b);
    }
    Ok(out)
}

fn u256_bytes_be_from_dec(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("missing bigint".to_string());
    }
    if trimmed == "0" {
        return Ok(vec![]);
    }
    let v = BigUint::from_str_radix(trimmed, 10).map_err(|_| "invalid bigint".to_string())?;
    Ok(v.to_bytes_be())
}

fn strip_leading_zeros(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    bytes
}

fn rlp_encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len <= 55 {
        vec![offset + (len as u8)]
    } else {
        let mut len_bytes = Vec::new();
        let mut x = len;
        while x > 0 {
            len_bytes.push((x & 0xff) as u8);
            x >>= 8;
        }
        len_bytes.reverse();
        let mut out = vec![offset + 55 + (len_bytes.len() as u8)];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = rlp_encode_length(bytes.len(), 0x80);
    out.extend_from_slice(bytes);
    out
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|x| x.len()).sum();
    let mut out = rlp_encode_length(payload_len, 0xc0);
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessListItem {
    address: String,
    storage_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Eip1559TxJson {
    chain_id: String,
    nonce: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    gas_limit: String,
    to: Option<String>,
    value: String,
    data: Option<String>,
    access_list: Option<Vec<AccessListItem>>,
}

fn encode_access_list(access: &[AccessListItem]) -> Result<Vec<u8>, String> {
    let mut items_enc: Vec<Vec<u8>> = Vec::with_capacity(access.len());
    for item in access {
        let addr = hex_to_bytes(&item.address)?;
        if addr.len() != 20 {
            return Err("accessList.address must be 20 bytes".to_string());
        }
        let mut storage_enc: Vec<Vec<u8>> = Vec::with_capacity(item.storage_keys.len());
        for k in &item.storage_keys {
            let b = hex_to_bytes(k)?;
            if b.len() != 32 {
                return Err("accessList.storageKeys must be 32 bytes".to_string());
            }
            storage_enc.push(rlp_encode_bytes(&b));
        }
        let list_storage = rlp_encode_list(&storage_enc);
        let item_list = rlp_encode_list(&[rlp_encode_bytes(&addr), list_storage]);
        items_enc.push(item_list);
    }
    Ok(rlp_encode_list(&items_enc))
}

fn encode_eip1559_fields(tx: &Eip1559TxJson) -> Result<Vec<u8>, String> {
    let to_bytes = match &tx.to {
        Some(t) => {
            let b = hex_to_bytes(t)?;
            if b.len() != 20 {
                return Err("to must be 20 bytes".to_string());
            }
            b
        }
        None => vec![],
    };
    let data_bytes = hex_to_bytes(tx.data.as_deref().unwrap_or("0x"))?;
    let access_list = tx.access_list.as_deref().unwrap_or(&[]);
    let access_list_enc = encode_access_list(access_list)?;

    let fields = vec![
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.gas_limit)?),
        rlp_encode_bytes(&to_bytes),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.value)?),
        rlp_encode_bytes(&data_bytes),
        access_list_enc,
    ];
    Ok(rlp_encode_list(&fields))
}

#[wasm_bindgen]
pub fn compute_eip1559_tx_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    let tx: Eip1559TxJson = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| JsValue::from_str(&format!("invalid tx: {e}")))?;
    let rlp = encode_eip1559_fields(&tx).map_err(|e| JsValue::from_str(&e))?;
    let mut preimage = Vec::with_capacity(1 + rlp.len());
    preimage.push(0x02);
    preimage.extend_from_slice(&rlp);
    let hash = Keccak256::digest(&preimage);
    Ok(hash.to_vec())
}

#[wasm_bindgen]
pub fn encode_eip1559_signed_tx(tx: JsValue, y_parity: u8, r: Vec<u8>, s: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    if y_parity > 1 {
        return Err(JsValue::from_str("yParity must be 0 or 1"));
    }
    if r.len() != 32 || s.len() != 32 {
        return Err(JsValue::from_str("r/s must be 32 bytes"));
    }
    let tx: Eip1559TxJson = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| JsValue::from_str(&format!("invalid tx: {e}")))?;

    let mut fields: Vec<Vec<u8>> = Vec::new();
    // Base fields (already RLP items, but we need list items, so rebuild with item encodings).
    // We reuse encode_eip1559_fields by decoding its list payload is cumbersome; rebuild.
    let to_bytes = match &tx.to {
        Some(t) => {
            let b = hex_to_bytes(t).map_err(|e| JsValue::from_str(&e))?;
            if b.len() != 20 {
                return Err(JsValue::from_str("to must be 20 bytes"));
            }
            b
        }
        None => vec![],
    };
    let data_bytes = hex_to_bytes(tx.data.as_deref().unwrap_or("0x")).map_err(|e| JsValue::from_str(&e))?;
    let access_list = tx.access_list.as_deref().unwrap_or(&[]);
    let access_list_enc = encode_access_list(access_list).map_err(|e| JsValue::from_str(&e))?;

    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_fee_per_gas).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.gas_limit).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&to_bytes));
    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.value).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&data_bytes));
    fields.push(access_list_enc);

    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&format!("{y_parity}")).map_err(|e| JsValue::from_str(&e))?));
    fields.push(rlp_encode_bytes(&strip_leading_zeros(r)));
    fields.push(rlp_encode_bytes(&strip_leading_zeros(s)));

    let rlp = rlp_encode_list(&fields);
    let mut out = Vec::with_capacity(1 + rlp.len());
    out.push(0x02);
    out.extend_from_slice(&rlp);
    Ok(out)
}

#[wasm_bindgen]
pub fn sign_secp256k1_recoverable(digest32: Vec<u8>, private_key32: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    if digest32.len() != 32 {
        return Err(JsValue::from_str("digest32 must be 32 bytes"));
    }
    if private_key32.len() != 32 {
        return Err(JsValue::from_str("privateKey must be 32 bytes"));
    }

    // k256 expects a 32-byte secret key.
    use k256::ecdsa::{Signature, SigningKey};
    use k256::elliptic_curve::SecretKey;

    let sk = SecretKey::from_slice(&private_key32)
        .map_err(|_| JsValue::from_str("invalid secp256k1 private key"))?;
    let signing_key: SigningKey = sk.into();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(&digest32)
        .map_err(|_| JsValue::from_str("secp256k1 signing failed"))?;

    let sig: Signature = sig;
    // Ethereum requires low-s normalized signatures (EIP-2).
    // When normalizing s -> n-s, the recovery id flips parity.
    let (sig, recid) = match sig.normalize_s() {
        Some(normalized) => {
            let flipped = k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1)
                .ok_or_else(|| JsValue::from_str("invalid recovery id"))?;
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
