use serde::Deserialize;
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

use crate::codec::{
    hex_to_bytes, rlp_encode_bytes, rlp_encode_list, strip_leading_zeros, u256_bytes_be_from_dec,
};

const TYPE_TEMPO_TX: u8 = 0x76;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessListItem {
    address: String,
    storage_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TempoCallJson {
    to: String,
    value: String,
    input: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kind")]
enum FeePayerSignatureJson {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "placeholder")]
    Placeholder,
    #[serde(rename = "signed")]
    Signed { v: u8, r: String, s: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TempoTxJson {
    chain_id: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    gas_limit: String,
    calls: Vec<TempoCallJson>,
    access_list: Option<Vec<AccessListItem>>,
    nonce_key: String,
    nonce: String,
    valid_before: Option<String>,
    valid_after: Option<String>,
    fee_token: Option<String>,
    fee_payer_signature: Option<FeePayerSignatureJson>,
    // MVP: keep AA list empty and keyAuthorization omitted.
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

fn encode_calls(calls: &[TempoCallJson]) -> Result<Vec<u8>, String> {
    if calls.is_empty() {
        return Err("calls must be non-empty".to_string());
    }
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(calls.len());
    for c in calls {
        let to = hex_to_bytes(&c.to)?;
        if to.len() != 20 {
            return Err("call.to must be 20 bytes".to_string());
        }
        let value = u256_bytes_be_from_dec(&c.value)?;
        let input = hex_to_bytes(c.input.as_deref().unwrap_or("0x"))?;
        let call_list = rlp_encode_list(&[
            rlp_encode_bytes(&to),
            rlp_encode_bytes(&value),
            rlp_encode_bytes(&input),
        ]);
        out.push(call_list);
    }
    Ok(rlp_encode_list(&out))
}

fn encode_opt_u64_bytes(v: &Option<String>) -> Result<Vec<u8>, String> {
    match v {
        None => Ok(vec![]),
        Some(s) => u256_bytes_be_from_dec(s),
    }
}

fn encode_fee_token(addr: &Option<String>) -> Result<Vec<u8>, String> {
    match addr {
        None => Ok(vec![]),
        Some(s) => {
            let b = hex_to_bytes(s)?;
            if b.len() != 20 {
                return Err("feeToken must be 20 bytes".to_string());
            }
            Ok(b)
        }
    }
}

fn has_fee_payer(tx: &TempoTxJson) -> bool {
    match tx.fee_payer_signature.as_ref() {
        None => false,
        Some(FeePayerSignatureJson::None) => false,
        Some(_) => true,
    }
}

fn encode_fee_payer_sig_field(sig: &Option<FeePayerSignatureJson>) -> Result<Vec<u8>, String> {
    match sig.as_ref().unwrap_or(&FeePayerSignatureJson::None) {
        FeePayerSignatureJson::None => Ok(rlp_encode_bytes(&[])),
        FeePayerSignatureJson::Placeholder => Ok(rlp_encode_bytes(&[0x00])),
        FeePayerSignatureJson::Signed { v, r, s } => {
            if *v > 1 {
                return Err("feePayerSignature.v must be 0 or 1".to_string());
            }
            let r = hex_to_bytes(r)?;
            let s = hex_to_bytes(s)?;
            if r.len() != 32 || s.len() != 32 {
                return Err("feePayerSignature.r/s must be 32 bytes".to_string());
            }
            let list = rlp_encode_list(&[
                rlp_encode_bytes(&u256_bytes_be_from_dec(&format!("{v}"))?),
                rlp_encode_bytes(strip_leading_zeros(&r)),
                rlp_encode_bytes(strip_leading_zeros(&s)),
            ]);
            Ok(list)
        }
    }
}

pub fn compute_tempo_sender_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    let tx: TempoTxJson = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| JsValue::from_str(&format!("invalid tx: {e}")))?;

    let access_list = tx.access_list.as_deref().unwrap_or(&[]);
    let access_list_enc = encode_access_list(access_list).map_err(|e| JsValue::from_str(&e))?;
    let calls_enc = encode_calls(&tx.calls).map_err(|e| JsValue::from_str(&e))?;

    let fee_token_for_sender = if has_fee_payer(&tx) {
        vec![]
    } else {
        encode_fee_token(&tx.fee_token).map_err(|e| JsValue::from_str(&e))?
    };
    let fee_payer_field_for_sender = if has_fee_payer(&tx) {
        vec![0x00] // placeholder
    } else {
        vec![] // empty
    };

    let fields = vec![
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id).map_err(|e| JsValue::from_str(&e))?),
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas)
                .map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.max_fee_per_gas).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.gas_limit).map_err(|e| JsValue::from_str(&e))?,
        ),
        calls_enc,
        access_list_enc,
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.nonce_key).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce).map_err(|e| JsValue::from_str(&e))?),
        rlp_encode_bytes(
            &encode_opt_u64_bytes(&tx.valid_before).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(
            &encode_opt_u64_bytes(&tx.valid_after).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(&fee_token_for_sender),
        rlp_encode_bytes(&fee_payer_field_for_sender),
    ];

    let rlp = rlp_encode_list(&fields);
    let mut preimage = Vec::with_capacity(1 + rlp.len());
    preimage.push(TYPE_TEMPO_TX);
    preimage.extend_from_slice(&rlp);
    let hash = Keccak256::digest(&preimage);
    Ok(hash.to_vec())
}

pub fn encode_tempo_signed_tx(tx: JsValue, sender_signature: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let tx: TempoTxJson = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| JsValue::from_str(&format!("invalid tx: {e}")))?;

    let access_list = tx.access_list.as_deref().unwrap_or(&[]);
    let access_list_enc = encode_access_list(access_list).map_err(|e| JsValue::from_str(&e))?;
    let calls_enc = encode_calls(&tx.calls).map_err(|e| JsValue::from_str(&e))?;
    let fee_token = encode_fee_token(&tx.fee_token).map_err(|e| JsValue::from_str(&e))?;
    let fee_payer_sig_field =
        encode_fee_payer_sig_field(&tx.fee_payer_signature).map_err(|e| JsValue::from_str(&e))?;

    // MVP: AA list is always empty.
    let aa_list_enc = rlp_encode_list(&[]);

    let fields = vec![
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id).map_err(|e| JsValue::from_str(&e))?),
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas)
                .map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.max_fee_per_gas).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.gas_limit).map_err(|e| JsValue::from_str(&e))?,
        ),
        calls_enc,
        access_list_enc,
        rlp_encode_bytes(
            &u256_bytes_be_from_dec(&tx.nonce_key).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce).map_err(|e| JsValue::from_str(&e))?),
        rlp_encode_bytes(
            &encode_opt_u64_bytes(&tx.valid_before).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(
            &encode_opt_u64_bytes(&tx.valid_after).map_err(|e| JsValue::from_str(&e))?,
        ),
        rlp_encode_bytes(&fee_token),
        fee_payer_sig_field,
        aa_list_enc,
        rlp_encode_bytes(&sender_signature),
    ];

    let rlp = rlp_encode_list(&fields);
    let mut out = Vec::with_capacity(1 + rlp.len());
    out.push(TYPE_TEMPO_TX);
    out.extend_from_slice(&rlp);
    Ok(out)
}
