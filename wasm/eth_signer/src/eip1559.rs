use serde::Deserialize;
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

use crate::codec::{
    hex_to_bytes, rlp_encode_bytes, rlp_encode_list, strip_leading_zeros, u256_bytes_be_from_dec,
};

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

fn base_fields(tx: &Eip1559TxJson) -> Result<Vec<Vec<u8>>, String> {
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

    Ok(vec![
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.gas_limit)?),
        rlp_encode_bytes(&to_bytes),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.value)?),
        rlp_encode_bytes(&data_bytes),
        access_list_enc,
    ])
}

pub fn compute_eip1559_tx_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    let tx: Eip1559TxJson = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| JsValue::from_str(&format!("invalid tx: {e}")))?;
    let fields = base_fields(&tx).map_err(|e| JsValue::from_str(&e))?;
    let rlp = rlp_encode_list(&fields);
    let mut preimage = Vec::with_capacity(1 + rlp.len());
    preimage.push(0x02);
    preimage.extend_from_slice(&rlp);
    let hash = Keccak256::digest(&preimage);
    Ok(hash.to_vec())
}

pub fn encode_eip1559_signed_tx(
    tx: JsValue,
    y_parity: u8,
    r: Vec<u8>,
    s: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    if y_parity > 1 {
        return Err(JsValue::from_str("yParity must be 0 or 1"));
    }
    if r.len() != 32 || s.len() != 32 {
        return Err(JsValue::from_str("r/s must be 32 bytes"));
    }
    let tx: Eip1559TxJson = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| JsValue::from_str(&format!("invalid tx: {e}")))?;

    let mut fields = base_fields(&tx).map_err(|e| JsValue::from_str(&e))?;
    fields.push(rlp_encode_bytes(
        &u256_bytes_be_from_dec(&format!("{y_parity}")).map_err(|e| JsValue::from_str(&e))?,
    ));
    fields.push(rlp_encode_bytes(&strip_leading_zeros(r)));
    fields.push(rlp_encode_bytes(&strip_leading_zeros(s)));

    let rlp = rlp_encode_list(&fields);
    let mut out = Vec::with_capacity(1 + rlp.len());
    out.push(0x02);
    out.extend_from_slice(&rlp);
    Ok(out)
}
