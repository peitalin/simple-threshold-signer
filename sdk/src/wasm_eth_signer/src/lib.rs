use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_eth_signer() {
    // no-op; reserved for future logger initialization
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
