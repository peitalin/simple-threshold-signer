use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::codec::{
    hex_to_bytes, rlp_encode_bytes, rlp_encode_list, strip_leading_zeros_slice,
    u256_bytes_be_from_dec,
};

pub const TYPE_TEMPO_TX: u8 = 0x76;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoAccessListItem {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoCall {
    pub to: String,
    pub value: String,
    pub input: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind")]
pub enum FeePayerSignature {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "placeholder")]
    Placeholder,
    #[serde(rename = "signed")]
    Signed { v: u8, r: String, s: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoTx {
    pub chain_id: String,
    pub max_priority_fee_per_gas: String,
    pub max_fee_per_gas: String,
    pub gas_limit: String,
    pub calls: Vec<TempoCall>,
    pub access_list: Option<Vec<TempoAccessListItem>>,
    pub nonce_key: String,
    pub nonce: String,
    pub valid_before: Option<String>,
    pub valid_after: Option<String>,
    pub fee_token: Option<String>,
    pub fee_payer_signature: Option<FeePayerSignature>,
}

fn encode_access_list(access: &[TempoAccessListItem]) -> Result<Vec<u8>, String> {
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

fn encode_calls(calls: &[TempoCall]) -> Result<Vec<u8>, String> {
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

fn has_fee_payer(tx: &TempoTx) -> bool {
    match tx.fee_payer_signature.as_ref() {
        None => false,
        Some(FeePayerSignature::None) => false,
        Some(_) => true,
    }
}

fn encode_fee_payer_sig_field(sig: &Option<FeePayerSignature>) -> Result<Vec<u8>, String> {
    match sig.as_ref().unwrap_or(&FeePayerSignature::None) {
        FeePayerSignature::None => Ok(rlp_encode_bytes(&[])),
        FeePayerSignature::Placeholder => Ok(rlp_encode_bytes(&[0x00])),
        FeePayerSignature::Signed { v, r, s } => {
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
                rlp_encode_bytes(strip_leading_zeros_slice(&r)),
                rlp_encode_bytes(strip_leading_zeros_slice(&s)),
            ]);
            Ok(list)
        }
    }
}

pub fn compute_tempo_sender_hash(tx: &TempoTx) -> Result<Vec<u8>, String> {
    let access_list = tx.access_list.as_deref().unwrap_or(&[]);
    let access_list_enc = encode_access_list(access_list)?;
    let calls_enc = encode_calls(&tx.calls)?;

    let fee_token_for_sender = if has_fee_payer(tx) {
        vec![]
    } else {
        encode_fee_token(&tx.fee_token)?
    };
    let fee_payer_field_for_sender = if has_fee_payer(tx) {
        vec![0x00]
    } else {
        vec![]
    };

    let fields = vec![
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.gas_limit)?),
        calls_enc,
        access_list_enc,
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce_key)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce)?),
        rlp_encode_bytes(&encode_opt_u64_bytes(&tx.valid_before)?),
        rlp_encode_bytes(&encode_opt_u64_bytes(&tx.valid_after)?),
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

pub fn encode_tempo_signed_tx(tx: &TempoTx, sender_signature: &[u8]) -> Result<Vec<u8>, String> {
    let access_list = tx.access_list.as_deref().unwrap_or(&[]);
    let access_list_enc = encode_access_list(access_list)?;
    let calls_enc = encode_calls(&tx.calls)?;
    let fee_token = encode_fee_token(&tx.fee_token)?;
    let fee_payer_sig_field = encode_fee_payer_sig_field(&tx.fee_payer_signature)?;

    // MVP: AA list is always empty.
    let aa_list_enc = rlp_encode_list(&[]);

    let fields = vec![
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.chain_id)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_priority_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.max_fee_per_gas)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.gas_limit)?),
        calls_enc,
        access_list_enc,
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce_key)?),
        rlp_encode_bytes(&u256_bytes_be_from_dec(&tx.nonce)?),
        rlp_encode_bytes(&encode_opt_u64_bytes(&tx.valid_before)?),
        rlp_encode_bytes(&encode_opt_u64_bytes(&tx.valid_after)?),
        rlp_encode_bytes(&fee_token),
        fee_payer_sig_field,
        aa_list_enc,
        rlp_encode_bytes(sender_signature),
    ];

    let rlp = rlp_encode_list(&fields);
    let mut out = Vec::with_capacity(1 + rlp.len());
    out.push(TYPE_TEMPO_TX);
    out.extend_from_slice(&rlp);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{:02x}", b);
        }
        out
    }

    fn test_tx(fee_token: &str, fee_payer_signature: Option<FeePayerSignature>) -> TempoTx {
        TempoTx {
            chain_id: "42431".to_string(),
            max_priority_fee_per_gas: "1".to_string(),
            max_fee_per_gas: "2".to_string(),
            gas_limit: "21000".to_string(),
            calls: vec![TempoCall {
                to: format!("0x{}", "11".repeat(20)),
                value: "0".to_string(),
                input: Some("0x".to_string()),
            }],
            access_list: Some(vec![]),
            nonce_key: "0".to_string(),
            nonce: "1".to_string(),
            valid_before: None,
            valid_after: None,
            fee_token: Some(fee_token.to_string()),
            fee_payer_signature,
        }
    }

    #[test]
    fn tempo_vectors_are_stable() {
        let tx_placeholder_a = test_tx(
            &format!("0x{}", "aa".repeat(20)),
            Some(FeePayerSignature::Placeholder),
        );
        let tx_placeholder_b = test_tx(
            &format!("0x{}", "bb".repeat(20)),
            Some(FeePayerSignature::Placeholder),
        );
        let hash_placeholder_a =
            compute_tempo_sender_hash(&tx_placeholder_a).expect("hash placeholder a");
        let hash_placeholder_b =
            compute_tempo_sender_hash(&tx_placeholder_b).expect("hash placeholder b");
        let sender_signature = vec![0x99; 65];
        let raw_placeholder = encode_tempo_signed_tx(&tx_placeholder_a, sender_signature.as_slice())
            .expect("raw placeholder");

        let tx_none_a = test_tx(&format!("0x{}", "aa".repeat(20)), Some(FeePayerSignature::None));
        let tx_none_b = test_tx(&format!("0x{}", "bb".repeat(20)), Some(FeePayerSignature::None));
        let hash_none_a = compute_tempo_sender_hash(&tx_none_a).expect("hash none a");
        let hash_none_b = compute_tempo_sender_hash(&tx_none_b).expect("hash none b");

        assert_eq!(
            to_hex(hash_placeholder_a.as_slice()),
            "53c88d360d006f5acef7c3f7a1cbd4052f4fa6fe1b9182aa1ba2a6ac2d6d573c"
        );
        assert_eq!(
            to_hex(hash_placeholder_b.as_slice()),
            "53c88d360d006f5acef7c3f7a1cbd4052f4fa6fe1b9182aa1ba2a6ac2d6d573c"
        );
        assert_eq!(
            to_hex(raw_placeholder.as_slice()),
            "76f88082a5bf0102825208d8d79411111111111111111111111111111111111111118080c08001808094aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00c0b8419999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
        );
        assert_eq!(
            to_hex(hash_none_a.as_slice()),
            "6a1c26faec9d34e62a1e4bbc107dfbe09a58627c78566eb0feef3f846a034072"
        );
        assert_eq!(
            to_hex(hash_none_b.as_slice()),
            "1485446f06a9ef17e8da3282ef81eedd4d20a0cbd53fcfbf2ea707594793ba8a"
        );
    }
}
