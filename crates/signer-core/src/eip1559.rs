use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::codec::{
    hex_to_bytes, rlp_encode_bytes, rlp_encode_list, strip_leading_zeros_slice,
    u256_bytes_be_from_dec,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip1559AccessListItem {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip1559Tx {
    pub chain_id: String,
    pub nonce: String,
    pub max_priority_fee_per_gas: String,
    pub max_fee_per_gas: String,
    pub gas_limit: String,
    pub to: Option<String>,
    pub value: String,
    pub data: Option<String>,
    pub access_list: Option<Vec<Eip1559AccessListItem>>,
}

fn encode_access_list(access: &[Eip1559AccessListItem]) -> Result<Vec<u8>, String> {
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

fn base_fields(tx: &Eip1559Tx) -> Result<Vec<Vec<u8>>, String> {
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

pub fn compute_eip1559_tx_hash(tx: &Eip1559Tx) -> Result<Vec<u8>, String> {
    let fields = base_fields(tx)?;
    let rlp = rlp_encode_list(&fields);
    let mut preimage = Vec::with_capacity(1 + rlp.len());
    preimage.push(0x02);
    preimage.extend_from_slice(&rlp);
    let hash = Keccak256::digest(&preimage);
    Ok(hash.to_vec())
}

pub fn encode_eip1559_signed_tx(
    tx: &Eip1559Tx,
    y_parity: u8,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    if y_parity > 1 {
        return Err("yParity must be 0 or 1".to_string());
    }
    if r.len() != 32 || s.len() != 32 {
        return Err("r/s must be 32 bytes".to_string());
    }

    let mut fields = base_fields(tx)?;
    fields.push(rlp_encode_bytes(&u256_bytes_be_from_dec(&format!(
        "{y_parity}"
    ))?));
    fields.push(rlp_encode_bytes(strip_leading_zeros_slice(r)));
    fields.push(rlp_encode_bytes(strip_leading_zeros_slice(s)));

    let rlp = rlp_encode_list(&fields);
    let mut out = Vec::with_capacity(1 + rlp.len());
    out.push(0x02);
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

    fn test_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: "11155111".to_string(),
            nonce: "7".to_string(),
            max_priority_fee_per_gas: "1500000000".to_string(),
            max_fee_per_gas: "3000000000".to_string(),
            gas_limit: "21000".to_string(),
            to: Some(format!("0x{}", "22".repeat(20))),
            value: "12345".to_string(),
            data: Some("0x".to_string()),
            access_list: Some(vec![]),
        }
    }

    #[test]
    fn eip1559_vectors_are_stable() {
        let tx = test_tx();
        let hash = compute_eip1559_tx_hash(&tx).expect("hash");
        let r = vec![0x11; 32];
        let s = vec![0x22; 32];
        let raw = encode_eip1559_signed_tx(&tx, 1, r.as_slice(), s.as_slice()).expect("raw");

        assert_eq!(
            to_hex(hash.as_slice()),
            "ec562eae017388b8e451182e6919ee681b63a9d8f9fe1d34009e8e58ab4f9366"
        );
        assert_eq!(
            to_hex(raw.as_slice()),
            "02f86f83aa36a7078459682f0084b2d05e0082520894222222222222222222222222222222222222222282303980c001a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222"
        );
    }
}
