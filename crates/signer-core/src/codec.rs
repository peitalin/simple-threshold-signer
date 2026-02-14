use num_bigint::BigUint;
use num_traits::Num;

use crate::error::{CoreResult, SignerCoreError};

pub fn hex_to_bytes(s: &str) -> CoreResult<Vec<u8>> {
    let raw = s.trim();
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.is_empty() {
        return Ok(vec![]);
    }
    if hex.len() % 2 != 0 {
        return Err(SignerCoreError::invalid_length("invalid hex (odd length)"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| SignerCoreError::decode_error("invalid hex"))?;
        out.push(b);
    }
    Ok(out)
}

pub fn u256_bytes_be_from_dec(s: &str) -> CoreResult<Vec<u8>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SignerCoreError::invalid_input("missing bigint"));
    }
    if trimmed == "0" {
        return Ok(vec![]);
    }
    let v = BigUint::from_str_radix(trimmed, 10)
        .map_err(|_| SignerCoreError::decode_error("invalid bigint"))?;
    Ok(v.to_bytes_be())
}

pub fn strip_leading_zeros_vec(mut bytes: Vec<u8>) -> Vec<u8> {
    let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    if first_nonzero == 0 {
        return bytes;
    }
    bytes.split_off(first_nonzero)
}

pub fn strip_leading_zeros_slice(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

pub fn rlp_encode_length(len: usize, offset: u8) -> Vec<u8> {
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

pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = rlp_encode_length(bytes.len(), 0x80);
    out.extend_from_slice(bytes);
    out
}

pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|x| x.len()).sum();
    let mut out = rlp_encode_length(payload_len, 0xc0);
    for it in items {
        out.extend_from_slice(it);
    }
    out
}
