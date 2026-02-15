#![allow(dead_code)]

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    signer_platform_web::codec::hex_to_bytes(s).map_err(|e| e.to_string())
}

pub fn u256_bytes_be_from_dec(s: &str) -> Result<Vec<u8>, String> {
    signer_platform_web::codec::u256_bytes_be_from_dec(s).map_err(|e| e.to_string())
}

pub fn strip_leading_zeros(bytes: Vec<u8>) -> Vec<u8> {
    signer_platform_web::codec::strip_leading_zeros_vec(bytes)
}

pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    signer_platform_web::codec::rlp_encode_bytes(bytes)
}

pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    signer_platform_web::codec::rlp_encode_list(items)
}
