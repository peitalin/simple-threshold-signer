pub const VECTORS_JSON: &str = include_str!("v1.json");
pub const HEX_INPUT: &str = "0x00abcd";
pub const HEX_EXPECTED: &str = "00abcd";
pub const U256_INPUT: &str = "12345678901234567890";
pub const U256_EXPECTED: &str = "ab54a98ceb1f0ad2";
pub const STRIP_INPUT_HEX: &str = "0000010203";
pub const STRIP_EXPECTED: &str = "010203";
pub const RLP_BYTES_INPUT_HEX: &str = "010203";
pub const RLP_BYTES_EXPECTED: &str = "83010203";
pub const RLP_LIST_ITEM_0_HEX: &str = "01";
pub const RLP_LIST_ITEM_1_HEX: &str = "0203";
pub const RLP_LIST_EXPECTED: &str = "c3010203";
pub const SECP_PRF_FIRST32_HEX: &str =
    "0707070707070707070707070707070707070707070707070707070707070707";
pub const SECP_USER_ID: &str = "user-123";
pub const SECP_DERIVATION_PATH: u32 = 42;
pub const SECP_DERIVE_CLIENT_EXPECTED: &str =
    "341731e0dfa798502e11429106bb3b07258ba6a5c8e54d98224955fbd0e7b35503b43b58b02652e112872421a5742c2f9e0af10a823280eee8d1a3cdac4ef0066e";
pub const SECP_PRF_SECOND_HEX: &str = "746573742d7072662d7365636f6e642d6f7574707574";
pub const SECP_NEAR_ACCOUNT_ID: &str = "alice.near";
pub const SECP_DERIVE_KEYPAIR_EXPECTED: &str =
    "7526346f837a5509c0f0ca16c7ce1fb7ccf58929fc0bc60553ac53322f9fa9cf02b020f05e664960bc0380289497f2b4c41a974f426da4b0b88a91b3f26a99c0b9545f4b8cdf09262c5489be7ef413431bcef6e082";
pub const MAP_ADDITIVE_SHARE_HEX: &str =
    "000000000000000000000000000000000000000000000000000000000000002a";
pub const MAP_PARTICIPANT_ID: u32 = 1;
pub const MAP_EXPECTED: &str = "000000000000000000000000000000000000000000000000000000000000000e";
pub const VALIDATE_PK_HEX: &str =
    "02b020f05e664960bc0380289497f2b4c41a974f426da4b0b88a91b3f26a99c0b9";
pub const ADD_RIGHT_PK_HEX: &str =
    "032a709888f7c7e1087d472005b99064112c1df5442f53ef9af4beae67f913eaca";
pub const ADD_EXPECTED: &str = "032516721a026f7e3eddc4cb67c9b24ee897ebc2d94ee78760736beb91b7d2f732";
pub const NEAR_PRF_B64U: &str = "ZGV0ZXJtaW5pc3RpYy1wcmYtb3V0cHV0";
pub const NEAR_ACCOUNT_ID: &str = "alice.near";
pub const NEAR_PRIVATE_EXPECTED: &str =
    "ed25519:2QQCTV5bC1HXBD274gbs2tULUj5Tb8HYihsrn8nxWr6H9TfevhWwwKe8Ekbg2nZCSqPEyDuqXtRn5P2359iGTwCJ";
pub const NEAR_PUBLIC_EXPECTED: &str = "ed25519:8Y3sr3jSPa7vNj5LkW49LfTZF3ACnjiR9vKv6AYfSmAe";
pub const WRAP_SEED_B64U: &str = "d3JhcC1zZWVk";
pub const WRAP_SALT_B64U: &str = "c2FsdA";
pub const KEK_EXPECTED: &str = "0ab776316f79db94c8125814b46c57e444f668f81ec2324ceae9f91299dfee48";
pub const CHACHA_PLAIN: &str = "near-private-key";
pub const CHACHA_KEY_HEX: &str = "0303030303030303030303030303030303030303030303030303030303030303";
pub const CHACHA_NONCE_HEX: &str = "090909090909090909090909";
pub const CHACHA_CIPHERTEXT_EXPECTED: &str =
    "8748d64cedbeb53ec3ccccc105ca1e3f539654c9436a18b6c1e378baa2726beb";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_INVALID_SENDER_SIGNATURE_HEX: &str =
    "9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_INVALID_AA_AUTHORIZATION_LIST_ENTRY: u8 = 1;
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_INVALID_AA_AUTHORIZATION_LIST_ERROR: &str =
    "aaAuthorizationList not supported in MVP (must be empty)";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_INVALID_KEY_AUTHORIZATION_ERROR: &str = "keyAuthorization not supported in MVP";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_CHAIN_ID: &str = "42431";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_MAX_PRIORITY_FEE_PER_GAS: &str = "1";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_MAX_FEE_PER_GAS: &str = "2";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_GAS_LIMIT: &str = "21000";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_CALL_TO: &str = "0x1111111111111111111111111111111111111111";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_CALL_VALUE: &str = "0";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_CALL_INPUT: &str = "0x";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_NONCE_KEY: &str = "0";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_NONCE: &str = "1";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const TEMPO_VECTOR_FEE_TOKEN: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const EIP1559_INVALID_SIGNATURE65_TOO_SHORT_HEX: &str =
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
#[cfg(feature = "tx-finalization")]
#[allow(dead_code)]
pub const EIP1559_INVALID_SIGNATURE65_TOO_SHORT_ERROR: &str = "signature65 must be 65 bytes";
#[cfg(feature = "near-threshold-ed25519")]
#[allow(dead_code)]
pub const NEAR_INVALID_NEP413_MESSAGE: &str = "hello";
#[cfg(feature = "near-threshold-ed25519")]
#[allow(dead_code)]
pub const NEAR_INVALID_NEP413_RECIPIENT: &str = "example.near";
#[cfg(feature = "near-threshold-ed25519")]
#[allow(dead_code)]
pub const NEAR_INVALID_NEP413_NONCE_BASE64_TOO_SHORT: &str = "BwcHBwcHBwcHBwcHBwcHBw==";
#[cfg(feature = "near-threshold-ed25519")]
#[allow(dead_code)]
pub const NEAR_INVALID_NEP413_NONCE_LENGTH_ERROR: &str =
    "Invalid nonce length: expected 32 bytes, got 16";

pub fn from_hex(hex: &str) -> Vec<u8> {
    let trimmed = hex.trim();
    let s = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if s.is_empty() {
        return vec![];
    }
    assert!(s.len() % 2 == 0, "hex length must be even");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}
