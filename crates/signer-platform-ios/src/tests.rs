use super::v1;

const VECTORS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../signer-core/fixtures/signing-vectors/v1.json"
));
const HEX_INPUT: &str = "0x00abcd";
const HEX_EXPECTED: &str = "00abcd";
const U256_INPUT: &str = "12345678901234567890";
const U256_EXPECTED: &str = "ab54a98ceb1f0ad2";
const STRIP_INPUT_HEX: &str = "0000010203";
const STRIP_EXPECTED: &str = "010203";
const RLP_BYTES_INPUT_HEX: &str = "010203";
const RLP_BYTES_EXPECTED: &str = "83010203";
const RLP_LIST_ITEM_0_HEX: &str = "01";
const RLP_LIST_ITEM_1_HEX: &str = "0203";
const RLP_LIST_EXPECTED: &str = "c3010203";
const SECP_PRF_FIRST32_HEX: &str =
    "0707070707070707070707070707070707070707070707070707070707070707";
const SECP_USER_ID: &str = "user-123";
const SECP_DERIVATION_PATH: u32 = 42;
const SECP_DERIVE_CLIENT_EXPECTED: &str =
    "341731e0dfa798502e11429106bb3b07258ba6a5c8e54d98224955fbd0e7b35503b43b58b02652e112872421a5742c2f9e0af10a823280eee8d1a3cdac4ef0066e";
const SECP_PRF_SECOND_HEX: &str = "746573742d7072662d7365636f6e642d6f7574707574";
const SECP_NEAR_ACCOUNT_ID: &str = "alice.near";
const SECP_DERIVE_KEYPAIR_EXPECTED: &str =
    "7526346f837a5509c0f0ca16c7ce1fb7ccf58929fc0bc60553ac53322f9fa9cf02b020f05e664960bc0380289497f2b4c41a974f426da4b0b88a91b3f26a99c0b9545f4b8cdf09262c5489be7ef413431bcef6e082";
const MAP_ADDITIVE_SHARE_HEX: &str =
    "000000000000000000000000000000000000000000000000000000000000002a";
const MAP_PARTICIPANT_ID: u32 = 1;
const MAP_EXPECTED: &str = "000000000000000000000000000000000000000000000000000000000000000e";
const VALIDATE_PK_HEX: &str = "02b020f05e664960bc0380289497f2b4c41a974f426da4b0b88a91b3f26a99c0b9";
const ADD_RIGHT_PK_HEX: &str = "032a709888f7c7e1087d472005b99064112c1df5442f53ef9af4beae67f913eaca";
const ADD_EXPECTED: &str = "032516721a026f7e3eddc4cb67c9b24ee897ebc2d94ee78760736beb91b7d2f732";
const NEAR_PRF_B64U: &str = "ZGV0ZXJtaW5pc3RpYy1wcmYtb3V0cHV0";
const NEAR_ACCOUNT_ID: &str = "alice.near";
const NEAR_PRIVATE_EXPECTED: &str =
    "ed25519:2QQCTV5bC1HXBD274gbs2tULUj5Tb8HYihsrn8nxWr6H9TfevhWwwKe8Ekbg2nZCSqPEyDuqXtRn5P2359iGTwCJ";
const NEAR_PUBLIC_EXPECTED: &str = "ed25519:8Y3sr3jSPa7vNj5LkW49LfTZF3ACnjiR9vKv6AYfSmAe";
const WRAP_SEED_B64U: &str = "d3JhcC1zZWVk";
const WRAP_SALT_B64U: &str = "c2FsdA";
const KEK_EXPECTED: &str = "0ab776316f79db94c8125814b46c57e444f668f81ec2324ceae9f91299dfee48";
const CHACHA_PLAIN: &str = "near-private-key";
const CHACHA_KEY_HEX: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const CHACHA_NONCE_HEX: &str = "090909090909090909090909";
const CHACHA_CIPHERTEXT_EXPECTED: &str =
    "8748d64cedbeb53ec3ccccc105ca1e3f539654c9436a18b6c1e378baa2726beb";

fn from_hex(hex: &str) -> Vec<u8> {
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

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

#[test]
fn parity_codec_with_web_binding() {
    assert_eq!(
        v1::hex_to_bytes(HEX_INPUT).expect("ios hex_to_bytes"),
        signer_platform_web::codec::hex_to_bytes(HEX_INPUT).expect("web hex_to_bytes")
    );

    assert_eq!(
        v1::u256_bytes_be_from_dec(U256_INPUT).expect("ios u256"),
        signer_platform_web::codec::u256_bytes_be_from_dec(U256_INPUT).expect("web u256")
    );
}

#[test]
fn parity_secp256k1_with_web_binding() {
    assert_eq!(
        v1::derive_threshold_secp256k1_client_share(
            from_hex(SECP_PRF_FIRST32_HEX),
            SECP_USER_ID.to_string(),
            SECP_DERIVATION_PATH,
        )
        .expect("ios threshold share"),
        signer_platform_web::secp256k1::derive_threshold_secp256k1_client_share(
            from_hex(SECP_PRF_FIRST32_HEX).as_slice(),
            SECP_USER_ID,
            SECP_DERIVATION_PATH,
        )
        .expect("web threshold share")
    );

    assert_eq!(
        v1::derive_secp256k1_keypair_from_prf_second(
            from_hex(SECP_PRF_SECOND_HEX),
            SECP_NEAR_ACCOUNT_ID.to_string(),
        )
        .expect("ios keypair"),
        signer_platform_web::secp256k1::derive_secp256k1_keypair_from_prf_second(
            from_hex(SECP_PRF_SECOND_HEX).as_slice(),
            SECP_NEAR_ACCOUNT_ID,
        )
        .expect("web keypair")
    );
}

#[test]
fn parity_near_ed25519_with_web_binding() {
    assert_eq!(
        v1::derive_ed25519_key_from_prf_output(
            NEAR_PRF_B64U.to_string(),
            NEAR_ACCOUNT_ID.to_string(),
        )
        .expect("ios near ed25519"),
        signer_platform_web::near_ed25519::derive_ed25519_key_from_prf_output(
            NEAR_PRF_B64U,
            NEAR_ACCOUNT_ID,
        )
        .expect("web near ed25519")
    );
}

#[test]
fn parity_near_crypto_with_web_binding() {
    assert_eq!(
        v1::derive_kek_from_wrap_key_seed_b64u(
            WRAP_SEED_B64U.to_string(),
            WRAP_SALT_B64U.to_string()
        )
        .expect("ios kek"),
        signer_platform_web::near_crypto::derive_kek_from_wrap_key_seed_b64u(
            WRAP_SEED_B64U,
            WRAP_SALT_B64U,
        )
        .expect("web kek")
    );

    let ios_ct = v1::encrypt_data_chacha20(
        CHACHA_PLAIN.to_string(),
        from_hex(CHACHA_KEY_HEX),
        from_hex(CHACHA_NONCE_HEX),
    )
    .expect("ios encrypt");
    let web_ct = signer_platform_web::near_crypto::encrypt_data_chacha20(
        CHACHA_PLAIN,
        from_hex(CHACHA_KEY_HEX).as_slice(),
        from_hex(CHACHA_NONCE_HEX).as_slice(),
    )
    .expect("web encrypt");
    assert_eq!(ios_ct, web_ct);

    assert_eq!(
        v1::decrypt_data_chacha20(
            ios_ct.clone(),
            from_hex(CHACHA_NONCE_HEX),
            from_hex(CHACHA_KEY_HEX),
        )
        .expect("ios decrypt"),
        signer_platform_web::near_crypto::decrypt_data_chacha20(
            web_ct.as_slice(),
            from_hex(CHACHA_NONCE_HEX).as_slice(),
            from_hex(CHACHA_KEY_HEX).as_slice(),
        )
        .expect("web decrypt")
    );
}

#[test]
fn vectors_v1_match_expected_outputs() {
    assert!(VECTORS_JSON.contains("\"version\": \"v1\""));
    assert!(VECTORS_JSON.contains(HEX_EXPECTED));
    assert!(VECTORS_JSON.contains(SECP_DERIVE_KEYPAIR_EXPECTED));

    assert_eq!(
        to_hex(
            v1::hex_to_bytes(HEX_INPUT)
                .expect("hex_to_bytes")
                .as_slice()
        ),
        HEX_EXPECTED
    );
    assert_eq!(
        to_hex(
            v1::u256_bytes_be_from_dec(U256_INPUT)
                .expect("u256")
                .as_slice()
        ),
        U256_EXPECTED
    );
    let strip_input = from_hex(STRIP_INPUT_HEX);
    assert_eq!(
        to_hex(v1::strip_leading_zeros(strip_input).as_slice()),
        STRIP_EXPECTED
    );
    assert_eq!(
        to_hex(v1::rlp_encode_bytes(from_hex(RLP_BYTES_INPUT_HEX).as_slice().to_vec()).as_slice()),
        RLP_BYTES_EXPECTED
    );
    let rlp_items = vec![from_hex(RLP_LIST_ITEM_0_HEX), from_hex(RLP_LIST_ITEM_1_HEX)];
    assert_eq!(
        to_hex(v1::rlp_encode_list(rlp_items).as_slice()),
        RLP_LIST_EXPECTED
    );

    assert_eq!(
        to_hex(
            v1::derive_threshold_secp256k1_client_share(
                from_hex(SECP_PRF_FIRST32_HEX),
                SECP_USER_ID.to_string(),
                SECP_DERIVATION_PATH,
            )
            .expect("derive client share")
            .as_slice()
        ),
        SECP_DERIVE_CLIENT_EXPECTED
    );

    assert_eq!(
        to_hex(
            v1::derive_secp256k1_keypair_from_prf_second(
                from_hex(SECP_PRF_SECOND_HEX),
                SECP_NEAR_ACCOUNT_ID.to_string(),
            )
            .expect("derive keypair")
            .as_slice()
        ),
        SECP_DERIVE_KEYPAIR_EXPECTED
    );

    assert_eq!(
        to_hex(
            v1::map_additive_share_to_threshold_signatures_share_2p(
                from_hex(MAP_ADDITIVE_SHARE_HEX),
                MAP_PARTICIPANT_ID,
            )
            .expect("map share")
            .as_slice()
        ),
        MAP_EXPECTED
    );

    assert_eq!(
        to_hex(
            v1::validate_secp256k1_public_key_33(from_hex(VALIDATE_PK_HEX))
                .expect("validate pk")
                .as_slice()
        ),
        VALIDATE_PK_HEX
    );

    assert_eq!(
        to_hex(
            v1::add_secp256k1_public_keys_33(from_hex(VALIDATE_PK_HEX), from_hex(ADD_RIGHT_PK_HEX),)
                .expect("add pks")
                .as_slice()
        ),
        ADD_EXPECTED
    );

    let (priv_key, pub_key) = v1::derive_ed25519_key_from_prf_output(
        NEAR_PRF_B64U.to_string(),
        NEAR_ACCOUNT_ID.to_string(),
    )
    .expect("near derive");
    assert_eq!(priv_key, NEAR_PRIVATE_EXPECTED);
    assert_eq!(pub_key, NEAR_PUBLIC_EXPECTED);

    assert_eq!(
        to_hex(
            v1::derive_kek_from_wrap_key_seed_b64u(
                WRAP_SEED_B64U.to_string(),
                WRAP_SALT_B64U.to_string()
            )
            .expect("derive kek")
            .as_slice()
        ),
        KEK_EXPECTED
    );

    let ciphertext = v1::encrypt_data_chacha20(
        CHACHA_PLAIN.to_string(),
        from_hex(CHACHA_KEY_HEX),
        from_hex(CHACHA_NONCE_HEX),
    )
    .expect("encrypt chacha20");
    assert_eq!(to_hex(ciphertext.as_slice()), CHACHA_CIPHERTEXT_EXPECTED);
    assert_eq!(
        v1::decrypt_data_chacha20(
            ciphertext,
            from_hex(CHACHA_NONCE_HEX),
            from_hex(CHACHA_KEY_HEX),
        )
        .expect("decrypt chacha20"),
        CHACHA_PLAIN
    );
}
