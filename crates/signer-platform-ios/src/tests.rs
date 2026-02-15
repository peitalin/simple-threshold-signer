use super::v1;

#[path = "../../signer-core/fixtures/signing-vectors/v1_test_vectors.rs"]
mod vectors;
use vectors::*;

#[cfg(feature = "tx-finalization")]
use crate::eip1559::{
    encode_eip1559_signed_tx_from_signature65 as ios_encode_eip1559_signed_tx_from_signature65,
    Eip1559Tx,
};

#[cfg(feature = "near-threshold-ed25519")]
use crate::near_threshold_ed25519::compute_nep413_signing_digest_from_nonce_base64 as ios_compute_nep413_signing_digest_from_nonce_base64;

#[cfg(feature = "tx-finalization")]
use crate::tempo_tx::{
    encode_tempo_signed_tx as ios_encode_tempo_signed_tx, FeePayerSignature, TempoCall,
    TempoRlpValue, TempoTx,
};

#[cfg(feature = "tx-finalization")]
fn eip1559_vector_tx() -> Eip1559Tx {
    Eip1559Tx {
        chain_id: "11155111".to_string(),
        nonce: "7".to_string(),
        max_priority_fee_per_gas: "1500000000".to_string(),
        max_fee_per_gas: "3000000000".to_string(),
        gas_limit: "21000".to_string(),
        to: Some("0x2222222222222222222222222222222222222222".to_string()),
        value: "12345".to_string(),
        data: Some("0x".to_string()),
        access_list: Some(vec![]),
    }
}

#[cfg(feature = "tx-finalization")]
fn tempo_invalid_vector_tx() -> TempoTx {
    TempoTx {
        chain_id: TEMPO_VECTOR_CHAIN_ID.to_string(),
        max_priority_fee_per_gas: TEMPO_VECTOR_MAX_PRIORITY_FEE_PER_GAS.to_string(),
        max_fee_per_gas: TEMPO_VECTOR_MAX_FEE_PER_GAS.to_string(),
        gas_limit: TEMPO_VECTOR_GAS_LIMIT.to_string(),
        calls: vec![TempoCall {
            to: TEMPO_VECTOR_CALL_TO.to_string(),
            value: TEMPO_VECTOR_CALL_VALUE.to_string(),
            input: Some(TEMPO_VECTOR_CALL_INPUT.to_string()),
        }],
        access_list: Some(vec![]),
        nonce_key: TEMPO_VECTOR_NONCE_KEY.to_string(),
        nonce: TEMPO_VECTOR_NONCE.to_string(),
        valid_before: None,
        valid_after: None,
        fee_token: Some(TEMPO_VECTOR_FEE_TOKEN.to_string()),
        fee_payer_signature: Some(FeePayerSignature::None),
        aa_authorization_list: None,
        key_authorization: None,
    }
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

#[cfg(feature = "tx-finalization")]
#[test]
fn parity_tempo_invalid_vectors_with_web_binding() {
    assert!(VECTORS_JSON.contains(TEMPO_INVALID_AA_AUTHORIZATION_LIST_ERROR));
    assert!(VECTORS_JSON.contains(TEMPO_INVALID_KEY_AUTHORIZATION_ERROR));

    let sender_signature = from_hex(TEMPO_INVALID_SENDER_SIGNATURE_HEX);

    let mut tx_invalid_aa = tempo_invalid_vector_tx();
    tx_invalid_aa.aa_authorization_list = Some(TempoRlpValue::Bytes(vec![
        TEMPO_INVALID_AA_AUTHORIZATION_LIST_ENTRY,
    ]));
    let ios_aa_error = ios_encode_tempo_signed_tx(&tx_invalid_aa, sender_signature.as_slice())
        .expect_err("ios aaAuthorizationList should be rejected");
    let web_aa_error = signer_platform_web::tempo_tx::encode_tempo_signed_tx(
        &tx_invalid_aa,
        sender_signature.as_slice(),
    )
    .expect_err("web aaAuthorizationList should be rejected");
    assert_eq!(ios_aa_error.to_string(), web_aa_error.to_string());
    assert!(ios_aa_error
        .to_string()
        .contains(TEMPO_INVALID_AA_AUTHORIZATION_LIST_ERROR));

    let mut tx_invalid_key = tempo_invalid_vector_tx();
    tx_invalid_key.key_authorization = Some(TempoRlpValue::List(vec![]));
    let ios_key_error = ios_encode_tempo_signed_tx(&tx_invalid_key, sender_signature.as_slice())
        .expect_err("ios keyAuthorization should be rejected");
    let web_key_error = signer_platform_web::tempo_tx::encode_tempo_signed_tx(
        &tx_invalid_key,
        sender_signature.as_slice(),
    )
    .expect_err("web keyAuthorization should be rejected");
    assert_eq!(ios_key_error.to_string(), web_key_error.to_string());
    assert!(ios_key_error
        .to_string()
        .contains(TEMPO_INVALID_KEY_AUTHORIZATION_ERROR));
}

#[cfg(all(feature = "tx-finalization", feature = "near-threshold-ed25519"))]
#[test]
fn parity_invalid_tx_finalization_vectors_with_web_binding() {
    assert!(VECTORS_JSON.contains(EIP1559_INVALID_SIGNATURE65_TOO_SHORT_ERROR));
    assert!(VECTORS_JSON.contains(NEAR_INVALID_NEP413_NONCE_LENGTH_ERROR));

    let short_signature = from_hex(EIP1559_INVALID_SIGNATURE65_TOO_SHORT_HEX);
    let ios_eip_error = ios_encode_eip1559_signed_tx_from_signature65(
        &eip1559_vector_tx(),
        short_signature.as_slice(),
    )
    .expect_err("ios short signature65 should be rejected");
    let web_eip_error = signer_platform_web::eip1559::encode_eip1559_signed_tx_from_signature65(
        &eip1559_vector_tx(),
        short_signature.as_slice(),
    )
    .expect_err("web short signature65 should be rejected");
    assert_eq!(ios_eip_error.to_string(), web_eip_error.to_string());
    assert!(ios_eip_error
        .to_string()
        .contains(EIP1559_INVALID_SIGNATURE65_TOO_SHORT_ERROR));

    let ios_near_error = ios_compute_nep413_signing_digest_from_nonce_base64(
        NEAR_INVALID_NEP413_MESSAGE,
        NEAR_INVALID_NEP413_RECIPIENT,
        NEAR_INVALID_NEP413_NONCE_BASE64_TOO_SHORT,
        None,
    )
    .expect_err("ios short NEP-413 nonce should be rejected");
    let web_near_error = signer_platform_web::near_threshold_ed25519::compute_nep413_signing_digest_from_nonce_base64(
        NEAR_INVALID_NEP413_MESSAGE,
        NEAR_INVALID_NEP413_RECIPIENT,
        NEAR_INVALID_NEP413_NONCE_BASE64_TOO_SHORT,
        None,
    )
    .expect_err("web short NEP-413 nonce should be rejected");
    assert_eq!(ios_near_error.to_string(), web_near_error.to_string());
    assert!(ios_near_error
        .to_string()
        .contains(NEAR_INVALID_NEP413_NONCE_LENGTH_ERROR));
}
