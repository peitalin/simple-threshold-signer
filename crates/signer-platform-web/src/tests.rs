#[path = "../../signer-core/fixtures/signing-vectors/v1_test_vectors.rs"]
mod vectors;
use vectors::*;

#[cfg(feature = "tx-finalization")]
use crate::eip1559::{encode_eip1559_signed_tx_from_signature65, Eip1559Tx};

#[cfg(feature = "near-threshold-ed25519")]
use crate::near_threshold_ed25519::compute_nep413_signing_digest_from_nonce_base64;

#[cfg(feature = "tx-finalization")]
use crate::tempo_tx::{
    encode_tempo_signed_tx, FeePayerSignature, TempoCall, TempoRlpValue, TempoTx,
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
fn vectors_v1_match_expected_outputs() {
    assert!(VECTORS_JSON.contains("\"version\": \"v1\""));
    assert!(VECTORS_JSON.contains(HEX_EXPECTED));
    assert!(VECTORS_JSON.contains(SECP_DERIVE_KEYPAIR_EXPECTED));

    assert_eq!(
        to_hex(
            crate::codec::hex_to_bytes(HEX_INPUT)
                .expect("hex_to_bytes")
                .as_slice()
        ),
        HEX_EXPECTED
    );
    assert_eq!(
        to_hex(
            crate::codec::u256_bytes_be_from_dec(U256_INPUT)
                .expect("u256")
                .as_slice()
        ),
        U256_EXPECTED
    );
    let strip_input = from_hex(STRIP_INPUT_HEX);
    assert_eq!(
        to_hex(crate::codec::strip_leading_zeros_slice(
            strip_input.as_slice()
        )),
        STRIP_EXPECTED
    );
    assert_eq!(
        to_hex(crate::codec::rlp_encode_bytes(from_hex(RLP_BYTES_INPUT_HEX).as_slice()).as_slice()),
        RLP_BYTES_EXPECTED
    );
    let rlp_items = vec![from_hex(RLP_LIST_ITEM_0_HEX), from_hex(RLP_LIST_ITEM_1_HEX)];
    assert_eq!(
        to_hex(crate::codec::rlp_encode_list(rlp_items.as_slice()).as_slice()),
        RLP_LIST_EXPECTED
    );

    assert_eq!(
        to_hex(
            crate::secp256k1::derive_threshold_secp256k1_client_share(
                from_hex(SECP_PRF_FIRST32_HEX).as_slice(),
                SECP_USER_ID,
                SECP_DERIVATION_PATH,
            )
            .expect("derive client share")
            .as_slice()
        ),
        SECP_DERIVE_CLIENT_EXPECTED
    );

    assert_eq!(
        to_hex(
            crate::secp256k1::derive_secp256k1_keypair_from_prf_second(
                from_hex(SECP_PRF_SECOND_HEX).as_slice(),
                SECP_NEAR_ACCOUNT_ID,
            )
            .expect("derive keypair")
            .as_slice()
        ),
        SECP_DERIVE_KEYPAIR_EXPECTED
    );

    assert_eq!(
        to_hex(
            crate::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
                from_hex(MAP_ADDITIVE_SHARE_HEX).as_slice(),
                MAP_PARTICIPANT_ID,
            )
            .expect("map share")
            .as_slice()
        ),
        MAP_EXPECTED
    );

    assert_eq!(
        to_hex(
            crate::secp256k1::validate_secp256k1_public_key_33(
                from_hex(VALIDATE_PK_HEX).as_slice(),
            )
            .expect("validate pk")
            .as_slice()
        ),
        VALIDATE_PK_HEX
    );

    assert_eq!(
        to_hex(
            crate::secp256k1::add_secp256k1_public_keys_33(
                from_hex(VALIDATE_PK_HEX).as_slice(),
                from_hex(ADD_RIGHT_PK_HEX).as_slice(),
            )
            .expect("add pks")
            .as_slice()
        ),
        ADD_EXPECTED
    );

    let (priv_key, pub_key) =
        crate::near_ed25519::derive_ed25519_key_from_prf_output(NEAR_PRF_B64U, NEAR_ACCOUNT_ID)
            .expect("near derive");
    assert_eq!(priv_key, NEAR_PRIVATE_EXPECTED);
    assert_eq!(pub_key, NEAR_PUBLIC_EXPECTED);

    assert_eq!(
        to_hex(
            crate::near_crypto::derive_kek_from_wrap_key_seed_b64u(WRAP_SEED_B64U, WRAP_SALT_B64U)
                .expect("derive kek")
                .as_slice()
        ),
        KEK_EXPECTED
    );

    let ciphertext = crate::near_crypto::encrypt_data_chacha20(
        CHACHA_PLAIN,
        from_hex(CHACHA_KEY_HEX).as_slice(),
        from_hex(CHACHA_NONCE_HEX).as_slice(),
    )
    .expect("encrypt chacha20");
    assert_eq!(to_hex(ciphertext.as_slice()), CHACHA_CIPHERTEXT_EXPECTED);

    assert_eq!(
        crate::near_crypto::decrypt_data_chacha20(
            ciphertext.as_slice(),
            from_hex(CHACHA_NONCE_HEX).as_slice(),
            from_hex(CHACHA_KEY_HEX).as_slice(),
        )
        .expect("decrypt chacha20"),
        CHACHA_PLAIN
    );
}

#[cfg(feature = "tx-finalization")]
#[test]
fn tempo_invalid_vectors_match_expected_errors() {
    assert!(VECTORS_JSON.contains(TEMPO_INVALID_AA_AUTHORIZATION_LIST_ERROR));
    assert!(VECTORS_JSON.contains(TEMPO_INVALID_KEY_AUTHORIZATION_ERROR));

    let sender_signature = from_hex(TEMPO_INVALID_SENDER_SIGNATURE_HEX);

    let mut tx_invalid_aa = tempo_invalid_vector_tx();
    tx_invalid_aa.aa_authorization_list = Some(TempoRlpValue::Bytes(vec![
        TEMPO_INVALID_AA_AUTHORIZATION_LIST_ENTRY,
    ]));
    let aa_err = encode_tempo_signed_tx(&tx_invalid_aa, sender_signature.as_slice())
        .expect_err("aaAuthorizationList should be rejected");
    assert!(aa_err
        .to_string()
        .contains(TEMPO_INVALID_AA_AUTHORIZATION_LIST_ERROR));

    let mut tx_invalid_key = tempo_invalid_vector_tx();
    tx_invalid_key.key_authorization = Some(TempoRlpValue::List(vec![]));
    let key_err = encode_tempo_signed_tx(&tx_invalid_key, sender_signature.as_slice())
        .expect_err("keyAuthorization should be rejected");
    assert!(key_err
        .to_string()
        .contains(TEMPO_INVALID_KEY_AUTHORIZATION_ERROR));
}

#[cfg(all(feature = "tx-finalization", feature = "near-threshold-ed25519"))]
#[test]
fn invalid_tx_finalization_vectors_match_expected_errors() {
    assert!(VECTORS_JSON.contains(EIP1559_INVALID_SIGNATURE65_TOO_SHORT_ERROR));
    assert!(VECTORS_JSON.contains(NEAR_INVALID_NEP413_NONCE_LENGTH_ERROR));

    let short_signature = from_hex(EIP1559_INVALID_SIGNATURE65_TOO_SHORT_HEX);
    let eip_error =
        encode_eip1559_signed_tx_from_signature65(&eip1559_vector_tx(), short_signature.as_slice())
            .expect_err("short signature65 must be rejected");
    assert!(eip_error
        .to_string()
        .contains(EIP1559_INVALID_SIGNATURE65_TOO_SHORT_ERROR));

    let near_error = compute_nep413_signing_digest_from_nonce_base64(
        NEAR_INVALID_NEP413_MESSAGE,
        NEAR_INVALID_NEP413_RECIPIENT,
        NEAR_INVALID_NEP413_NONCE_BASE64_TOO_SHORT,
        None,
    )
    .expect_err("short NEP-413 nonce must be rejected");
    assert!(near_error
        .to_string()
        .contains(NEAR_INVALID_NEP413_NONCE_LENGTH_ERROR));
}
