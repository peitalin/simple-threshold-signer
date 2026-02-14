#[cfg(all(
    feature = "secp256k1",
    feature = "near-ed25519",
    feature = "near-crypto"
))]
#[path = "../fixtures/signing-vectors/v1_test_vectors.rs"]
mod vectors;

#[cfg(all(
    feature = "secp256k1",
    feature = "near-ed25519",
    feature = "near-crypto"
))]
use vectors::*;

#[cfg(all(
    feature = "secp256k1",
    feature = "near-ed25519",
    feature = "near-crypto"
))]
#[test]
fn vectors_v1_match_expected_outputs() {
    assert!(VECTORS_JSON.contains("\"version\": \"v1\""));
    assert!(VECTORS_JSON.contains(HEX_EXPECTED));
    assert!(VECTORS_JSON.contains(SECP_DERIVE_KEYPAIR_EXPECTED));

    assert_eq!(
        to_hex(
            signer_core::codec::hex_to_bytes(HEX_INPUT)
                .expect("hex_to_bytes")
                .as_slice()
        ),
        HEX_EXPECTED
    );
    assert_eq!(
        to_hex(
            signer_core::codec::u256_bytes_be_from_dec(U256_INPUT)
                .expect("u256")
                .as_slice()
        ),
        U256_EXPECTED
    );
    let strip_input = from_hex(STRIP_INPUT_HEX);
    assert_eq!(
        to_hex(signer_core::codec::strip_leading_zeros_slice(
            strip_input.as_slice()
        )),
        STRIP_EXPECTED
    );
    assert_eq!(
        to_hex(
            signer_core::codec::rlp_encode_bytes(from_hex(RLP_BYTES_INPUT_HEX).as_slice())
                .as_slice()
        ),
        RLP_BYTES_EXPECTED
    );
    let rlp_items = vec![from_hex(RLP_LIST_ITEM_0_HEX), from_hex(RLP_LIST_ITEM_1_HEX)];
    assert_eq!(
        to_hex(signer_core::codec::rlp_encode_list(rlp_items.as_slice()).as_slice()),
        RLP_LIST_EXPECTED
    );

    assert_eq!(
        to_hex(
            signer_core::secp256k1::derive_threshold_secp256k1_client_share(
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
            signer_core::secp256k1::derive_secp256k1_keypair_from_prf_second(
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
            signer_core::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
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
            signer_core::secp256k1::validate_secp256k1_public_key_33(
                from_hex(VALIDATE_PK_HEX).as_slice(),
            )
            .expect("validate pk")
            .as_slice()
        ),
        VALIDATE_PK_HEX
    );

    assert_eq!(
        to_hex(
            signer_core::secp256k1::add_secp256k1_public_keys_33(
                from_hex(VALIDATE_PK_HEX).as_slice(),
                from_hex(ADD_RIGHT_PK_HEX).as_slice(),
            )
            .expect("add pks")
            .as_slice()
        ),
        ADD_EXPECTED
    );

    let (priv_key, pub_key) = signer_core::near_ed25519::derive_ed25519_key_from_prf_output(
        NEAR_PRF_B64U,
        NEAR_ACCOUNT_ID,
    )
    .expect("near derive");
    assert_eq!(priv_key, NEAR_PRIVATE_EXPECTED);
    assert_eq!(pub_key, NEAR_PUBLIC_EXPECTED);

    assert_eq!(
        to_hex(
            signer_core::near_crypto::derive_kek_from_wrap_key_seed_b64u(
                WRAP_SEED_B64U,
                WRAP_SALT_B64U,
            )
            .expect("derive kek")
            .as_slice()
        ),
        KEK_EXPECTED
    );

    let ciphertext = signer_core::near_crypto::encrypt_data_chacha20(
        CHACHA_PLAIN,
        from_hex(CHACHA_KEY_HEX).as_slice(),
        from_hex(CHACHA_NONCE_HEX).as_slice(),
    )
    .expect("encrypt chacha20");
    assert_eq!(to_hex(ciphertext.as_slice()), CHACHA_CIPHERTEXT_EXPECTED);

    assert_eq!(
        signer_core::near_crypto::decrypt_data_chacha20(
            ciphertext.as_slice(),
            from_hex(CHACHA_NONCE_HEX).as_slice(),
            from_hex(CHACHA_KEY_HEX).as_slice(),
        )
        .expect("decrypt chacha20"),
        CHACHA_PLAIN
    );
}
