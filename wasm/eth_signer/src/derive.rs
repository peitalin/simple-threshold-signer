use wasm_bindgen::prelude::*;

use crate::errors::js_core_err;

pub fn derive_threshold_secp256k1_client_share(
    prf_first32: Vec<u8>,
    user_id: String,
    derivation_path: u32,
) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::secp256k1::derive_threshold_secp256k1_client_share(
        prf_first32.as_slice(),
        user_id.as_str(),
        derivation_path,
    )
    .map_err(js_core_err)
}

pub fn derive_secp256k1_keypair_from_prf_second(
    prf_second: Vec<u8>,
    near_account_id: String,
) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::secp256k1::derive_secp256k1_keypair_from_prf_second(
        prf_second.as_slice(),
        near_account_id.as_str(),
    )
    .map_err(js_core_err)
}

pub fn map_additive_share_to_threshold_signatures_share_2p(
    additive_share32: Vec<u8>,
    participant_id: u32,
) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
        additive_share32.as_slice(),
        participant_id,
    )
    .map_err(js_core_err)
}

pub fn validate_secp256k1_public_key_33(public_key33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::secp256k1::validate_secp256k1_public_key_33(public_key33.as_slice())
        .map_err(js_core_err)
}

pub fn add_secp256k1_public_keys_33(left33: Vec<u8>, right33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::secp256k1::add_secp256k1_public_keys_33(
        left33.as_slice(),
        right33.as_slice(),
    )
    .map_err(js_core_err)
}
