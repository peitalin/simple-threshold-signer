use wasm_bindgen::prelude::*;

use crate::errors::js_core_err;

pub fn build_webauthn_p256_signature(
    challenge32: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
    pub_key_x32: Vec<u8>,
    pub_key_y32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::webauthn_p256::build_webauthn_p256_signature(
        challenge32,
        authenticator_data,
        client_data_json,
        signature_der,
        pub_key_x32,
        pub_key_y32,
    )
    .map_err(js_core_err)
}
