use wasm_bindgen::prelude::*;

use crate::errors::js_core_err;

pub fn sign_secp256k1_recoverable(
    digest32: Vec<u8>,
    private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    signer_platform_web::secp256k1::sign_secp256k1_recoverable(
        digest32.as_slice(),
        private_key32.as_slice(),
    )
    .map_err(js_core_err)
}
