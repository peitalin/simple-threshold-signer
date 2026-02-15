use wasm_bindgen::prelude::*;

use crate::errors::{js_core_err, js_invalid_input_err};

pub fn compute_eip1559_tx_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    let tx: signer_platform_web::eip1559::Eip1559Tx = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| js_invalid_input_err(format!("invalid tx: {e}")))?;
    signer_platform_web::eip1559::compute_eip1559_tx_hash(&tx).map_err(js_core_err)
}

pub fn encode_eip1559_signed_tx_from_signature65(
    tx: JsValue,
    signature65: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let tx: signer_platform_web::eip1559::Eip1559Tx = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| js_invalid_input_err(format!("invalid tx: {e}")))?;
    signer_platform_web::eip1559::encode_eip1559_signed_tx_from_signature65(
        &tx,
        signature65.as_slice(),
    )
    .map_err(js_core_err)
}
