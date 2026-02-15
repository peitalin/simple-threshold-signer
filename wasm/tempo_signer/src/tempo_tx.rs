use wasm_bindgen::prelude::*;

use crate::errors::{js_core_err, js_invalid_input_err};

pub fn compute_tempo_sender_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    let tx: signer_platform_web::tempo_tx::TempoTx = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| js_invalid_input_err(format!("invalid tx: {e}")))?;
    signer_platform_web::tempo_tx::compute_tempo_sender_hash(&tx).map_err(js_core_err)
}

pub fn encode_tempo_signed_tx(tx: JsValue, sender_signature: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let tx: signer_platform_web::tempo_tx::TempoTx = serde_wasm_bindgen::from_value(tx)
        .map_err(|e| js_invalid_input_err(format!("invalid tx: {e}")))?;
    signer_platform_web::tempo_tx::encode_tempo_signed_tx(&tx, sender_signature.as_slice())
        .map_err(js_core_err)
}
