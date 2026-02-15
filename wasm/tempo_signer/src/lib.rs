mod codec;
mod errors;
mod tempo_tx;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_tempo_signer() {
    // no-op
}

#[wasm_bindgen]
pub fn compute_tempo_sender_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    tempo_tx::compute_tempo_sender_hash(tx)
}

#[wasm_bindgen]
pub fn encode_tempo_signed_tx(tx: JsValue, sender_signature: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    tempo_tx::encode_tempo_signed_tx(tx, sender_signature)
}
