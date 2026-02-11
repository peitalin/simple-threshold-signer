mod codec;
mod derive;
mod eip1559;
mod errors;
mod secp256k1_sign;
mod threshold;

use wasm_bindgen::prelude::*;

pub use threshold::ThresholdEcdsaPresignSession;

#[wasm_bindgen]
pub fn init_eth_signer() {
    // no-op; reserved for future logger initialization
}

#[wasm_bindgen]
pub fn threshold_ecdsa_compute_signature_share(
    participant_ids: Vec<u32>,
    me: u32,
    public_key_sec1: Vec<u8>,
    presign_big_r_sec1: Vec<u8>,
    presign_k_share32: Vec<u8>,
    presign_sigma_share32: Vec<u8>,
    digest32: Vec<u8>,
    entropy32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    threshold::threshold_ecdsa_compute_signature_share(
        participant_ids,
        me,
        public_key_sec1,
        presign_big_r_sec1,
        presign_k_share32,
        presign_sigma_share32,
        digest32,
        entropy32,
    )
}

#[wasm_bindgen]
pub fn threshold_ecdsa_finalize_signature(
    participant_ids: Vec<u32>,
    relayer_id: u32,
    public_key_sec1: Vec<u8>,
    presign_big_r_sec1: Vec<u8>,
    relayer_k_share32: Vec<u8>,
    relayer_sigma_share32: Vec<u8>,
    digest32: Vec<u8>,
    entropy32: Vec<u8>,
    client_signature_share32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    threshold::threshold_ecdsa_finalize_signature(
        participant_ids,
        relayer_id,
        public_key_sec1,
        presign_big_r_sec1,
        relayer_k_share32,
        relayer_sigma_share32,
        digest32,
        entropy32,
        client_signature_share32,
    )
}

#[wasm_bindgen]
pub fn compute_eip1559_tx_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    eip1559::compute_eip1559_tx_hash(tx)
}

#[wasm_bindgen]
pub fn encode_eip1559_signed_tx(
    tx: JsValue,
    y_parity: u8,
    r: Vec<u8>,
    s: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    eip1559::encode_eip1559_signed_tx(tx, y_parity, r, s)
}

#[wasm_bindgen]
pub fn sign_secp256k1_recoverable(
    digest32: Vec<u8>,
    private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    secp256k1_sign::sign_secp256k1_recoverable(digest32, private_key32)
}

#[wasm_bindgen]
pub fn derive_threshold_secp256k1_client_share(
    prf_first32: Vec<u8>,
    user_id: String,
    derivation_path: u32,
) -> Result<Vec<u8>, JsValue> {
    derive::derive_threshold_secp256k1_client_share(prf_first32, user_id, derivation_path)
}
