use curve25519_dalek::edwards::EdwardsPoint;
use wasm_bindgen::prelude::*;

pub(crate) fn compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
    client_point: EdwardsPoint,
    relayer_point: EdwardsPoint,
    client_participant_id: u16,
    relayer_participant_id: u16,
) -> Result<[u8; 32], String> {
    let client_bytes = client_point.compress().to_bytes();
    let relayer_bytes = relayer_point.compress().to_bytes();
    signer_platform_web::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_bytes,
        &relayer_bytes,
        client_participant_id,
        relayer_participant_id,
    )
    .map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn threshold_ed25519_keygen_from_client_verifying_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: signer_platform_web::near_threshold_frost::ThresholdEd25519KeygenFromClientVerifyingShareArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_keygen_from_client_verifying_share(args)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize keygen output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_keygen_from_master_secret_and_client_verifying_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: signer_platform_web::near_threshold_frost::ThresholdEd25519KeygenFromMasterSecretArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_keygen_from_master_secret_and_client_verifying_share(args)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize keygen output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_round1_commit(
    relayer_signing_share_b64u: String,
) -> Result<JsValue, JsValue> {
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_round1_commit(
        relayer_signing_share_b64u.as_str(),
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round1 output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_round2_sign(args: JsValue) -> Result<JsValue, JsValue> {
    let args: signer_platform_web::near_threshold_frost::ThresholdEd25519Round2SignArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid round2 args: {e}")))?;
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_round2_sign(args)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round2 output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_round2_sign_cosigner(args: JsValue) -> Result<JsValue, JsValue> {
    let args: signer_platform_web::near_threshold_frost::ThresholdEd25519Round2SignArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid round2 args: {e}")))?;
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_round2_sign_cosigner(args)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round2 output: {e}")))
}
