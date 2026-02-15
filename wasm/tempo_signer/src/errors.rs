use serde::Serialize;
use signer_platform_web::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::JsValue;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerWorkerErrorWire {
    code: String,
    core_code: String,
    message: String,
}

fn map_core_code_to_host_code(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "SIGNER_INVALID_INPUT",
        SignerCoreErrorCode::InvalidLength => "SIGNER_INVALID_LENGTH",
        SignerCoreErrorCode::DecodeError => "SIGNER_DECODE_ERROR",
        SignerCoreErrorCode::EncodeError => "SIGNER_ENCODE_ERROR",
        SignerCoreErrorCode::HkdfError => "SIGNER_KDF_ERROR",
        SignerCoreErrorCode::CryptoError => "SIGNER_CRYPTO_ERROR",
        SignerCoreErrorCode::Utf8Error => "SIGNER_UTF8_ERROR",
        SignerCoreErrorCode::Unsupported => "SIGNER_UNSUPPORTED",
        SignerCoreErrorCode::Internal => "SIGNER_INTERNAL",
    }
}

fn core_code_name(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "InvalidInput",
        SignerCoreErrorCode::InvalidLength => "InvalidLength",
        SignerCoreErrorCode::DecodeError => "DecodeError",
        SignerCoreErrorCode::EncodeError => "EncodeError",
        SignerCoreErrorCode::HkdfError => "HkdfError",
        SignerCoreErrorCode::CryptoError => "CryptoError",
        SignerCoreErrorCode::Utf8Error => "Utf8Error",
        SignerCoreErrorCode::Unsupported => "Unsupported",
        SignerCoreErrorCode::Internal => "Internal",
    }
}

fn js_error_with_codes(code: &str, core_code: &str, message: String) -> JsValue {
    let wire = SignerWorkerErrorWire {
        code: code.to_string(),
        core_code: core_code.to_string(),
        message,
    };
    serde_wasm_bindgen::to_value(&wire)
        .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

pub fn js_core_err(err: SignerCoreError) -> JsValue {
    js_error_with_codes(
        map_core_code_to_host_code(err.code),
        core_code_name(err.code),
        err.message,
    )
}

pub fn js_invalid_input_err(msg: impl core::fmt::Display) -> JsValue {
    js_error_with_codes("SIGNER_INVALID_INPUT", "InvalidInput", msg.to_string())
}
