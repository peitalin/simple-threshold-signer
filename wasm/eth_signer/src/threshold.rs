use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use crate::errors::js_core_err;

#[wasm_bindgen]
pub struct ThresholdEcdsaPresignSession {
    inner: signer_platform_web::threshold_ecdsa::ThresholdEcdsaPresignSession,
}

fn progress_to_js(
    progress: signer_platform_web::threshold_ecdsa::ThresholdEcdsaPresignProgress,
) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("stage"),
        &JsValue::from_str(progress.stage.as_str()),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("event"),
        &JsValue::from_str(progress.event.as_str()),
    )?;

    let arr = Array::new();
    for msg in progress.outgoing {
        let u8 = Uint8Array::from(msg.as_slice());
        arr.push(&u8);
    }
    Reflect::set(&obj, &JsValue::from_str("outgoing"), &arr)?;

    Ok(obj.into())
}

#[wasm_bindgen]
impl ThresholdEcdsaPresignSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        participant_ids: Vec<u32>,
        me: u32,
        threshold: u32,
        private_share32: Vec<u8>,
        public_key_sec1: Vec<u8>,
    ) -> Result<ThresholdEcdsaPresignSession, JsValue> {
        let inner = signer_platform_web::threshold_ecdsa::ThresholdEcdsaPresignSession::new(
            participant_ids.as_slice(),
            me,
            threshold,
            private_share32.as_slice(),
            public_key_sec1.as_slice(),
        )
        .map_err(js_core_err)?;

        Ok(Self { inner })
    }

    #[wasm_bindgen]
    pub fn stage(&self) -> String {
        self.inner.stage().to_string()
    }

    #[wasm_bindgen]
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    #[wasm_bindgen]
    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        let progress = self.inner.poll().map_err(js_core_err)?;
        progress_to_js(progress)
    }

    #[wasm_bindgen]
    pub fn message(&mut self, from: u32, data: Vec<u8>) -> Result<(), JsValue> {
        self.inner.message(from, data.as_slice()).map_err(js_core_err)
    }

    #[wasm_bindgen]
    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_core_err)
    }

    #[wasm_bindgen]
    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.take_presignature_97().map_err(js_core_err)
    }
}

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
    signer_platform_web::threshold_ecdsa::threshold_ecdsa_compute_signature_share(
        participant_ids.as_slice(),
        me,
        public_key_sec1.as_slice(),
        presign_big_r_sec1.as_slice(),
        presign_k_share32.as_slice(),
        presign_sigma_share32.as_slice(),
        digest32.as_slice(),
        entropy32.as_slice(),
    )
    .map_err(js_core_err)
}

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
    signer_platform_web::threshold_ecdsa::threshold_ecdsa_finalize_signature(
        participant_ids.as_slice(),
        relayer_id,
        public_key_sec1.as_slice(),
        presign_big_r_sec1.as_slice(),
        relayer_k_share32.as_slice(),
        relayer_sigma_share32.as_slice(),
        digest32.as_slice(),
        entropy32.as_slice(),
        client_signature_share32.as_slice(),
    )
    .map_err(js_core_err)
}
