use threshold_signatures::errors::{InitializationError, ProtocolError};
use wasm_bindgen::prelude::JsValue;

pub fn js_err(msg: impl Into<String>) -> JsValue {
    JsValue::from_str(&msg.into())
}

pub fn map_init_err(e: InitializationError) -> JsValue {
    js_err(format!("protocol init failed: {e:?}"))
}

pub fn map_proto_err(e: ProtocolError) -> JsValue {
    js_err(format!("protocol failed: {e:?}"))
}
