use k256::SecretKey;
use wasm_bindgen::prelude::*;

pub fn sign_secp256k1_recoverable(
    digest32: Vec<u8>,
    private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    if digest32.len() != 32 {
        return Err(JsValue::from_str("digest32 must be 32 bytes"));
    }
    if private_key32.len() != 32 {
        return Err(JsValue::from_str("privateKey must be 32 bytes"));
    }

    use k256::ecdsa::{Signature, SigningKey};

    let sk = SecretKey::from_slice(&private_key32)
        .map_err(|_| JsValue::from_str("invalid secp256k1 private key"))?;
    let signing_key: SigningKey = sk.into();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(&digest32)
        .map_err(|_| JsValue::from_str("secp256k1 signing failed"))?;

    let sig: Signature = sig;
    // Ethereum requires low-s normalized signatures (EIP-2).
    // When normalizing s -> n-s, the recovery id flips parity.
    let (sig, recid) = match sig.normalize_s() {
        Some(normalized) => {
            let flipped = k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1)
                .ok_or_else(|| JsValue::from_str("invalid recovery id"))?;
            (normalized, flipped)
        }
        None => (sig, recid),
    };
    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    out.push(recid.to_byte());
    Ok(out)
}
