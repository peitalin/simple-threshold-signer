pub use signer_core::codec;

#[cfg(feature = "near-crypto")]
pub use signer_core::near_crypto;

#[cfg(feature = "near-ed25519")]
pub use signer_core::near_ed25519;

#[cfg(feature = "near-threshold-ed25519")]
pub use signer_core::near_threshold_ed25519;

#[cfg(feature = "secp256k1")]
pub use signer_core::secp256k1;

#[cfg(feature = "tx-finalization")]
pub use signer_core::eip1559;

#[cfg(feature = "tx-finalization")]
pub use signer_core::tempo_tx;

use std::ffi::{c_char, CStr, CString};
use std::ptr;

fn read_c_string(input: *const c_char) -> Option<String> {
    if input.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `input` points to a valid NUL-terminated C string.
    let cstr = unsafe { CStr::from_ptr(input) };
    cstr.to_str().ok().map(ToOwned::to_owned)
}

fn into_c_string_ptr(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` must have been allocated by `CString::into_raw` in this module.
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_hex_to_bytes_hex(input: *const c_char) -> *mut c_char {
    let input = match read_c_string(input) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let bytes = match v1::hex_to_bytes(input.as_str()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    into_c_string_ptr(bytes_to_hex(bytes.as_slice()))
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_u256_bytes_be_from_dec_hex(
    input: *const c_char,
) -> *mut c_char {
    let input = match read_c_string(input) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let bytes = match v1::u256_bytes_be_from_dec(input.as_str()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    into_c_string_ptr(bytes_to_hex(bytes.as_slice()))
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_strip_leading_zeros_hex(
    input_hex: *const c_char,
) -> *mut c_char {
    let input_hex = match read_c_string(input_hex) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let bytes = match v1::hex_to_bytes(input_hex.as_str()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    into_c_string_ptr(bytes_to_hex(v1::strip_leading_zeros(bytes).as_slice()))
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_rlp_encode_bytes_hex(input_hex: *const c_char) -> *mut c_char {
    let input_hex = match read_c_string(input_hex) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let bytes = match v1::hex_to_bytes(input_hex.as_str()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    into_c_string_ptr(bytes_to_hex(v1::rlp_encode_bytes(bytes).as_slice()))
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_rlp_encode_list_hex(
    first_hex: *const c_char,
    second_hex: *const c_char,
) -> *mut c_char {
    let first_hex = match read_c_string(first_hex) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let second_hex = match read_c_string(second_hex) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let first = match v1::hex_to_bytes(first_hex.as_str()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    let second = match v1::hex_to_bytes(second_hex.as_str()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    let items = vec![first, second];
    into_c_string_ptr(bytes_to_hex(v1::rlp_encode_list(items).as_slice()))
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_derive_threshold_secp256k1_client_share_hex(
    prf_first32_hex: *const c_char,
    user_id: *const c_char,
    derivation_path: u32,
) -> *mut c_char {
    #[cfg(feature = "secp256k1")]
    {
        let prf_first32_hex = match read_c_string(prf_first32_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let user_id = match read_c_string(user_id) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let prf_first32 = match v1::hex_to_bytes(prf_first32_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let bytes = match v1::derive_threshold_secp256k1_client_share(prf_first32, user_id, derivation_path) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = (prf_first32_hex, user_id, derivation_path);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_derive_secp256k1_keypair_from_prf_second_hex(
    prf_second_hex: *const c_char,
    near_account_id: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "secp256k1")]
    {
        let prf_second_hex = match read_c_string(prf_second_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let near_account_id = match read_c_string(near_account_id) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let prf_second = match v1::hex_to_bytes(prf_second_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let bytes = match v1::derive_secp256k1_keypair_from_prf_second(prf_second, near_account_id) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = (prf_second_hex, near_account_id);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_map_additive_share_to_threshold_signatures_share_2p_hex(
    additive_share32_hex: *const c_char,
    participant_id: u32,
) -> *mut c_char {
    #[cfg(feature = "secp256k1")]
    {
        let additive_share32_hex = match read_c_string(additive_share32_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let additive_share32 = match v1::hex_to_bytes(additive_share32_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let bytes = match v1::map_additive_share_to_threshold_signatures_share_2p(
            additive_share32,
            participant_id,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = (additive_share32_hex, participant_id);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_validate_secp256k1_public_key_33_hex(
    public_key33_hex: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "secp256k1")]
    {
        let public_key33_hex = match read_c_string(public_key33_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let public_key33 = match v1::hex_to_bytes(public_key33_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let bytes = match v1::validate_secp256k1_public_key_33(public_key33) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = public_key33_hex;
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_add_secp256k1_public_keys_33_hex(
    left33_hex: *const c_char,
    right33_hex: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "secp256k1")]
    {
        let left33_hex = match read_c_string(left33_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let right33_hex = match read_c_string(right33_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let left33 = match v1::hex_to_bytes(left33_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let right33 = match v1::hex_to_bytes(right33_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let bytes = match v1::add_secp256k1_public_keys_33(left33, right33) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = (left33_hex, right33_hex);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_derive_ed25519_keypair(
    prf_output_base64: *const c_char,
    account_id: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "near-ed25519")]
    {
        let prf_output_base64 = match read_c_string(prf_output_base64) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let account_id = match read_c_string(account_id) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let (private_key, public_key) = match v1::derive_ed25519_key_from_prf_output(
            prf_output_base64,
            account_id,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let combined = format!("{private_key}\n{public_key}");
        return into_c_string_ptr(combined);
    }
    #[cfg(not(feature = "near-ed25519"))]
    {
        let _ = (prf_output_base64, account_id);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_derive_kek_from_wrap_key_seed_b64u_hex(
    wrap_key_seed_b64u: *const c_char,
    wrap_key_salt_b64u: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "near-crypto")]
    {
        let wrap_key_seed_b64u = match read_c_string(wrap_key_seed_b64u) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let wrap_key_salt_b64u = match read_c_string(wrap_key_salt_b64u) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let bytes = match v1::derive_kek_from_wrap_key_seed_b64u(wrap_key_seed_b64u, wrap_key_salt_b64u) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "near-crypto"))]
    {
        let _ = (wrap_key_seed_b64u, wrap_key_salt_b64u);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_encrypt_data_chacha20_hex(
    plain_text_data: *const c_char,
    key_hex: *const c_char,
    nonce_hex: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "near-crypto")]
    {
        let plain_text_data = match read_c_string(plain_text_data) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let key_hex = match read_c_string(key_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let nonce_hex = match read_c_string(nonce_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let key_bytes = match v1::hex_to_bytes(key_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let nonce_bytes = match v1::hex_to_bytes(nonce_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let bytes = match v1::encrypt_data_chacha20(plain_text_data, key_bytes, nonce_bytes) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(bytes_to_hex(bytes.as_slice()));
    }
    #[cfg(not(feature = "near-crypto"))]
    {
        let _ = (plain_text_data, key_hex, nonce_hex);
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn signer_platform_ios_v1_decrypt_data_chacha20(
    encrypted_hex: *const c_char,
    nonce_hex: *const c_char,
    key_hex: *const c_char,
) -> *mut c_char {
    #[cfg(feature = "near-crypto")]
    {
        let encrypted_hex = match read_c_string(encrypted_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let nonce_hex = match read_c_string(nonce_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let key_hex = match read_c_string(key_hex) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let encrypted_data = match v1::hex_to_bytes(encrypted_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let nonce_bytes = match v1::hex_to_bytes(nonce_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let key_bytes = match v1::hex_to_bytes(key_hex.as_str()) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let plain_text = match v1::decrypt_data_chacha20(encrypted_data, nonce_bytes, key_bytes) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return into_c_string_ptr(plain_text);
    }
    #[cfg(not(feature = "near-crypto"))]
    {
        let _ = (encrypted_hex, nonce_hex, key_hex);
        ptr::null_mut()
    }
}

/// Versioned iOS-facing API surface.
/// This module is designed to be wrapped by UniFFI/C-ABI in a later phase.
pub mod v1 {
    pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, String> {
        crate::codec::hex_to_bytes(input).map_err(|e| e.to_string())
    }

    pub fn u256_bytes_be_from_dec(input: &str) -> Result<Vec<u8>, String> {
        crate::codec::u256_bytes_be_from_dec(input).map_err(|e| e.to_string())
    }

    pub fn strip_leading_zeros(bytes: Vec<u8>) -> Vec<u8> {
        crate::codec::strip_leading_zeros_vec(bytes)
    }

    pub fn rlp_encode_bytes(bytes: Vec<u8>) -> Vec<u8> {
        crate::codec::rlp_encode_bytes(bytes.as_slice())
    }

    pub fn rlp_encode_list(items: Vec<Vec<u8>>) -> Vec<u8> {
        crate::codec::rlp_encode_list(items.as_slice())
    }

    #[cfg(feature = "secp256k1")]
    pub fn derive_threshold_secp256k1_client_share(
        prf_first32: Vec<u8>,
        user_id: String,
        derivation_path: u32,
    ) -> Result<Vec<u8>, String> {
        crate::secp256k1::derive_threshold_secp256k1_client_share(
            prf_first32.as_slice(),
            user_id.as_str(),
            derivation_path,
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "secp256k1")]
    pub fn derive_secp256k1_keypair_from_prf_second(
        prf_second: Vec<u8>,
        near_account_id: String,
    ) -> Result<Vec<u8>, String> {
        crate::secp256k1::derive_secp256k1_keypair_from_prf_second(
            prf_second.as_slice(),
            near_account_id.as_str(),
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "secp256k1")]
    pub fn map_additive_share_to_threshold_signatures_share_2p(
        additive_share32: Vec<u8>,
        participant_id: u32,
    ) -> Result<Vec<u8>, String> {
        crate::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
            additive_share32.as_slice(),
            participant_id,
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "secp256k1")]
    pub fn validate_secp256k1_public_key_33(public_key33: Vec<u8>) -> Result<Vec<u8>, String> {
        crate::secp256k1::validate_secp256k1_public_key_33(public_key33.as_slice())
            .map_err(|e| e.to_string())
    }

    #[cfg(feature = "secp256k1")]
    pub fn add_secp256k1_public_keys_33(
        left33: Vec<u8>,
        right33: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        crate::secp256k1::add_secp256k1_public_keys_33(left33.as_slice(), right33.as_slice())
            .map_err(|e| e.to_string())
    }

    #[cfg(feature = "near-ed25519")]
    pub fn derive_ed25519_key_from_prf_output(
        prf_output_base64: String,
        account_id: String,
    ) -> Result<(String, String), String> {
        crate::near_ed25519::derive_ed25519_key_from_prf_output(
            prf_output_base64.as_str(),
            account_id.as_str(),
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "near-crypto")]
    pub fn derive_kek_from_wrap_key_seed_b64u(
        wrap_key_seed_b64u: String,
        wrap_key_salt_b64u: String,
    ) -> Result<Vec<u8>, String> {
        crate::near_crypto::derive_kek_from_wrap_key_seed_b64u(
            wrap_key_seed_b64u.as_str(),
            wrap_key_salt_b64u.as_str(),
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "near-crypto")]
    pub fn encrypt_data_chacha20(
        plain_text_data: String,
        key_bytes: Vec<u8>,
        nonce_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        crate::near_crypto::encrypt_data_chacha20(
            plain_text_data.as_str(),
            key_bytes.as_slice(),
            nonce_bytes.as_slice(),
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "near-crypto")]
    pub fn decrypt_data_chacha20(
        encrypted_data: Vec<u8>,
        nonce_bytes: Vec<u8>,
        key_bytes: Vec<u8>,
    ) -> Result<String, String> {
        crate::near_crypto::decrypt_data_chacha20(
            encrypted_data.as_slice(),
            nonce_bytes.as_slice(),
            key_bytes.as_slice(),
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(all(
    test,
    feature = "secp256k1",
    feature = "near-ed25519",
    feature = "near-crypto"
))]
mod tests;
