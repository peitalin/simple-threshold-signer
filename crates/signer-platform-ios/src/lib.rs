pub use signer_core::codec;

#[cfg(feature = "near-crypto")]
pub use signer_core::near_crypto;

#[cfg(feature = "near-ed25519")]
pub use signer_core::near_ed25519;

#[cfg(feature = "secp256k1")]
pub use signer_core::secp256k1;

/// Versioned iOS-facing API surface.
/// This module is designed to be wrapped by UniFFI/C-ABI in a later phase.
pub mod v1 {
    pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, String> {
        crate::codec::hex_to_bytes(input)
    }

    pub fn u256_bytes_be_from_dec(input: &str) -> Result<Vec<u8>, String> {
        crate::codec::u256_bytes_be_from_dec(input)
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
    }

    #[cfg(feature = "secp256k1")]
    pub fn validate_secp256k1_public_key_33(public_key33: Vec<u8>) -> Result<Vec<u8>, String> {
        crate::secp256k1::validate_secp256k1_public_key_33(public_key33.as_slice())
    }

    #[cfg(feature = "secp256k1")]
    pub fn add_secp256k1_public_keys_33(
        left33: Vec<u8>,
        right33: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        crate::secp256k1::add_secp256k1_public_keys_33(left33.as_slice(), right33.as_slice())
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
    }
}

#[cfg(all(
    test,
    feature = "secp256k1",
    feature = "near-ed25519",
    feature = "near-crypto"
))]
mod tests;
