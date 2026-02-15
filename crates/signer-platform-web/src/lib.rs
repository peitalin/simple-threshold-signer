pub use signer_core::codec;
pub use signer_core::error;
pub use signer_core::webauthn_p256;

#[cfg(feature = "secp256k1")]
pub use signer_core::secp256k1;

#[cfg(feature = "threshold-ecdsa")]
pub use signer_core::threshold_ecdsa;

#[cfg(feature = "near-ed25519")]
pub use signer_core::near_ed25519;

#[cfg(feature = "near-threshold-ed25519")]
pub use signer_core::near_threshold_ed25519;
#[cfg(feature = "near-threshold-ed25519")]
pub use signer_core::near_threshold_frost;

#[cfg(feature = "near-crypto")]
pub use signer_core::near_crypto;

#[cfg(feature = "tx-finalization")]
pub use signer_core::eip1559;

#[cfg(feature = "tx-finalization")]
pub use signer_core::tempo_tx;

#[cfg(all(
    test,
    feature = "secp256k1",
    feature = "near-ed25519",
    feature = "near-crypto"
))]
mod tests;
