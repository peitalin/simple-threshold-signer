#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerOperationVersion {
    V1,
}

impl SignerOperationVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerOperationFamily {
    Codec,
    Secp256k1,
    NearEd25519,
    NearCrypto,
    Eip1559,
    TempoTx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationMetadata {
    pub version: SignerOperationVersion,
    pub family: SignerOperationFamily,
}

impl OperationMetadata {
    pub const fn v1(family: SignerOperationFamily) -> Self {
        Self {
            version: SignerOperationVersion::V1,
            family,
        }
    }
}
