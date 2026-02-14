use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerCoreErrorCode {
    InvalidInput,
    InvalidLength,
    DecodeError,
    EncodeError,
    HkdfError,
    CryptoError,
    Utf8Error,
    Unsupported,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerCoreError {
    pub code: SignerCoreErrorCode,
    pub message: String,
}

impl SignerCoreError {
    pub fn new(code: SignerCoreErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::InvalidInput, message)
    }

    pub fn invalid_length(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::InvalidLength, message)
    }

    pub fn decode_error(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::DecodeError, message)
    }

    pub fn encode_error(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::EncodeError, message)
    }

    pub fn hkdf_error(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::HkdfError, message)
    }

    pub fn crypto_error(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::CryptoError, message)
    }

    pub fn utf8_error(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::Utf8Error, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::Unsupported, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(SignerCoreErrorCode::Internal, message)
    }
}

impl fmt::Display for SignerCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SignerCoreError {}

pub type CoreResult<T> = Result<T, SignerCoreError>;
