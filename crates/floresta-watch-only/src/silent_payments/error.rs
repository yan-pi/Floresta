//! Silent Payment specific error types
//!
//! This module defines comprehensive error types for Silent Payment operations,
//! following Floresta's convention of exact and meaningful errors that explain
//! what went wrong and provide context.

use floresta_common::prelude::*;

/// Errors that can occur during Silent Payment operations
#[derive(Debug)]
pub enum SilentPaymentError {
    /// Failed to extract public key from input at index {input_index}: {reason}
    InputKeyExtractionFailed {
        /// Index of the input that failed extraction
        input_index: usize,

        /// Detailed reason for the failure
        reason: String,
    },

    /// Invalid scan private key: {reason}
    InvalidScanKey {
        /// Reason the scan key is invalid
        reason: String,
    },

    /// Invalid spend public key: {reason}
    InvalidSpendPubkey {
        /// Reason the spend pubkey is invalid
        reason: String,
    },

    /// ECDH computation failed for input sum: {reason}
    EcdhFailed {
        /// Reason ECDH failed
        reason: String,
    },

    /// Shared secret derivation failed: {reason}
    SharedSecretFailed {
        /// Reason shared secret derivation failed
        reason: String,
    },

    /// Output derivation failed at index {output_index}: {reason}
    OutputDerivationFailed {
        /// Index of the output that failed derivation
        output_index: u32,

        /// Reason the derivation failed
        reason: String,
    },

    /// Label computation failed for label {label}: {reason}
    LabelComputationFailed {
        /// Label value that failed (m value)
        label: u32,

        /// Reason the computation failed
        reason: String,
    },

    /// Transaction has no eligible inputs for Silent Payments
    NoEligibleInputs,

    /// Transaction has no P2TR outputs (required for Silent Payments)
    NoTaprootOutputs,

    /// Database operation failed: {reason}
    DatabaseError {
        /// Reason the database operation failed
        reason: String,
    },

    /// Invalid label value {label}: must be 0 to 2^31-1
    InvalidLabelValue {
        /// The invalid label value
        label: u32,
    },

    /// Serialization failed: {reason}
    SerializationFailed {
        /// Reason serialization failed
        reason: String,
    },

    /// Deserialization failed: {reason}
    DeserializationFailed {
        /// Reason deserialization failed
        reason: String,
    },
}

impl fmt::Display for SilentPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputKeyExtractionFailed {
                input_index,
                reason,
            } => {
                write!(
                    f,
                    "Failed to extract public key from input {}: {}",
                    input_index, reason
                )
            }

            Self::InvalidScanKey { reason } => {
                write!(f, "Invalid scan private key: {}", reason)
            }

            Self::InvalidSpendPubkey { reason } => {
                write!(f, "Invalid spend public key: {}", reason)
            }

            Self::EcdhFailed { reason } => {
                write!(f, "ECDH computation failed for input sum: {}", reason)
            }

            Self::SharedSecretFailed { reason } => {
                write!(f, "Shared secret derivation failed: {}", reason)
            }

            Self::OutputDerivationFailed {
                output_index,
                reason,
            } => {
                write!(
                    f,
                    "Output derivation failed at index {}: {}",
                    output_index, reason
                )
            }

            Self::LabelComputationFailed { label, reason } => {
                write!(
                    f,
                    "Label computation failed for label {}: {}",
                    label, reason
                )
            }

            Self::NoEligibleInputs => {
                write!(f, "Transaction has no eligible inputs for Silent Payments")
            }

            Self::NoTaprootOutputs => {
                write!(
                    f,
                    "Transaction has no P2TR outputs (required for Silent Payments)"
                )
            }

            Self::DatabaseError { reason } => {
                write!(f, "Database operation failed: {}", reason)
            }

            Self::InvalidLabelValue { label } => {
                write!(f, "Invalid label value {}: must be 0 to 2^31-1", label)
            }

            Self::SerializationFailed { reason } => {
                write!(f, "Serialization failed: {}", reason)
            }

            Self::DeserializationFailed { reason } => {
                write!(f, "Deserialization failed: {}", reason)
            }
        }
    }
}

impl Error for SilentPaymentError {}
