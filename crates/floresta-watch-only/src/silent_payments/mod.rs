//! Silent Payments implementation for Floresta
//!
//! This module implements BIP-352 Silent Payments (receive-only) for
//! Floresta's watch-only wallet. It integrates with the BlockConsumer
//! trait to efficiently scan blocks for incoming silent payments.
//!
//! # Overview
//!
//! Silent Payments allow users to receive Bitcoin without revealing
//! their receiving addresses on-chain. This implementation focuses
//! on the "forward scanning" path: detecting payments to the wallet's
//! silent payment address as new blocks arrive.
//!
//! # Architecture
//!
//! - **protocol**: BIP-352 core primitives (ECDH, output derivation, tagged hashes)
//! - **scanner**: Transaction and block scanning logic
//! - **keys**: Key management and output detection
//! - **labels**: Label computation and change detection (m=0 to 2^31-1)
//! - **database**: Database trait extensions for persistent storage
//! - **error**: Silent payment specific error types
//!
//! # Example
//!
//! ```
//! # use floresta_watch_only::silent_payments::SilentPaymentKeys;
//! # use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1};
//! # let secp = Secp256k1::new();
//! # let scan_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
//! # let spend_pubkey = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
//! // Load silent payment keys
//! let keys = SilentPaymentKeys::new(scan_key, spend_pubkey);
//! ```

pub mod database;

pub mod error;

pub mod keys;

pub mod labels;

pub mod protocol;

pub mod scanner;

#[cfg(test)]
mod tests;

pub use error::SilentPaymentError;
pub use keys::SilentPaymentKeys;
pub use keys::SpOutput;
pub use scanner::SilentPaymentScanner;
