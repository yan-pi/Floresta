//! Silent Payment keys and output data structures
//!
//! This module defines the core data structures for managing Silent Payment
//! keys and detected outputs.

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::SecretKey;
use bitcoin::OutPoint;
use bitcoin::Txid;

use crate::silent_payments::SilentPaymentError;

/// Silent Payment keys for a wallet
///
/// Contains the scan private key and spend public key needed to detect
/// and spend Silent Payment outputs. This is the receive-only configuration.
#[derive(Debug, Clone)]
pub struct SilentPaymentKeys {
    /// The scan private key (b_scan)
    ///
    /// Used to compute shared secrets with transaction inputs to detect outputs
    scan_privkey: SecretKey,

    /// The spend public key (B_spend)
    ///
    /// The base public key that is tweaked to derive output scriptPubKeys
    spend_pubkey: PublicKey,
}

impl SilentPaymentKeys {
    /// Create a new SilentPaymentKeys instance
    ///
    /// # Arguments
    ///
    /// * `scan_privkey` - The scan private key (b_scan)
    /// * `spend_pubkey` - The spend public key (B_spend)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use bitcoin::secp256k1::{SecretKey, PublicKey};
    /// # use floresta_watch_only::silent_payments::SilentPaymentKeys;
    /// # let scan_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
    /// # let spend_pubkey = PublicKey::from_slice(&[
    /// #     0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    /// #     0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
    /// #     0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
    /// #     0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    /// # ]).unwrap();
    /// let keys = SilentPaymentKeys::new(scan_privkey, spend_pubkey);
    /// ```
    pub fn new(scan_privkey: SecretKey, spend_pubkey: PublicKey) -> Self {
        Self {
            scan_privkey,
            spend_pubkey,
        }
    }

    /// Get a reference to the scan private key
    pub fn scan_privkey(&self) -> &SecretKey {
        &self.scan_privkey
    }

    /// Get a reference to the spend public key
    pub fn spend_pubkey(&self) -> &PublicKey {
        &self.spend_pubkey
    }
}

/// A detected Silent Payment output
///
/// Represents an output that was successfully matched to the wallet's
/// Silent Payment keys during blockchain scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpOutput {
    /// The outpoint (txid + vout) of this output
    pub outpoint: OutPoint,

    /// The amount in satoshis
    pub amount: u64,

    /// The label value (m) if this output used a label, None for unlabeled
    ///
    /// m=0 is reserved for change detection
    pub label: Option<u32>,

    /// The block height where this output was found
    pub block_height: u32,

    /// The block timestamp when this output was found
    pub block_time: u32,

    /// The tweak value used to derive this output
    ///
    /// This is the hash(shared_secret || k) value and is needed for spending
    pub tweak: sha256::Hash,
}

impl SpOutput {
    /// Create a new SpOutput
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        txid: Txid,
        vout: u32,
        amount: u64,
        label: Option<u32>,
        block_height: u32,
        block_time: u32,
        tweak: sha256::Hash,
    ) -> Self {
        Self {
            outpoint: OutPoint { txid, vout },
            amount,
            label,
            block_height,
            block_time,
            tweak,
        }
    }

    /// Check if this is a change output (label m=0)
    pub fn is_change(&self) -> bool {
        self.label == Some(0)
    }

    /// Validate the label value if present
    ///
    /// Labels must be in range 0 to 2^31-1
    pub fn validate_label(&self) -> Result<(), SilentPaymentError> {
        if let Some(label) = self.label {
            if label >= (1 << 31) {
                return Err(SilentPaymentError::InvalidLabelValue { label });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    #[test]
    fn test_sp_output_is_change() {
        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            Some(0),
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(output.is_change());

        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            Some(1),
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(!output.is_change());

        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            None,
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(!output.is_change());
    }

    #[test]
    fn test_sp_output_validate_label() {
        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            Some(0),
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(output.validate_label().is_ok());

        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            Some((1 << 31) - 1),
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(output.validate_label().is_ok());

        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            Some(1 << 31),
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(output.validate_label().is_err());

        let output = SpOutput::new(
            Txid::all_zeros(),
            0,
            1000,
            None,
            100,
            1000000,
            sha256::Hash::all_zeros(),
        );
        assert!(output.validate_label().is_ok());
    }
}
