//! Silent Payment transaction and block scanner
//!
//! This module implements the scanning logic for detecting Silent Payment
//! outputs in transactions and blocks.

use crate::silent_payments::SilentPaymentKeys;

/// Scanner for detecting Silent Payment outputs in blocks
#[derive(Debug)]
pub struct SilentPaymentScanner {
    /// The Silent Payment keys to scan for
    _keys: SilentPaymentKeys,
}

impl SilentPaymentScanner {
    /// Create a new scanner with the given keys
    pub fn new(keys: SilentPaymentKeys) -> Self {
        Self { _keys: keys }
    }
}
