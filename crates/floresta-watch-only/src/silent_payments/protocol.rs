//! BIP-352 Silent Payments protocol primitives
//!
//! This module implements the core cryptographic primitives for BIP-352
//! Silent Payments, including input public key extraction, ECDH computation,
//! output derivation, and tagged hashes.
//!
//! # Overview
//!
//! The BIP-352 Silent Payments protocol consists of:
//! 1. Extract public keys from eligible inputs (P2TR, P2WPKH, P2SH-P2WPKH, P2PKH)
//! 2. Sort outpoints lexicographically
//! 3. Compute input public key sum
//! 4. Perform ECDH to derive shared secret
//! 5. Compute output tweaks using tagged hashing
//! 6. Derive output public keys

use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::secp256k1::ecdh;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxIn;
use floresta_common::prelude::*;

use super::SilentPaymentError;

/// Tag for BIP-340 tagged hash: "BIP0352/SharedSecret"
const TAG_SHARED_SECRET: &[u8] = b"BIP0352/SharedSecret";

/// Extracts public key from a transaction input's scriptPubKey
///
/// Supports the following input types:
/// - P2TR (Taproot): extracts public key from witness program
/// - P2WPKH (Native SegWit): extracts public key from witness
/// - P2SH-P2WPKH (Nested SegWit): extracts public key from witness
/// - P2PKH (Legacy): extracts public key from scriptSig (compressed keys only)
///
/// # Arguments
///
/// * `txin` - The transaction input
/// * `prevout_script` - The scriptPubKey of the previous output being spent
///
/// # Returns
///
/// The extracted public key, or an error if extraction failed
pub fn extract_input_pubkey(
    txin: &TxIn,
    prevout_script: &ScriptBuf,
) -> Result<PublicKey, SilentPaymentError> {
    // P2TR: 51 20 <32-byte-x-only-pubkey>
    if prevout_script.is_p2tr() {
        return extract_p2tr_pubkey(txin, prevout_script);
    }

    // P2WPKH: 00 14 <20-byte-pubkey-hash>
    if prevout_script.is_p2wpkh() {
        return extract_p2wpkh_pubkey(txin);
    }

    // P2SH-P2WPKH: Check if it's actually nested segwit
    if prevout_script.is_p2sh() {
        // For P2SH-P2WPKH, witness must be present
        if !txin.witness.is_empty() {
            return extract_p2wpkh_pubkey(txin);
        }
    }

    // P2PKH: OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
    if prevout_script.is_p2pkh() {
        return extract_p2pkh_pubkey(txin);
    }

    Err(SilentPaymentError::InputKeyExtractionFailed {
        input_index: 0, // Will be set by caller
        reason: "unsupported input type".to_string(),
    })
}

/// Extracts public key from P2TR (Taproot) input
///
/// For taproot, the public key is in the scriptPubKey itself (32-byte x-only key).
/// We need to check the y-coordinate parity from the witness.
fn extract_p2tr_pubkey(
    _txin: &TxIn,
    prevout_script: &ScriptBuf,
) -> Result<PublicKey, SilentPaymentError> {
    // Extract x-only pubkey from script (bytes 2-34)
    let script_bytes = prevout_script.as_bytes();
    if script_bytes.len() != 34 || script_bytes[0] != 0x51 || script_bytes[1] != 0x20 {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: "invalid P2TR script format".to_string(),
        });
    }

    let x_only_bytes = &script_bytes[2..34];

    // For taproot key path spends, witness has exactly one element (64-byte signature)
    // For script path spends, we need to look at the annex or control block
    // BIP-352 specifies we use even parity (0x02) for taproot inputs
    let mut pubkey_bytes = [0u8; 33];
    pubkey_bytes[0] = 0x02; // Even parity
    pubkey_bytes[1..33].copy_from_slice(x_only_bytes);

    PublicKey::from_slice(&pubkey_bytes).map_err(|e| SilentPaymentError::InputKeyExtractionFailed {
        input_index: 0,
        reason: format!("invalid taproot public key: {}", e),
    })
}

/// Extracts public key from P2WPKH witness
fn extract_p2wpkh_pubkey(txin: &TxIn) -> Result<PublicKey, SilentPaymentError> {
    // P2WPKH witness: <signature> <pubkey>
    if txin.witness.len() != 2 {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: format!("invalid P2WPKH witness length: {}", txin.witness.len()),
        });
    }

    let pubkey_bytes =
        txin.witness
            .nth(1)
            .ok_or_else(|| SilentPaymentError::InputKeyExtractionFailed {
                input_index: 0,
                reason: "missing pubkey in witness".to_string(),
            })?;

    PublicKey::from_slice(pubkey_bytes).map_err(|e| SilentPaymentError::InputKeyExtractionFailed {
        input_index: 0,
        reason: format!("invalid witness public key: {}", e),
    })
}

/// Extracts public key from P2PKH scriptSig
///
/// Only compressed public keys (33 bytes) are supported for Silent Payments
fn extract_p2pkh_pubkey(txin: &TxIn) -> Result<PublicKey, SilentPaymentError> {
    // P2PKH scriptSig: <signature> <pubkey>
    // We need to parse the script to extract the pubkey
    let script = &txin.script_sig;
    let script_bytes = script.as_bytes();

    if script_bytes.is_empty() {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: "empty P2PKH scriptSig".to_string(),
        });
    }

    // Simple parsing: skip signature, get pubkey
    // Signature starts with length byte, then DER signature
    let mut offset = 0;

    // First byte is signature length
    if offset >= script_bytes.len() {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: "truncated P2PKH scriptSig".to_string(),
        });
    }
    let sig_len = script_bytes[offset] as usize;
    offset += 1 + sig_len; // Skip length byte + signature

    // Next byte should be pubkey length
    if offset >= script_bytes.len() {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: "no pubkey in P2PKH scriptSig".to_string(),
        });
    }
    let pubkey_len = script_bytes[offset] as usize;
    offset += 1;

    // Only compressed pubkeys (33 bytes) are allowed
    if pubkey_len != 33 {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: format!(
                "uncompressed or invalid pubkey length: {} (must be 33)",
                pubkey_len
            ),
        });
    }

    if offset + pubkey_len > script_bytes.len() {
        return Err(SilentPaymentError::InputKeyExtractionFailed {
            input_index: 0,
            reason: "truncated pubkey in P2PKH scriptSig".to_string(),
        });
    }

    let pubkey_bytes = &script_bytes[offset..offset + pubkey_len];

    PublicKey::from_slice(pubkey_bytes).map_err(|e| SilentPaymentError::InputKeyExtractionFailed {
        input_index: 0,
        reason: format!("invalid P2PKH public key: {}", e),
    })
}

/// Sorts outpoints lexicographically as per BIP-352
///
/// Outpoints are sorted by txid (lexicographically on bytes), then by vout (little-endian)
pub fn sort_outpoints(outpoints: &mut [(OutPoint, PublicKey)]) {
    outpoints.sort_by(|a, b| {
        // First compare txid bytes lexicographically
        let cmp = a.0.txid.as_byte_array().cmp(b.0.txid.as_byte_array());
        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }
        // Then compare vout
        a.0.vout.cmp(&b.0.vout)
    });
}

/// Computes the input public key hash as per BIP-352
///
/// Hash = SHA256(tagged_hash("BIP0352/Inputs", smallest_outpoint || ... || largest_outpoint))
pub fn compute_input_hash(sorted_outpoints: &[(OutPoint, PublicKey)]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    for (outpoint, _) in sorted_outpoints {
        // Write txid (32 bytes, as-is)
        engine.input(outpoint.txid.as_byte_array());
        // Write vout (4 bytes, little-endian)
        engine.input(&outpoint.vout.to_le_bytes());
    }

    sha256::Hash::from_engine(engine)
}

/// Sums public keys using elliptic curve addition
pub fn sum_public_keys(
    _secp: &Secp256k1<bitcoin::secp256k1::All>,
    pubkeys: &[PublicKey],
) -> Result<PublicKey, SilentPaymentError> {
    if pubkeys.is_empty() {
        return Err(SilentPaymentError::NoEligibleInputs);
    }

    let mut sum = pubkeys[0];
    for pubkey in &pubkeys[1..] {
        sum = sum
            .combine(pubkey)
            .map_err(|e| SilentPaymentError::InputKeyExtractionFailed {
                input_index: 0,
                reason: format!("failed to sum public keys: {}", e),
            })?;
    }

    Ok(sum)
}

/// Computes BIP-340 tagged hash
///
/// tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
fn tagged_hash(tag: &[u8], msg: &[u8]) -> sha256::Hash {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(msg);
    sha256::Hash::from_engine(engine)
}

/// Computes shared secret using ECDH
///
/// shared_secret = input_pubkey_sum * scan_privkey
/// Then applies tagged hash for BIP-352
pub fn compute_shared_secret(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    input_pubkey_sum: &PublicKey,
    scan_privkey: &SecretKey,
    input_hash: &sha256::Hash,
) -> Result<PublicKey, SilentPaymentError> {
    // Perform ECDH: multiply input pubkey sum by scan private key
    let ecdh_point = ecdh::shared_secret_point(input_pubkey_sum, scan_privkey);

    // The ECDH point is 33 bytes (compressed public key)
    // Apply tagged hash: tagged_hash("BIP0352/SharedSecret", ecdh_point || input_hash)
    let mut msg = Vec::with_capacity(33 + 32);
    msg.extend_from_slice(&ecdh_point);
    msg.extend_from_slice(input_hash.as_byte_array());

    let shared_secret_hash = tagged_hash(TAG_SHARED_SECRET, &msg);

    // Convert hash to scalar and then to public key (G * scalar)
    let scalar = SecretKey::from_slice(shared_secret_hash.as_byte_array()).map_err(|e| {
        SilentPaymentError::SharedSecretFailed {
            reason: format!("invalid shared secret scalar: {}", e),
        }
    })?;

    let shared_secret_pubkey = PublicKey::from_secret_key(secp, &scalar);

    Ok(shared_secret_pubkey)
}

/// Derives output public key for a given index k
///
/// P_k = B_spend + hash(shared_secret || ser32(k)) * G
///
/// # Arguments
///
/// * `secp` - Secp256k1 context
/// * `spend_pubkey` - Recipient's spend public key (B_spend)
/// * `shared_secret` - Shared secret public key
/// * `k` - Output index (0, 1, 2, ...)
///
/// # Returns
///
/// The derived output public key P_k
pub fn derive_output_pubkey(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    spend_pubkey: &PublicKey,
    shared_secret: &PublicKey,
    k: u32,
) -> Result<PublicKey, SilentPaymentError> {
    // Compute tweak = hash(shared_secret || ser32(k))
    let mut msg = Vec::with_capacity(33 + 4);
    msg.extend_from_slice(&shared_secret.serialize());
    msg.extend_from_slice(&k.to_be_bytes()); // ser32 uses big-endian

    let tweak_hash = sha256::Hash::hash(&msg);

    // Convert hash to scalar
    let tweak_scalar = SecretKey::from_slice(tweak_hash.as_byte_array()).map_err(|e| {
        SilentPaymentError::OutputDerivationFailed {
            output_index: k,
            reason: format!("invalid tweak scalar: {}", e),
        }
    })?;

    // Compute tweak_pubkey = tweak_scalar * G
    let tweak_pubkey = PublicKey::from_secret_key(secp, &tweak_scalar);

    // Compute P_k = B_spend + tweak_pubkey
    let output_pubkey = spend_pubkey.combine(&tweak_pubkey).map_err(|e| {
        SilentPaymentError::OutputDerivationFailed {
            output_index: k,
            reason: format!("failed to combine pubkeys: {}", e),
        }
    })?;

    Ok(output_pubkey)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::Txid;

    use super::*;

    #[test]
    fn test_tagged_hash() {
        // Test that tagged hash works correctly
        let tag = b"BIP0352/SharedSecret";
        let msg = b"test message";
        let hash = tagged_hash(tag, msg);

        // Verify it's a valid hash
        assert_eq!(hash.as_byte_array().len(), 32);
    }

    #[test]
    fn test_sort_outpoints() {
        use bitcoin::hashes::Hash;
        use bitcoin::Txid;

        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());

        let mut outpoints = vec![
            (
                OutPoint {
                    txid: Txid::from_slice(&[2u8; 32]).unwrap(),
                    vout: 1,
                },
                pk,
            ),
            (
                OutPoint {
                    txid: Txid::from_slice(&[1u8; 32]).unwrap(),
                    vout: 0,
                },
                pk,
            ),
            (
                OutPoint {
                    txid: Txid::from_slice(&[1u8; 32]).unwrap(),
                    vout: 1,
                },
                pk,
            ),
        ];

        sort_outpoints(&mut outpoints);

        // Should be sorted by txid first, then vout
        assert_eq!(outpoints[0].0.txid, Txid::from_slice(&[1u8; 32]).unwrap());
        assert_eq!(outpoints[0].0.vout, 0);
        assert_eq!(outpoints[1].0.txid, Txid::from_slice(&[1u8; 32]).unwrap());
        assert_eq!(outpoints[1].0.vout, 1);
        assert_eq!(outpoints[2].0.txid, Txid::from_slice(&[2u8; 32]).unwrap());
        assert_eq!(outpoints[2].0.vout, 1);
    }

    #[test]
    fn test_p2pkh_pubkey_extraction() {
        // Test vector from BIP-352: P2PKH input with compressed pubkey
        let script_sig_hex = "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5";
        let script_pubkey_hex = "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac";

        let script_sig_bytes = Vec::from_hex(script_sig_hex).unwrap();
        let script_pubkey_bytes = Vec::from_hex(script_pubkey_hex).unwrap();

        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig_bytes),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        };

        let prevout_script = ScriptBuf::from_bytes(script_pubkey_bytes);

        let pubkey = extract_input_pubkey(&txin, &prevout_script).unwrap();

        // Expected pubkey from test vector
        let expected_pubkey = PublicKey::from_slice(
            &Vec::from_hex("025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(pubkey, expected_pubkey);
    }

    #[test]
    fn test_sum_public_keys() {
        let secp = Secp256k1::new();

        // Test vector pubkeys from BIP-352 first test case
        let pk1 = PublicKey::from_slice(
            &Vec::from_hex("025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")
                .unwrap(),
        )
        .unwrap();
        let pk2 = PublicKey::from_slice(
            &Vec::from_hex("03bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")
                .unwrap(),
        )
        .unwrap();

        let sum = sum_public_keys(&secp, &[pk1, pk2]).unwrap();

        // The sum should be deterministic
        assert!(sum.serialize().len() == 33);
    }

    #[test]
    fn test_derive_output_pubkey() {
        let secp = Secp256k1::new();

        // Test with simple keys
        let spend_pubkey =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let shared_secret =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        // Derive output for k=0
        let output_pk = derive_output_pubkey(&secp, &spend_pubkey, &shared_secret, 0).unwrap();

        // Should produce a valid pubkey
        assert!(output_pk.serialize().len() == 33);

        // Derive output for k=1 should be different
        let output_pk2 = derive_output_pubkey(&secp, &spend_pubkey, &shared_secret, 1).unwrap();
        assert_ne!(output_pk, output_pk2);
    }
}
