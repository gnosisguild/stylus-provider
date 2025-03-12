//! FHE Compute Contract for Arbitrum Stylus
//!
//! This library implements a Fully Homomorphic Encryption (FHE) computation service
//! on Arbitrum Stylus. It provides functionality for processing encrypted data
//! without revealing the underlying plaintext.

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
extern crate alloc;

mod merkle;
pub mod processor;

pub use processor::FHEInputs;

use alloc::vec::Vec;
use bincode;
use merkle::MerkleTree;
use sha3::{Digest, Keccak256};
use stylus_sdk::prelude::*;

/// Result of the FHE computation
///
/// Contains cryptographic proofs and results of the computation.
type ComputeResult = (Vec<u8>, Vec<u8>, Vec<u8>);

// Define persistent storage using the Solidity ABI
sol_storage! {
    #[entrypoint]
    pub struct StylusProvider {}
}

/// Implementation of the StylusProvider contract
#[public]
impl StylusProvider {
    /// Executes FHE computation on encrypted data
    ///
    /// # Arguments
    ///
    /// * `input` - Serialized FHEInputs structure
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * The computation result
    /// * Hash of the parameters
    /// * Merkle root for verification
    pub fn run_compute(&self, input: Vec<u8>) -> ComputeResult {
        // Deserialize the input
        let deserialized: FHEInputs = bincode::deserialize(&input)
            .expect("Failed to deserialize input");
        
        // Build Merkle tree for verification
        let mut tree = MerkleTree::new();
        tree.compute_leaf_hashes(&deserialized.ciphertexts);
        let root = tree.build_tree().root()
            .expect("Failed to compute Merkle root");
        
        // Compute parameter hash
        let params_hash = Keccak256::digest(&deserialized.params).to_vec();
        
        // Process the FHE computation
        // let result = processor::fhe_processor(&deserialized);
        
        // (result, params_hash, hex::decode(root).expect("Failed to decode root hex"))
        (vec![], params_hash, hex::decode(root).expect("Failed to decode root hex"))
    }
}

/// Exports the ABI for the contract
#[cfg(feature = "export-abi")]
pub fn export_abi(license: &str, solidity_version: &str) {
    stylus_sdk::export_abi(license, solidity_version);
}
