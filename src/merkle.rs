//! Merkle Tree Implementation
//!
//! This module provides a Merkle tree implementation for cryptographic verification
//! of FHE computation results. It uses Poseidon2 hash functions for efficient
//! zero-knowledge proof compatibility.

use lean_imt::LeanIMT;
use openzeppelin_crypto::arithmetic::uint::{from_str_hex, from_str_radix};
use openzeppelin_crypto::field::instance::FpBN256;
use openzeppelin_crypto::poseidon2::{Poseidon2, instance::bn256::BN256Params};
use sha3::{Digest, Keccak256};

/// Merkle tree implementation for FHE computation verification
///
/// This structure manages the creation and verification of a Merkle tree
/// for cryptographic proofs of computation integrity.
pub struct MerkleTree {
    /// Hashes of the leaf nodes in the Merkle tree
    pub leaf_hashes: Vec<String>,
}

impl MerkleTree {
    /// Creates a new empty Merkle tree
    pub fn new() -> Self {
        Self { leaf_hashes: vec![] }
    }

    /// Computes leaf hashes for the Merkle tree
    ///
    /// The process involves:
    /// 1. Computing Keccak-256 hash of each ciphertext
    /// 2. Converting the Keccak hash (hex) & index (decimal) to BN256 field elements
    /// 3. Applying Poseidon2 hash function and storing the result as hex
    ///
    /// # Arguments
    ///
    /// * `data` - Vector of (ciphertext, index) pairs
    pub fn compute_leaf_hashes(&mut self, data: &[(Vec<u8>, u64)]) {
        for (ciphertext, idx) in data {
            // 1) Compute Keccak256 hash of the ciphertext
            let keccak_hex = hex::encode(Keccak256::digest(ciphertext));

            // 2a) Convert the Keccak hash (hex) to BN256 field element
            let keccak_uint = from_str_hex(&keccak_hex);
            let keccak_field = FpBN256::new(keccak_uint);

            // 2b) Convert the index (decimal) to BN256 field element
            let index_str = idx.to_string();                   
            let index_uint = from_str_radix(&index_str, 10);
            let index_field = FpBN256::new(index_uint);

            // 3) Apply Poseidon2 hash and store as hex
            let mut poseidon = Poseidon2::<BN256Params, _>::new();
            poseidon.absorb(&keccak_field);
            poseidon.absorb(&index_field);

            let hash_result = poseidon.squeeze();
            let hash_hex = hash_result.to_string();

            self.leaf_hashes.push(hash_hex);
        }
    }

    /// Hash function for internal nodes of the Merkle tree
    ///
    /// Uses Poseidon2 hash function for efficient ZK-proof compatibility
    ///
    /// # Arguments
    ///
    /// * `nodes` - Vector of hex-encoded node values to hash
    ///
    /// # Returns
    ///
    /// Hex-encoded hash result
    fn poseidon_hash(nodes: Vec<String>) -> String {
        let mut poseidon = Poseidon2::<BN256Params, _>::new();

        // Process each node (hex-encoded BN256 field element)
        for node_hex in nodes {
            let uint_val = from_str_hex(&node_hex);
            let field_val = FpBN256::new(uint_val);
            poseidon.absorb(&field_val);
        }

        // Return the hash result as a hex string
        let hash_result = poseidon.squeeze();
        hash_result.to_string()
    }

    /// Builds the Merkle tree from the computed leaf hashes
    ///
    /// # Returns
    ///
    /// A LeanIMT (Incremental Merkle Tree) instance
    pub fn build_tree(&self) -> LeanIMT {
        let mut tree = LeanIMT::new(Self::poseidon_hash);
        tree.insert_many(self.leaf_hashes.clone())
            .expect("Failed to insert leaves into Merkle tree");
        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the Merkle tree construction and root calculation
    #[test]
    fn test_merkle_tree() {
        // Sample test data
        let data = vec![
            (b"ciphertext_1".to_vec(), 0),
            (b"ciphertext_2".to_vec(), 1),
            (b"ciphertext_3".to_vec(), 2),
        ];

        // Create and populate the Merkle tree
        let mut tree_handler = MerkleTree::new();
        tree_handler.compute_leaf_hashes(&data);
        let tree = tree_handler.build_tree();

        // Verify that a root was computed
        let root = tree.root().expect("Failed to compute Merkle root");
        println!("Root: 0x{}", root);
        
        // The test passes if execution reaches this point without panicking
        assert!(!root.is_empty(), "Root should not be empty");
    }
}