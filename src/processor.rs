//! FHE Processor Module
//!
//! This module implements the core FHE (Fully Homomorphic Encryption) processing
//! functionality. It handles the actual computation on encrypted data.

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::Bytes;
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_traits::{Deserialize, DeserializeParametrized, Serialize};

/// Input structure for FHE computation
///
/// Contains the encrypted data (ciphertexts index) and parameters needed
/// for FHE operations.
pub type FHEInputs = (Vec<(Bytes, u64)>, Bytes);

/// Processes FHE ciphertexts according to the CRISP protocol
///
/// This function takes encrypted inputs and performs homomorphic operations
/// on them without decrypting the data.
///
/// # Arguments
///
/// * `fhe_inputs` - The FHE inputs containing ciphertexts and parameters
///
/// # Returns
///
/// A vector of bytes representing the encrypted result
pub fn fhe_processor(fhe_inputs: &FHEInputs) -> Vec<u8> {
    let params = Arc::new(
        BfvParameters::try_deserialize(&fhe_inputs.1)
            .expect("Failed to deserialize BFV parameters"),
    );

    // Initialize with a zero ciphertext
    let mut sum = Ciphertext::zero(&params);

    // Sum all ciphertexts
    for (ciphertext_bytes, _) in &fhe_inputs.0 {
        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes, &params)
            .expect("Failed to deserialize ciphertext");
        sum += &ciphertext;
    }

    // Return the serialized result
    sum.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StylusProvider;
    use alloy_sol_types::SolValue;
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    #[test]
    fn test_contract() {
        use stylus_sdk::testing::*;
        let vm = TestVM::default();
        let contract = StylusProvider::from(&vm);

        // Create parameters
        let params = BfvParametersBuilder::new()
            .set_degree(1024)
            .set_plaintext_modulus(65537)
            .set_moduli(&[1152921504606584833])
            .build_arc()
            .expect("Failed to build parameters");

        // Generate keys
        let mut rng: ThreadRng = thread_rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        // Create test inputs: [1, 2, 3]
        let inputs = vec![1u64, 2u64, 3u64];
        let expected_sum = inputs.iter().sum::<u64>();

        // Encrypt inputs
        let ciphertexts: Vec<(Bytes, u64)> = inputs
            .iter()
            .enumerate()
            .map(|(idx, &val)| {
                let pt = Plaintext::try_encode(&[val], Encoding::poly(), &params)
                    .expect("Failed to encode plaintext");
                let ct = pk.try_encrypt(&pt, &mut rng).expect("Failed to encrypt");
                (Bytes::from(ct.to_bytes()), idx as u64)
            })
            .collect();

        // Create FHEInputs
        let fhe_inputs = (ciphertexts, Bytes::from(params.to_bytes()));

        let encoded_input = FHEInputs::abi_encode(&fhe_inputs);

        // Process the inputs
        let result_compute = contract.run_compute(encoded_input);

        type FHEResult = (Bytes, Bytes, Bytes);
        let (result_bytes, _, _) =
            FHEResult::abi_decode(&result_compute, true).unwrap();

        // Decrypt the result
        let result_ct =
            Ciphertext::from_bytes(&result_bytes, &params).expect("Failed to deserialize result");
        let result_pt = sk
            .try_decrypt(&result_ct)
            .expect("Failed to decrypt result");
        let result_values: Vec<u64> =
            Vec::<u64>::try_decode(&result_pt, Encoding::poly()).expect("Failed to decode result");

        // Verify the result
        assert_eq!(
            result_values[0], expected_sum,
            "Expected sum {} but got {}",
            expected_sum, result_values[0]
        );
    }

    #[test]
    fn test_fhe_processor_addition() {
        // Create parameters
        let params = BfvParametersBuilder::new()
            .set_degree(1024)
            .set_plaintext_modulus(65537)
            .set_moduli(&[1152921504606584833])
            .build_arc()
            .expect("Failed to build parameters");

        // Generate keys
        let mut rng: ThreadRng = thread_rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        // Create test inputs: [1, 2, 3]
        let inputs = vec![1u64, 2u64, 3u64];
        let expected_sum = inputs.iter().sum::<u64>();

        // Encrypt inputs
        let ciphertexts: Vec<(Bytes, u64)> = inputs
            .iter()
            .enumerate()
            .map(|(idx, &val)| {
                let pt = Plaintext::try_encode(&[val], Encoding::poly(), &params)
                    .expect("Failed to encode plaintext");
                let ct = pk.try_encrypt(&pt, &mut rng).expect("Failed to encrypt");
                (Bytes::from(ct.to_bytes()), idx as u64)
            })
            .collect();

        // Create FHEInputs
        let fhe_inputs = (ciphertexts, Bytes::from(params.to_bytes()));

        // Process the inputs
        let result_bytes = fhe_processor(&fhe_inputs);

        // Decrypt the result
        let result_ct =
            Ciphertext::from_bytes(&result_bytes, &params).expect("Failed to deserialize result");
        let result_pt = sk
            .try_decrypt(&result_ct)
            .expect("Failed to decrypt result");
        let result_values: Vec<u64> =
            Vec::<u64>::try_decode(&result_pt, Encoding::poly()).expect("Failed to decode result");

        // Verify the result
        assert_eq!(
            result_values[0], expected_sum,
            "Expected sum {} but got {}",
            expected_sum, result_values[0]
        );
    }
}
