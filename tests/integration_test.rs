use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder,FheDecoder, FheEncrypter, Serialize};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use std::sync::Arc;
use stylus_provider::FHEInputs;
use stylus_provider::processor::fhe_processor;

fn generate_test_inputs(values: &[u64]) -> (FHEInputs, Arc<BfvParameters>, SecretKey) {
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
    
    // Encrypt inputs
    let ciphertexts: Vec<(Vec<u8>, u64)> = values
        .iter()
        .enumerate()
        .map(|(idx, &val)| {
            let pt = Plaintext::try_encode(&[val], Encoding::poly(), &params)
                .expect("Failed to encode plaintext");
            let ct = pk.try_encrypt(&pt, &mut rng).expect("Failed to encrypt");
            (ct.to_bytes(), idx as u64)
        })
        .collect();
    
    // Create FHEInputs
    let fhe_inputs = FHEInputs {
        ciphertexts,
        params: params.to_bytes(),
    };
    
    (fhe_inputs, params, sk)
}

fn decrypt_result(result_bytes: &[u8], params: &Arc<BfvParameters>, sk: &SecretKey) -> u64 {
    let result_ct = Ciphertext::from_bytes(result_bytes, params)
        .expect("Failed to deserialize result");
    let result_pt = sk.try_decrypt(&result_ct).expect("Failed to decrypt result");
    let result_values: Vec<u64> = Vec::<u64>::try_decode(&result_pt, Encoding::poly())
        .expect("Failed to decode result");
    result_values[0]
}

#[test]
fn test_fhe_addition() {
    let values = vec![5, 10, 15];
    let expected_sum = values.iter().sum::<u64>();
    
    // Generate inputs
    let (fhe_inputs, params, sk) = generate_test_inputs(&values);
    
    // Process the inputs
    let result_bytes = fhe_processor(&fhe_inputs);
    
    // Decrypt and verify the result
    let result = decrypt_result(&result_bytes, &params, &sk);
    assert_eq!(result, expected_sum, "Expected sum {} but got {}", expected_sum, result);
}

#[test]
fn test_fhe_zero_values() {
    let values = vec![0, 0, 0];
    let expected_sum = 0;
    
    // Generate inputs
    let (fhe_inputs, params, sk) = generate_test_inputs(&values);
    
    // Process the inputs
    let result_bytes = fhe_processor(&fhe_inputs);
    
    // Decrypt and verify the result
    let result = decrypt_result(&result_bytes, &params, &sk);
    assert_eq!(result, expected_sum, "Expected sum {} but got {}", expected_sum, result);
}

#[test]
fn test_fhe_single_value() {
    let values = vec![42];
    let expected_sum = 42;
    
    // Generate inputs
    let (fhe_inputs, params, sk) = generate_test_inputs(&values);
    
    // Process the inputs
    let result_bytes = fhe_processor(&fhe_inputs);
    
    // Decrypt and verify the result
    let result = decrypt_result(&result_bytes, &params, &sk);
    assert_eq!(result, expected_sum, "Expected sum {} but got {}", expected_sum, result);
}
