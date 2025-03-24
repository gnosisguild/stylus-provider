use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner, sol,
};
use alloy_primitives::Bytes;
use alloy_sol_types::SolValue;
use dotenv::dotenv;
use eyre::eyre;
use std::sync::Arc;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{Deserialize, DeserializeParametrized, FheEncoder, FheDecoder, FheEncrypter, FheDecrypter, Serialize};
use rand::thread_rng;

fn generate_inputs() -> ((Vec<(Bytes, u64)>, Bytes), SecretKey) {
    let params = create_params();
    let (sk, pk) = generate_keys(&params);
    let inputs = vec![1, 1, 0];
    let incs: Vec<(Bytes, u64)> = encrypt_inputs(&inputs, &pk, &params)
        .iter()
        .map(|c| (Bytes::from(c.to_bytes()), 1))
        .collect();

    println!("Generated {} encrypted inputs", incs.len());
    println!("Expected sum: {}", inputs.iter().sum::<u64>());
    
    ((incs, Bytes::from(params.to_bytes())), sk)
}

/// Create BFV parameters for FHE
fn create_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(1024)
        .set_plaintext_modulus(65537)
        .set_moduli(&[1152921504606584833])
        .build_arc()
        .expect("Failed to build parameters")
}

/// Generate encryption keys
fn generate_keys(params: &Arc<BfvParameters>) -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    let sk = SecretKey::random(params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    (sk, pk)
}

/// Encrypt input values
fn encrypt_inputs(inputs: &[u64], pk: &PublicKey, params: &Arc<BfvParameters>) -> Vec<Ciphertext> {
    let mut rng = thread_rng();
    inputs
        .iter()
        .map(|&input| {
            let pt = Plaintext::try_encode(&[input], Encoding::poly(), params)
                .expect("Failed to encode plaintext");
            pk.try_encrypt(&pt, &mut rng).expect("Failed to encrypt")
        })
        .collect()
}

/// Decrypt a ciphertext using the saved secret key
fn decrypt_result(result_bytes: &[u8], params_bytes: &[u8], sk: &SecretKey) -> u64 {
    let params = Arc::new(
        BfvParameters::try_deserialize(params_bytes)
            .expect("Failed to deserialize parameters")
    );
    
    
    let ciphertext = Ciphertext::from_bytes(result_bytes, &params)
        .expect("Failed to deserialize result ciphertext");
    
    let plaintext = sk.try_decrypt(&ciphertext).expect("Failed to decrypt result");
    let values = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).expect("Failed to decode result");
    
    values[0]
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();
    // Generate FHE computation inputs
    let (fhe_inputs, sk) = generate_inputs();
    
    
    // If not running locally, proceed with RPC call
    let privkey = std::env::var("PRIV_KEY")
        .map_err(|_| eyre!("Missing PRIV_KEY in .env file"))?;
    let rpc_url = std::env::var("RPC_URL")
        .map_err(|_| eyre!("Missing RPC_URL in .env file"))?;
    let contract_address = std::env::var("STYLUS_CONTRACT_ADDRESS")
        .map_err(|_| eyre!("Missing STYLUS_CONTRACT_ADDRESS in .env file"))?;
    
    println!("Running computation via RPC...");
    println!("RPC URL: {}", rpc_url);
    println!("Contract address: {}", contract_address);
    println!("Private key: {}", privkey);
    
    sol! {
        #[derive(Debug)]
        #[sol(rpc)]
        contract StylusProvider {
            function runCompute(uint8[] memory input) external pure returns (uint8[] memory);
        }
    }

    let signer: PrivateKeySigner = privkey.parse()?;
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_builtin(&rpc_url)
        .await?;

    let contract = StylusProvider::new(contract_address.parse()?, provider);
    type FHEInputs = (Vec<(Bytes, u64)>, Bytes);
    let encoded_input = FHEInputs::abi_encode(&fhe_inputs);
    println!("Sending computation request to contract...");
    let result= contract
        .runCompute(encoded_input)
        .call()
        .await?._0;
    
    println!("Computation completed!");

    type FHEResult = (Bytes, Bytes, Bytes);
    let (result, params_hash, merkle_root) = FHEResult::abi_decode(&result, true).unwrap();
    println!("Result: {:?}", result);
    println!("Params hash: 0x{}", hex::encode(&params_hash));
    println!("Merkle root: 0x{}", hex::encode(&merkle_root));
    
    // Decrypt the result
    let decrypted = decrypt_result(&result, &fhe_inputs.1, &sk);
    println!("Decrypted result: {}", decrypted);
    
    Ok(())
}
