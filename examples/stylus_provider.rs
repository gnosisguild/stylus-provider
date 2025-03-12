use ethers::{
    middleware::SignerMiddleware,
    prelude::abigen,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, Bytes},
};
use dotenv::dotenv;
use eyre::eyre;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::sync::Arc;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{Deserialize, DeserializeParametrized, FheEncoder, FheDecoder, FheEncrypter, FheDecrypter, Serialize};
use bincode;
use rand::thread_rng;
use ::stylus_provider::FHEInputs;
use ::stylus_provider::processor::fhe_processor;

fn generate_inputs() -> (Vec<(Vec<u8>, u64)>, Vec<u8>) {
    let params = create_params();
    let (sk, pk) = generate_keys(&params);
    let inputs = vec![1, 1, 0];
    let incs: Vec<(Vec<u8>, u64)> = encrypt_inputs(&inputs, &pk, &params)
        .iter()
        .map(|c| (c.to_bytes(), 1))
        .collect();

    println!("Generated {} encrypted inputs", incs.len());
    println!("Expected sum: {}", inputs.iter().sum::<u64>());
    
    // Save secret key for later decryption
    let sk_bytes = bincode::serialize(&sk.coeffs).expect("Failed to serialize secret key");
    std::fs::write("secret_key.bin", &sk_bytes).expect("Failed to save secret key");
    println!("Secret key saved to secret_key.bin");

    (incs, params.to_bytes())
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
fn decrypt_result(result_bytes: &[u8], params_bytes: &[u8]) -> u64 {
    let params = Arc::new(
        BfvParameters::try_deserialize(params_bytes)
            .expect("Failed to deserialize parameters")
    );
    
    let sk_bytes = std::fs::read("secret_key.bin").expect("Failed to read secret key");
    let sk_decoded: Vec<i64> = bincode::deserialize(&sk_bytes).expect("Failed to deserialize secret key");
    let sk = SecretKey::new(sk_decoded, &params);
    
    let ciphertext = Ciphertext::from_bytes(result_bytes, &params)
        .expect("Failed to deserialize result ciphertext");
    
    let plaintext = sk.try_decrypt(&ciphertext).expect("Failed to decrypt result");
    let values = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).expect("Failed to decode result");
    
    values[0]
}

fn cleanup() {
    println!("Cleaning up temporary files...");
    if let Err(e) = std::fs::remove_file("secret_key.bin") {
        println!("Warning: Could not remove secret_key.bin: {}", e);
    }
    println!("Cleanup complete");
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();

    // Check if we should cleanup after run
    let cleanup_enabled = std::env::var("CLEANUP_AFTER_RUN")
        .unwrap_or_else(|_| "true".to_string()) == "true";
    
    // Generate FHE computation inputs
    let (ciphertexts, params) = generate_inputs();
    let fhe_inputs = FHEInputs {
        ciphertexts,
        params: params.clone(),
    };
    
    // Serialize inputs for the contract
    let serialized_input = bincode::serialize(&fhe_inputs).expect("Failed to serialize inputs");
    
    // Check if we should run locally or via RPC
    let run_local = std::env::var("RUN_LOCAL").unwrap_or_else(|_| "true".to_string());
    
    if run_local == "true" {
        println!("Running computation locally...");
        
        // Run the computation locally
        let result = fhe_processor(&fhe_inputs);
        
        // Decrypt and display the result
        let decrypted = decrypt_result(&result, &params);
        println!("Decrypted result: {}", decrypted);

        if cleanup_enabled {
            cleanup();
        }
        
        return Ok(());
    }
    
    // If not running locally, proceed with RPC call
    let priv_key_path = std::env::var("PRIV_KEY_PATH")
        .map_err(|_| eyre!("Missing PRIV_KEY_PATH in .env file"))?;
    let rpc_url = std::env::var("RPC_URL")
        .map_err(|_| eyre!("Missing RPC_URL in .env file"))?;
    let contract_address = std::env::var("STYLUS_CONTRACT_ADDRESS")
        .map_err(|_| eyre!("Missing STYLUS_CONTRACT_ADDRESS in .env file"))?;
    
    
    abigen!(
        StylusProvider,
        r#"[
            function run_compute(bytes calldata input) external view returns (bytes memory, bytes memory, bytes memory)
        ]"#
    );

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let address: Address = contract_address.parse()?;

    let privkey = read_secret_from_file(&priv_key_path)?;
    let wallet = LocalWallet::from_str(&privkey)?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    let contract = StylusProvider::new(address, client);
    
    println!("Sending computation request to contract...");
    let (result, params_hash, merkle_root) = contract
        .run_compute(Bytes::from(serialized_input))
        .call()
        .await?;
    
    println!("Computation completed!");
    println!("Result size: {} bytes", result.len());
    println!("Params hash: 0x{}", hex::encode(&params_hash));
    println!("Merkle root: 0x{}", hex::encode(&merkle_root));
    
    // Decrypt the result
    let decrypted = decrypt_result(&result, &params);
    println!("Decrypted result: {}", decrypted);

    if cleanup_enabled {
        cleanup();
    }
    
    Ok(())
}

fn read_secret_from_file(fpath: &str) -> eyre::Result<String> {
    let f = std::fs::File::open(fpath)?;
    let mut buf_reader = BufReader::new(f);
    let mut secret = String::new();
    buf_reader.read_line(&mut secret)?;
    Ok(secret.trim().to_string())
}
