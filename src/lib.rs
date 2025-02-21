// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
extern crate alloc;

mod processor;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::prelude::*;
use bincode;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FHEInputs {
    pub ciphertexts: Vec<(Vec<u8>, u64)>,
    pub params: Vec<u8>,
}

// Define some persistent storage using the Solidity ABI.
// `StylusProvider` will be the entrypoint.
sol_storage! {
    #[entrypoint]
    pub struct StylusProvider{}
}

/// Declare that `StylusProvider` is a contract with the following external methods.
#[public]
impl StylusProvider {
    pub fn run_compute(&self, input: Vec<u8>) -> Vec<u8> {
        let deserialized: FHEInputs = bincode::deserialize(&input).unwrap();
        processor::fhe_processor(&deserialized)
    }
}
