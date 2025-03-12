//! Stylus FHE Compute Contract
//! 
//! This is the main entry point for the Stylus FHE computation contract.
//! The contract provides a way to perform homomorphic encryption operations
//! on the Arbitrum Stylus platform.

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]

/// No-op main function for the contract when not in test or export-abi mode
#[cfg(not(any(test, feature = "export-abi")))]
#[no_mangle]
pub extern "C" fn main() {}

/// Exports the ABI when the "export-abi" feature is enabled
#[cfg(feature = "export-abi")]
fn main() {
    // Generate and print the Solidity ABI with license and pragma information
    stylus_provider::export_abi("MIT-OR-APACHE-2.0", "pragma solidity ^0.8.23;");
}
