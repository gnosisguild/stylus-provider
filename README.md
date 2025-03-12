# Stylus-Based Enclave Compute Provider

This repository contains the implementation of a Stylus-based Compute Provider for encrypted execution environments, designed to securely process votes using Fully Homomorphic Encryption (FHE) directly on-chain. This compute provider leverages Arbitrum Stylus to perform on-chain computations efficiently while ensuring data privacy and integrity.

## Running Tests

Run the unit and integration tests to verify the FHE computation functionality:

```bash
# Run all tests
cargo test
```

### Local Execution

You can run the FHE computation locally without connecting to an RPC endpoint:

```bash
# Set environment variable to run locally
export RUN_LOCAL=true

# Run the example
cargo run --example stylus_provider
```

### RPC Execution

To run the computation via RPC against a deployed contract:

```bash
# Create a .env file with your configuration
cp .env.example .env
# Edit .env with your private key, RPC URL, and contract address

# Run the example
RUN_LOCAL=false cargo run --example stylus_provider
```


### Project Structure

- `src/lib.rs` - Main library and contract implementation
- `src/processor.rs` - FHE computation logic
- `src/merkle.rs` - Merkle tree implementation for verification
- `examples/stylus_provider.rs` - Example client for interacting with the contract
- `tests/integration_test.rs` - Integration tests

### Adding New FHE Operations

To add new FHE operations, modify the `fhe_processor` function in `src/processor.rs`. The current implementation performs a simple summation of all ciphertexts.
