# Pre-Computation Benchmarks

This folder contains benchmarking tools and scripts for evaluating the performance of pre-computation attacks on Matter's SPAKE2+ protocol. The benchmarks focus on key derivation, table generation, and lookup efficiency using PBKDF2 and Argon2id hashing algorithms.

## Folder Structure

- **lookup/**: Contains the `LookupBenchmark.ts` script, which benchmarks the lookup performance of pre-computed `w0` values in a CSV table.
- **tableGeneration/**: Contains Rust-based benchmarks for generating and filling tables with hashed passcodes using PBKDF2 and Argon2id algorithms.
  - **benches/**: Includes benchmarking scripts for Criterion-based performance evaluation.
  - **src/**: Contains the main implementation of table generation and hashing logic.
  - **Cargo.toml**: Rust project manifest file for managing dependencies.

## How to Use

### Lookup Benchmark
1. Navigate to the `lookup/` directory.
2. Run the `LookupBenchmark.ts` script using:
   ```bash
   npx ts-node LookupBenchmark.ts
   ```


### Table Generation Benchmark
1. Navigate to the `tableGeneration/` directory.
2. Run the Rust benchmarks using
   ```bash
   cargo bench
   ```