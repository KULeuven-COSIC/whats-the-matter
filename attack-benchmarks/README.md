# Attack Benchmarks

This folder contains benchmarking tools and scripts for evaluating the performance of the brute-force and pre-computation attacks on Matter's protocols.

## Folder Structure

- **bruteForce/**: Contains Python script for brute-force attacks on the CHIP-tool.
- **preComputation/**: Contains tools for benchmarking pre-computation attacks.
  - **lookup/**: Benchmarks the lookup performance of pre-computed `w0` values in a CSV table.
  - **tableGeneration/**: Includes Rust-based benchmarks for generating and filling tables with derived passcodes using PBKDF2 and Argon2id algorithms.

For detailed instructions on how to run the benchmarks, refer to the README files in the corresponding subfolders.