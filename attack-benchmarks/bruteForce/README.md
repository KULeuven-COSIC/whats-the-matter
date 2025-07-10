# Brute-Force Attack Benchmarks

This folder contains a Python script for performing brute-force attacks on Matter's commissioning process using the CHIP-tool.

## Files

- **BruteForceAttackWithBenchmarks.py**: Simulates multiple commissioning attempts with incorrect passcodes to evaluate the robustness of the protocol. The script also collects timing data for statistical analysis, such as restart times and attempt durations.

## Setup

Before running the script, make sure to update the following variables in the script with the correct paths:

- `CHIP_TOOL_BUILD_DIR`: Add the directory where the `chip-tool` executable is located.
- `LIGHTING_APP_BUILD_DIR`: Add the directory where the `lighting-app` executable is located.

## How to Run

Run the script using the following command:
   ```bash
   python3 BruteForceAttackWithBenchmarks.py