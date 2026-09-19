# Attack Benchmarks

Cost measurements supporting the attacks in [`../implementation-attacks`](../implementation-attacks): pre-computation and lookup cost (Table 2 and Sect. 7.1 of the paper) and the timing of online commissioning attempts (Sect. 6).

## Folder Structure

- **preComputation/tableGeneration/**: Rust benchmarks for deriving passcodes with PBKDF2.
- **preComputation/lookup/**: `LookupBenchmark.ts`, which times a scan for a `w0` value in a pre-computed table. `snippet.csv` is a sample of a generated table, so the benchmark runs without building the full one.
- **bruteForce/**: `BruteForceAttackWithBenchmarks.py`, which simulates repeated commissioning attempts with incorrect passcodes through the CHIP-tool and records restart times and attempt durations.

## Table Generation

Requires Rust. The crate uses edition 2024, so Rust 1.85 or newer. Same on macOS and Linux:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version     # 1.85 or newer
```

Run:

```bash
cd preComputation/tableGeneration
cargo bench
```

Criterion prints the mean time per derivation and writes reports to `target/criterion/`. The full table of Table 2 is not generated here: take the per-derivation mean, multiply by the 10^8 passcode space, and divide by the core count for the parallel figure.

## Lookup

Requires Node.js 18 or newer. The TypeScript dependencies come from the `spake2p` project, so install those first:

```bash
cd ../../implementation-attacks/spake2p && npm install
```

Run:

```bash
cd attack-benchmarks/preComputation/lookup
npx ts-node LookupBenchmark.ts
```

## Brute Force

Build `chip-tool` and `chip-lighting-app` first, as described in [`../implementation-attacks/README.md`](../implementation-attacks/README.md).

Then set the two paths. The script reads them from the environment and exits if either is unset:

```bash
export CHIP_TOOL_BUILD_DIR=<dir containing the chip-tool binary>
export LIGHTING_APP_BUILD_DIR=<dir containing the chip-lighting-app binary>
```

Run:

```bash
cd bruteForce
python3 BruteForceAttackWithBenchmarks.py
```
