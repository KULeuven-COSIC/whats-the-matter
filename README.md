# What's the Matter? An In-Depth Security Analysis of the Matter Protocol

> **Abstract**  The Matter protocol has emerged as a leading standard for secure IoT
  interoperability, backed by major vendors such as Apple, Google, Amazon, 
  Samsung, and others. With millions of Matter-certified devices already 
  deployed, its security assurances are critical to the safety of global 
  IoT ecosystems. This paper presents the first in-depth security evaluation 
  and formal verification of Matter’s core protocols, focusing on its 
  Passcode-Authenticated Session Establishment (PASE) and 
  Certificate-Authenticated Session Establishment (CASE) mechanisms. 
  While these are based on the well-studied SPAKE2+ and
  SIGMA respectively, Matter introduces modifications that 
  compromise the original security guarantees.
  Our analysis reveals multiple cryptographic design flaws, including 
  low-entropy passcodes, static salts, and weak PBKDF2 parameters -- all of which contradict Matter’s own threat model and stated security goals. We highlight cases where Matter delegates critical 
  security decisions to vendors, rather than enforcing robust cryptographic 
  practices in the specification, thereby making the system more fragile 
  and susceptible to exploitation. 
  We formally model both standard and Matter-adapted variants of these 
  protocols in ProVerif, confirming several of Matter’s security goals, 
  but disproving others. Our findings go as far as rendering some of Matter's 
  own mitigations insufficient, exposing *all* Matter-certified devices 
  to threats classified as *``High Risk”* in their own documentation. 
  As part of our study, we also discovered previously unknown vulnerabilities 
  in Matter’s public codebase, which we responsibly disclosed to the 
  developers, leading to updates in the codebase.

This repository contains the code and resources which supplement our work on the security analysis and evaluation of the Matter Protocol. Below is an overview of the repository contents and structure.

## Repository Structure

The repository contains three main directories: `attack-benchmarks`, `formal-models` and `implementation-attacks`, each with code relevant to its section and an accompanying README file explaining its contents and usage. Additionally, we have provided the specification documents used in our evaluation — `Matter-1.3-Core-Specification.pdf` and `Matter-1.4-Core-Specification.pdf`.

### Directory Tree

The contents of this repository are as follows:
```bash
├── attack-benchmarks
│   ├── README.md
│   ├── bruteForce
│   │   ├── BruteForceAttackWithBenchmarks.py
│   │   └── README.md
│   ├── preComputation
│   │   ├── lookup
│   │   │   ├── LookupBenchmark.ts
│   │   │   ├── snippet.csv
│   │   │   └── README.md
│   │   ├── tableGeneration
│   │   │   ├── benches
│   │   │   │   └── bench.rs
│   │   │   ├── src
│   │   │   │   ├── lib.rs
│   │   │   │   └── main.rs
│   │   │   ├── Cargo.toml
│   │   │   └── README.md
│   │   └── README.md
├── formal-models
│   ├── proverif
│   │   ├── case-resumption.pv
│   │   ├── case-resumption.pv.out
│   │   ├── case.pv
│   │   ├── case.pv.out
│   │   ├── pase.pv
│   │   ├── pase.pv.out
│   │   ├── sigma.pv
│   │   ├── sigma.pv.out
│   │   ├── spake2p.pv
│   │   └── spake2p.pv.out
│   └── README.md
├── implementation-attacks
│   ├── README.md
│   ├── chip-attacks
│   │   ├── BruteForceAttack.py
│   ├── chip-tool
│   └── spake2p
│       ├── Spake2pTest.test.ts
│       ├── codec
│       │   ├── Base64Codec.ts
│       │   ├── DerCodec.ts
│       │   └── export.ts
│       ├── crypto
│       │   ├── Crypto.ts
│       │   ├── CryptoConstants.ts
│       │   ├── CryptoNode.ts
│       │   ├── Key.ts
│       │   ├── Spake2p.ts
│       │   └── export.ts
│       ├── package-lock.json
│       ├── package.json
│       ├── session
│       │   ├── export.ts
│       │   └── pase
│       │       ├── PaseClient.ts
│       │       ├── PaseServer.ts
│       │       ├── bruteForceAttack.ts
│       │       ├── forbiddenPasscodes.ts
│       │       ├── pairingTest.ts
│       │       ├── preComputationAttack.ts
│       │       └── preComputationTableBuilder.ts
│       ├── test.config.ts
│       ├── tsconfig.json
│       └── util
│           ├── ByteArray.ts
│           ├── DataReader.ts
│           ├── DataWriter.ts
│           ├── Number.ts
│           ├── Type.ts
│           └── export.ts
├── Matter-1.3-Core-Specification.pdf
├── Matter-1.4-Core-Specification.pdf
└── README.md
```

## Getting Started

1. **attack-benchmarks**: This directory contains benchmarking tools and scripts for evaluating the performance of brute-force and pre-computation attacks on Matter's protocols. See the `README.md` within this directory for detailed instructions on usage and setup.

2. **implementation-attacks**: This directory contains scripts to simulate various attacks on the Matter protocol. See the `README.md` within this directory for detailed instructions on usage and setup.
   
3. **formal-models**: This directory includes ProVerif files for the formal verification of the PASE, CASE, and SPAKE protocols. Refer to the `README.md` in this directory for more information.

## Specifications

- `Matter-1.3-Core-Specification.pdf`: The core Matter specification (v1.3).
- `Matter-1.4-Core-Specification.pdf`: The latest version of the specification (v1.4).

## How to Use

Each directory’s `README.md` file provides specific instructions on running and understanding the tools included in that section. For any additional questions, please refer to the main documentation within each directory.
