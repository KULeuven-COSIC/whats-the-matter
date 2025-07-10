# Implementation Attacks

This directory contains research and code related to attacks we performed to break the commissioning scheme of Matter.

## Files & directories Overview

### 1. **spake2p**
This directory contains TypeScript code, forked from the official [Matter.js repository](https://github.com/project-chip/matter.js/), for conducting pre-computation and brute force attacks specifically targeting Matter's SPAKE2+ protocol. This code also allows for simulating a full PASE session between two devices. The code has been adjusted to remove some Matter-specific dependencies, allowing for a simplified simulation of a PASE session.

To be able to run the project, it is important to execute the following command in the main `spake2p` directory: `npm install`.

The important code is in the directory `session/pase`:
- **pairingTest.ts**: A TypeScript test file that can be run by executing the command `npx ts-node pairingTest.ts` in a terminal (in the same directory as the file). It simulates the pairing between two devices.
- **bruteForceAttack.ts**: Contains code for performing a brute force attack on Matter's PASE protocol. Can be run with `npx ts-node bruteForceAttack.ts` in a terminal (in the same directory as the file).
- **preComputationTableBuilder.ts**: This file contains the logic for building the table required for the pre-computation attack. Can be run with `npx ts-node preComputationTableBuilder.ts` in a terminal (in the same directory as the file).
- **preComputationAttack.ts**: The main script for executing the pre-computation attack. The salt value in this script is set to 'public' for testing purposes. Can be run with `npx ts-node preComputationAttack.ts` in a terminal (in the same directory as the file).

### 2. **chip-tool**
The `chip-tool` is a command-line tool used for commissioning Matter devices, meaning it helps securely add new devices to a Matter network. It facilitates the pairing and configuration process.

To run the `chip-tool` for commissioning, you can use the following command:

```bash
./chip-tool
```

For more detailed instructions and examples on how to use the `chip-tool`, you can refer to the official guide [here](https://project-chip.github.io/connectedhomeip-doc/development_controllers/chip-tool/chip_tool_guide.html), or a more simplified guide by Nordic Seminconductors guide [here](https://docs.nordicsemi.com/bundle/ncs-latest/page/matter/chip_tool_guide.html). We provide this code as a standalone package to build and run our attacks. Alternatively, you can also build the entire Matter controller framework from the SDK, by following the steps mentioned [here](https://project-chip.github.io/connectedhomeip-doc/guides/BUILDING.html).
### 3. **chip-attacks**
This directory contains Python scripts for performing brute force attacks on Matter's commissioning process. The scripts simulate multiple commissioning attempts using incorrect passcodes to test the robustness of the commissioning scheme.

#### Files:
- **BruteForceAttack.py**: A script that performs brute force attacks by simulating multiple commissioning attempts. It includes logic for restarting the device and handling errors during the attack process.

Before running the script, you must specify the paths for the following directories:
- The directory where the `chip-tool` executable is located.
- The directory where the `chip-lighting-app` executable is located.

These paths are currently left empty in the code and need to be filled in before running the attacks. Make sure to update the `CHIP_TOOL_BUILD_DIR` and `LIGHTING_APP_BUILD_DIR` variables in the script with the correct paths to the respective executables.