# Implementation Attacks

This directory contains research and code related to attacks we performed to break the commissioning scheme of Matter.

## Files & directories Overview

### 1. **spake2p**
This directory contains TypeScript code, forked from the official [Matter.js repository](https://github.com/project-chip/matter.js/), for conducting pre-computation and brute force attacks specifically targeting Matter's SPAKE2+ protocol. This code also allows for simulating a full PASE session between two devices. The code has been adjusted to remove some Matter-specific dependencies, allowing for a simplified simulation of a PASE session.

Requires Node.js 18 or newer (`brew install node` on macOS, or the NodeSource package on Linux). In the main `spake2p` directory:

```bash
npm install
```

The important code is in the directory `session/pase`:
- **pairingTest.ts**: A TypeScript test file that can be run by executing the command `npx ts-node pairingTest.ts` in a terminal (in the same directory as the file). It simulates the pairing between two devices.
- **bruteForceAttack.ts**: Contains code for performing a brute force attack on Matter's PASE protocol. Can be run with `npx ts-node bruteForceAttack.ts` in a terminal (in the same directory as the file).
- **preComputationTableBuilder.ts**: This file contains the logic for building the table required for the pre-computation attack. Can be run with `npx ts-node preComputationTableBuilder.ts` in a terminal (in the same directory as the file).
- **preComputationAttack.ts**: The main script for executing the pre-computation attack. The salt value in this script is set to 'public' for testing purposes. Can be run with `npx ts-node preComputationAttack.ts` in a terminal (in the same directory as the file).

### 2. **chip-tool**
The `chip-tool` is a command-line tool used for commissioning Matter devices, meaning it helps securely add new devices to a Matter network. It facilitates the pairing and configuration process.

### Building chip-tool and chip-lighting-app

The attacks in `chip-attacks` need both binaries from the official SDK.

**macOS**

```bash
brew install openssl pkg-config ninja python@3.11
git clone --depth=1 https://github.com/project-chip/connectedhomeip.git
cd connectedhomeip
./scripts/checkout_submodules.py --shallow --platform darwin
source scripts/activate.sh
cd examples/chip-tool && gn gen out/debug && ninja -C out/debug
cd ../lighting-app/linux && gn gen out/debug && ninja -C out/debug
```

**Linux (Debian/Ubuntu)**

```bash
sudo apt update && sudo apt install -y git gcc g++ pkg-config libssl-dev \
  libdbus-1-dev libglib2.0-dev libavahi-client-dev ninja-build \
  python3-venv python3-dev python3-pip unzip libgirepository1.0-dev \
  libcairo2-dev libreadline-dev
git clone --depth=1 https://github.com/project-chip/connectedhomeip.git
cd connectedhomeip
./scripts/checkout_submodules.py --shallow --platform linux
source scripts/activate.sh
cd examples/chip-tool && gn gen out/debug && ninja -C out/debug
cd ../lighting-app/linux && gn gen out/debug && ninja -C out/debug
```

The binaries land in `examples/chip-tool/out/debug/chip-tool` and `examples/lighting-app/linux/out/debug/chip-lighting-app`.

To run `chip-tool` on its own:

```bash
./chip-tool
```

For more detailed instructions and examples on how to use the `chip-tool`, you can refer to the official guide [here](https://project-chip.github.io/connectedhomeip-doc/development_controllers/chip-tool/chip_tool_guide.html), or a more simplified guide by Nordic Seminconductors guide [here](https://docs.nordicsemi.com/bundle/ncs-latest/page/matter/chip_tool_guide.html). The build steps above produce the `chip-tool` and `chip-lighting-app` binaries that the brute-force scripts in `chip-attacks` invoke to run repeated commissioning attempts. Alternatively, you can also build the entire Matter controller framework from the SDK, by following the steps mentioned [here](https://project-chip.github.io/connectedhomeip-doc/guides/BUILDING.html).
### 3. **chip-attacks**
This directory contains Python scripts for performing brute force attacks on Matter's commissioning process. The scripts simulate multiple commissioning attempts using incorrect passcodes to test the robustness of the commissioning scheme.

#### Files:
- **BruteForceAttack.py**: A script that performs brute force attacks by simulating multiple commissioning attempts. It includes logic for restarting the device and handling errors during the attack process.

**Set these two paths before running.** The script reads them from the environment and exits if either is unset:

```bash
export CHIP_TOOL_BUILD_DIR=<dir containing the chip-tool binary>
export LIGHTING_APP_BUILD_DIR=<dir containing the chip-lighting-app binary>
python3 BruteForceAttack.py
```