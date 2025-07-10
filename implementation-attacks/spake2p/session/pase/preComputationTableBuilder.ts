import { createWriteStream } from 'fs';
import { PaseServer } from './PaseServer';
import { PbkdfParameters, Spake2p } from "../../crypto/Spake2p";
import { ByteArray } from "../../util/ByteArray";
import { Crypto } from "../../crypto/Crypto";
import { CryptoNode } from "../../crypto/CryptoNode";

// initializing the cryptographic provider
const TheCrypto = new CryptoNode();
Crypto.get = () => TheCrypto;

// function to ask the server for PBKDF parameters
async function getPBKDFParametersFromServer(server: PaseServer): Promise<PbkdfParameters> {
    return server.getPBKDFParameters();
}

// function to generate w0 and w1 for a given passcode
async function generateW0W1(passcode: number, pbkdfParameters: PbkdfParameters) {
    const { w0, w1 } = await Spake2p.computeW0W1(pbkdfParameters, passcode);
    return { w0, w1 };
}

// main function to generate the pre-computed table file
async function generateCSV() {

    const server = new PaseServer(0, { iterations: 1000, salt: ByteArray.fromString('asalt') });


    // receiving PBKDF parameters from server
    const pbkdfParameters = await getPBKDFParametersFromServer(server);

    // creating a write stream for the CSV file
    const fileStream = createWriteStream('table.csv');
    fileStream.write('passcode,w0,w1\n'); // writing header

    // iterating over all possible passcodes (even the forbidden ones, just to keep the code simple)
    for (let passcode = 1; passcode <= 99999998; passcode++) {
        const { w0, w1 } = await generateW0W1(passcode, pbkdfParameters);
        // writing passcode, w0, and w1 to the CSV file
        fileStream.write(`${passcode},${w0.toString()},${w1.toString()}\n`);
    }

    fileStream.end(); // closing the file stream
    console.log('CSV file generation completed.');
}

// running the main function
generateCSV();
