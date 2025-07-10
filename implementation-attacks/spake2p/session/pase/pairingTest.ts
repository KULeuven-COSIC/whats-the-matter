import { PaseClient } from './PaseClient';
import { PaseServer } from './PaseServer';
import { PbkdfParameters } from "../../crypto/Spake2p";
import { ByteArray } from "../../util/ByteArray";

import { Crypto } from "../../crypto/Crypto";
import { CryptoNode } from "../../crypto/CryptoNode";

// initializing the cryptographic provider
const TheCrypto = new CryptoNode();
Crypto.get = () => TheCrypto;

async function testSpake2PlusPairing() {

    // initializing parameters
    const setupPin = 123456; // example PIN
    const pbkdfParameters: PbkdfParameters = {
        iterations: 1000,
        salt: new ByteArray([1, 2, 3, 4]), // example salt
    };

    // creating server and client objects
    const server = new PaseServer(setupPin, pbkdfParameters);
    const client = new PaseClient();

    // doing the pairing
    try {
        const sharedSecret = await client.initiatePairing(setupPin, pbkdfParameters, server);
        console.log('Shared Secret:', sharedSecret);
    } catch (error) {
        console.error('Pairing failed:', error);
    }
}

testSpake2PlusPairing();