import { Crypto } from "../../crypto/Crypto";
import { PbkdfParameters, Spake2p } from "../../crypto/Spake2p";
import { ByteArray } from "../../util/ByteArray";
import { ec } from "../../crypto/Crypto";

const { bytesToNumberBE } = ec;

export class PaseServer {
    private spake2p: Spake2p;
    private w0: bigint;
    private L: ByteArray;
    private pbkdfParameters: PbkdfParameters;
    private initiatorRandom: ByteArray;
    private responderRandom: ByteArray;
    private Ke: ByteArray;
    private cA: ByteArray;

    constructor(setupPinCode: number, pbkdfParameters: PbkdfParameters) {
        // assigning the pbkdfParameters
        this.pbkdfParameters = pbkdfParameters;

        // computing initial SPAKE2+ values asynchronously
        Spake2p.computeW0L(pbkdfParameters, setupPinCode).then(initValues => {
            this.w0 = initValues.w0;
            this.L = initValues.L;
        });
    }

    // this function is just for demonstration purposes, this is not part of the original SPAKE2+ code!
    stealw0() {
        return new Promise<bigint>((resolve) => {
            const checkW0 = () => {
                if (this.w0 !== undefined) {
                    resolve(this.w0);  // returning w0 if it is defined
                } else {
                    setTimeout(checkW0, 100);  // waiting 100ms before trying again
                }
            };
            checkW0();
        });
    }

    // this function is just for demonstration purposes, this is not part of the original SPAKE2+ code!
    getPBKDFParameters() {
        return this.pbkdfParameters;
    }

    receivePbkdfParamRequest(request: { initiatorRandom: ByteArray; initiatorSessionId: string; passcodeId: number; hasPbkdfParameters: boolean }) {
        this.initiatorRandom = request.initiatorRandom;
        this.responderRandom = Crypto.getRandom();
        const responderSessionId = "server_session"; // example Session Id

        console.log(`Pase server: Received pbkdfParamRequest, sending pbkdfParamResponse.`);
        return {
            pbkdfParameters: this.pbkdfParameters,
            responderSessionId,
            responderRandom: this.responderRandom,
        };
    }

    async receivePasePake1(pake1: { x: ByteArray }) {
        if (!this.initiatorRandom || !this.responderRandom) {
            throw new Error("PaseServer: Random values not initialized.");
        }

        this.spake2p = Spake2p.create(Crypto.hash(ByteArray.concat(this.initiatorRandom, this.responderRandom)), this.w0);
        const Y = this.spake2p.computeY();
        const { Ke, cA, cB } = await this.spake2p.computeSecretAndVerifiersFromX(this.L, pake1.x, Y);
        this.cA = cA;
        this.Ke = Ke; // saving the shared secret for future use
        console.log(`Pase server: Received PASE Pake1, sending PASE Pake2.`);
        return { Y, cB };
    }

    receivePasePake3(pake3: { cA: ByteArray }) {
        if (!this.spake2p || !this.Ke) {
            throw new Error("PaseServer: SPAKE2+ process not properly initialized.");
        }

        // verifying client's verifier
        if (!pake3.cA.equals(this.cA)) {
            throw new Error("PaseServer: Client verifier does not match.");
        }

        console.log(`Pase server: Received PASE Pake3, pairing confirmed successfully.`);
        return true;  // indicating successful pairing
    }
}