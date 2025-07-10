import { Crypto } from "../../crypto/Crypto";
import { PbkdfParameters, Spake2p } from "../../crypto/Spake2p";
import { ByteArray } from "../../util/ByteArray";
import { ec } from "../../crypto/Crypto";
import { PaseServer } from "./PaseServer";  // Ensure this import matches your file structure

const { numberToBytesBE } = ec;

export class PaseClient {
    private w0: bigint;
    private w1: bigint;
    private spake2p: Spake2p;
    private X: ByteArray;

    async initiatePairing(setupPin: number, pbkdfParameters: PbkdfParameters, server: PaseServer) {
        // Step 1: generating random values and send pbkdfParamRequest
        const initiatorRandom = Crypto.getRandom();
        const initiatorSessionId = "client_session"; // Example Session Id

        // receiving pbkdfParamResponse from server
        const { pbkdfParameters: serverPbkdfParameters, responderSessionId, responderRandom } = server.receivePbkdfParamRequest({
            initiatorRandom,
            initiatorSessionId,
            passcodeId: 1,
            hasPbkdfParameters: false,
        });

        // Step 2: computing SPAKE2+ keys
        const { w0, w1 } = await Spake2p.computeW0W1(serverPbkdfParameters || pbkdfParameters, setupPin);
        this.w0 = w0;
        this.w1 = w1;
        this.spake2p = Spake2p.create(Crypto.hash(ByteArray.concat(initiatorRandom, responderRandom)), w0);
        this.X = this.spake2p.computeX();

        // sending PASE Pake1 and awaiting response
        // "verifier: hBX" means take the verifier property from the object and assign it to a new variable named hBX!
        const { Y, cB } = await server.receivePasePake1({ x: this.X });

        // Step 3: processing Pake2 and sending Pake3
        const { Ke, cA, cB: computedcB } = await this.spake2p.computeSecretAndVerifiersFromY(w1, this.X, Y);
        if (!cB.equals(computedcB)) throw new Error("Received incorrect key confirmation from the server.");
        server.receivePasePake3({ cA });

        // Step 4: confirming successful pairing
        console.log(`Pase client: Paired successfully with session ID ${responderSessionId}.`);
        return Ke;
    }
}