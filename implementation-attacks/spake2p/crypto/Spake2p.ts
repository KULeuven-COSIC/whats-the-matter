/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { DataWriter } from "../util/DataWriter";
import { ByteArray, Endian } from "../util/ByteArray";
import { Crypto, ec } from "./Crypto";
import { CRYPTO_GROUP_SIZE_BYTES } from "./CryptoConstants";

//  Destructuring key elements from the elliptic curve cryptography module (EC).
// `ProjectivePoint` is used for elliptic curve point operations,
// `P256_CURVE` represents the parameters of the P-256 elliptic curve,
// `numberToBytesBE` and `bytesToNumberBE` are utility functions for conversions between numbers and byte arrays,
// `mod` is a utility function for modular arithmetic operations.
const {
    p256: { ProjectivePoint, CURVE: P256_CURVE },
    numberToBytesBE,
    bytesToNumberBE,
    mod,
} = ec;

// M and N constants from https://datatracker.ietf.org/doc/html/draft-bar-cfrg-spake2plus-01
const M = ProjectivePoint.fromHex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
const N = ProjectivePoint.fromHex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");

const CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8;

/**
 * Interface defining parameters for PBKDF2 key derivation.
 * Includes iteration count and salt used in the derivation process.
 */
export interface PbkdfParameters {
    iterations: number;
    salt: ByteArray;
}

/**
 * The SPAKE2+ Protocol.
 */
export class Spake2p {

    /**
    * Computes w0 and w1 using PBKDF2 based on provided parameters and a PIN.
    */
    static async computeW0W1({ iterations, salt }: PbkdfParameters, pin: number) {
        const pinWriter = new DataWriter(Endian.Little);
        pinWriter.writeUInt32(pin);
        const ws = await Crypto.pbkdf2(pinWriter.toByteArray(), salt, iterations, CRYPTO_W_SIZE_BYTES * 2);
        const w0 = mod(bytesToNumberBE(ws.slice(0, 40)), P256_CURVE.n);
        const w1 = mod(bytesToNumberBE(ws.slice(40, 80)), P256_CURVE.n);
        return { w0, w1 };
    }

    /**
    * Computes w0 and L from PBKDF2 parameters and a PIN.
    * L is a value used by the commissionee, calculated from w1.
    */
    static async computeW0L(pbkdfParameters: PbkdfParameters, pin: number) {
        const { w0, w1 } = await this.computeW0W1(pbkdfParameters, pin);
        const L = ProjectivePoint.BASE.multiply(w1).toRawBytes(false); // ProjectivePoint.BASE => the generator
        return { w0, L };
    }

    /**
    * Creates a new SPAKE2+ instance using a context and a random w0 value.
    * It initializes a SPAKE2+ object with a random value for cryptographic operations.
     */
    static create(context: ByteArray, w0: bigint) {
        const random = Crypto.getRandomBigInt(32, P256_CURVE.p);
        return new Spake2p(context, random, w0);
    }

    /**
    * SPAKE2+ constructor.
    * Initializes the instance with the provided context, random value, and w0.
    */
    constructor(
        private readonly context: ByteArray,
        private readonly random: bigint,
        private readonly w0: bigint,
    ) {}

    /**
    * Computes the X value in the SPAKE2+ protocol.
    * X is derived from the base point, random value, and w0, used for secure key exchange.
    * X = shareP
    */
    computeX(): ByteArray {
        const X = ProjectivePoint.BASE.multiply(this.random).add(M.multiply(this.w0));
        return X.toRawBytes(false);
    }

    /**
    * Computes the Y value in the SPAKE2+ protocol.
    * Y is derived from the base point, random value, and w0, similar to X but using a different point.
    * Y = shareV
    */
    computeY(): ByteArray {
        const Y = ProjectivePoint.BASE.multiply(this.random).add(N.multiply(this.w0));
        return Y.toRawBytes(false);
    }

    /**
    * Computes the shared secret and verifiers given w1, X, and Y.
    * The following values are computed and passed to computeSecretAndVerifiers:
    *   Z
    *   V
    */
    async computeSecretAndVerifiersFromY(w1: bigint, X: ByteArray, Y: ByteArray) {
        const YPoint = ProjectivePoint.fromHex(Y);
        try {
            YPoint.assertValidity();
        } catch (error) {
            throw new Error(`Y is not on the curve: ${(error as any).message}`);
        }
        const yNwo = YPoint.add(N.multiply(this.w0).negate());
        const Z = yNwo.multiply(this.random);
        const V = yNwo.multiply(w1);
        return this.computeSecretAndVerifiers(X, Y, Z.toRawBytes(false), V.toRawBytes(false));
    }

    /**
    * Computes the shared secret and verifiers given L, X, and Y.
    * The following values are computed and passed to computeSecretAndVerifiers:
    *   Z
    *   V
    */
    async computeSecretAndVerifiersFromX(L: ByteArray, X: ByteArray, Y: ByteArray) {
        const XPoint = ProjectivePoint.fromHex(X);
        const LPoint = ProjectivePoint.fromHex(L);
        try {
            XPoint.assertValidity();
        } catch (error) {
            throw new Error(`X is not on the curve: ${(error as any).message}`);
        }
        const Z = XPoint.add(M.multiply(this.w0).negate()).multiply(this.random);
        const V = LPoint.multiply(this.random);
        return this.computeSecretAndVerifiers(X, Y, Z.toRawBytes(false), V.toRawBytes(false));
    }

    /**
    * Helper method that computes the shared secret and verifiers given X, Y, Z and V.
    * The following values are computed:
    *   Z
    *   V
    */
    private async computeSecretAndVerifiers(X: ByteArray, Y: ByteArray, Z: ByteArray, V: ByteArray) {
        const TT_HASH = this.computeTranscriptHash(X, Y, Z, V);
        const Ka = TT_HASH.slice(0, 16);
        const Ke = TT_HASH.slice(16, 32);

        const KcAB = await Crypto.hkdf(Ka, new ByteArray(0), ByteArray.fromString("ConfirmationKeys"), 32);
        const KcA = KcAB.slice(0, 16);
        const KcB = KcAB.slice(16, 32);

        const cA = Crypto.hmac(KcA, Y);
        const cB = Crypto.hmac(KcB, X);

        return { Ke, cA, cB };
    }

    /**
    * Computes a hash of the protocol transcript.
    * Used in generating cryptographic keys and ensuring data integrity during key exchange.
    */
    private computeTranscriptHash(X: ByteArray, Y: ByteArray, Z: ByteArray, V: ByteArray) {
        const TTwriter = new DataWriter(Endian.Little);
        this.addToContext(TTwriter, this.context);
        this.addToContext(TTwriter, ByteArray.fromString(""));
        this.addToContext(TTwriter, ByteArray.fromString(""));
        this.addToContext(TTwriter, M.toRawBytes(false));
        this.addToContext(TTwriter, N.toRawBytes(false));
        this.addToContext(TTwriter, X);
        this.addToContext(TTwriter, Y);
        this.addToContext(TTwriter, Z);
        this.addToContext(TTwriter, V);
        this.addToContext(TTwriter, numberToBytesBE(this.w0, 32));
        return Crypto.hash(TTwriter.toByteArray());
    }

    /**
    * Adds a ByteArray to the transcript writer, updating the context with its length and the data itself.
    */
    private addToContext(TTwriter: DataWriter<Endian.Little>, data: ByteArray) {
        TTwriter.writeUInt64(data.length);
        TTwriter.writeByteArray(data);
    }
}
