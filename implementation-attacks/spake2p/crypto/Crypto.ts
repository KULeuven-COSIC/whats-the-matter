/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import * as mod from "@noble/curves/abstract/modular";
import * as utils from "@noble/curves/abstract/utils";
import { p256 } from "@noble/curves/p256";
import { DataReader } from "../util/DataReader";
import { ByteArray, Endian } from "../util/ByteArray";
import { PrivateKey } from "./Key.js";

export const ec = {
    p256,
    ...utils,
    ...mod,
};

export const CRYPTO_RANDOM_LENGTH = 32;
export const CRYPTO_ENCRYPT_ALGORITHM = "aes-128-ccm";
export const CRYPTO_HASH_ALGORITHM = "sha256";
export const CRYPTO_EC_CURVE = "prime256v1";
export const CRYPTO_EC_KEY_BYTES = 32;
export const CRYPTO_AUTH_TAG_LENGTH = 16;
export const CRYPTO_SYMMETRIC_KEY_LENGTH = 16;
export type CryptoDsaEncoding = "ieee-p1363" | "der";

/**
 * Abstract class for cryptographic operations with static methods
 * for accessing an underlying cryptographic provider.
 */
export abstract class Crypto {
    // Getter for the crypto provider instance. Throws an error if not configured.
    static get: () => Crypto = () => {
        throw new Error("No provider configured");
    };

    // Abstract method for encrypting data with a given key and nonce.
    abstract encrypt(key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray;
    static readonly encrypt = (key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray =>
        Crypto.get().encrypt(key, data, nonce, aad);


    // Abstract method for decrypting data with a given key and nonce.
    abstract decrypt(key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray;
    static readonly decrypt = (key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray =>
        Crypto.get().decrypt(key, data, nonce, aad);

    // Abstract method to generate random data of a specified length.
    abstract getRandomData(length: number): ByteArray;
    static readonly getRandomData = (length: number): ByteArray => Crypto.get().getRandomData(length);

    // Static method to generate a random ByteArray of a default length.
    static readonly getRandom = (): ByteArray => Crypto.get().getRandomData(CRYPTO_RANDOM_LENGTH);

    // Static method to generate a random 16-bit unsigned integer.
    static readonly getRandomUInt16 = (): number =>
        new DataReader(Crypto.get().getRandomData(2), Endian.Little).readUInt16();

    // Static method to generate a random 32-bit unsigned integer.
    static readonly getRandomUInt32 = (): number =>
        new DataReader(Crypto.get().getRandomData(4), Endian.Little).readUInt32();

    // Static method to generate a random 64-bit unsigned integer as a bigint.
    static readonly getRandomBigUInt64 = (): bigint =>
        new DataReader(Crypto.get().getRandomData(8), Endian.Little).readUInt64();

    // Static method to generate a random bigint within an optional maximum value.
    static readonly getRandomBigInt = (size: number, maxValue?: bigint): bigint => {
        const { bytesToNumberBE } = ec;
        if (maxValue === undefined) {
            return bytesToNumberBE(Crypto.getRandomData(size));
        }
        while (true) {
            const random = bytesToNumberBE(Crypto.getRandomData(size));
            if (random < maxValue) return random;
        }
    };

    // Abstract method to generate a public key for ECDH (Elliptic Curve Diffie-Hellman).
    abstract ecdhGeneratePublicKey(): { publicKey: ByteArray; ecdh: any };
    static readonly ecdhGeneratePublicKey = (): { publicKey: ByteArray; ecdh: any } =>
        Crypto.get().ecdhGeneratePublicKey();

    // Abstract method to generate a public key and shared secret for ECDH.
    abstract ecdhGeneratePublicKeyAndSecret(peerPublicKey: ByteArray): {
        publicKey: ByteArray;
        sharedSecret: ByteArray;
    };
    static readonly ecdhGeneratePublicKeyAndSecret = (
        peerPublicKey: ByteArray,
    ): { publicKey: ByteArray; sharedSecret: ByteArray } => Crypto.get().ecdhGeneratePublicKeyAndSecret(peerPublicKey);

    // Abstract method to generate a shared secret for ECDH.
    abstract ecdhGenerateSecret(peerPublicKey: ByteArray, ecdh: any): ByteArray;
    static readonly ecdhGenerateSecret = (peerPublicKey: ByteArray, ecdh: any): ByteArray =>
        Crypto.get().ecdhGenerateSecret(peerPublicKey, ecdh);

    // Abstract method to hash data.
    abstract hash(data: ByteArray | ByteArray[]): ByteArray;
    static readonly hash = (data: ByteArray | ByteArray[]): ByteArray => Crypto.get().hash(data);

    // Abstract method for PBKDF2 (Password-Based Key Derivation Function 2).
    abstract pbkdf2(secret: ByteArray, salt: ByteArray, iteration: number, keyLength: number): Promise<ByteArray>;
    static readonly pbkdf2 = (
        secret: ByteArray,
        salt: ByteArray,
        iteration: number,
        keyLength: number,
    ): Promise<ByteArray> => Crypto.get().pbkdf2(secret, salt, iteration, keyLength);

    // Abstract method for HKDF (HMAC-based Key Derivation Function).
    abstract hkdf(secret: ByteArray, salt: ByteArray, info: ByteArray, length?: number): Promise<ByteArray>;
    static readonly hkdf = (secret: ByteArray, salt: ByteArray, info: ByteArray, length?: number): Promise<ByteArray> =>
        Crypto.get().hkdf(secret, salt, info, length);

    // Abstract method to generate an HMAC (Hash-based Message Authentication Code).
    abstract hmac(key: ByteArray, data: ByteArray): ByteArray;
    static readonly hmac = (key: ByteArray, data: ByteArray): ByteArray => Crypto.get().hmac(key, data);

    // Abstract method to sign data using a private key.
    abstract sign(privateKey: JsonWebKey, data: ByteArray | ByteArray[], dsaEncoding?: CryptoDsaEncoding): ByteArray;
    static readonly sign = (
        privateKey: JsonWebKey,
        data: ByteArray | ByteArray[],
        dsaEncoding?: CryptoDsaEncoding,
    ): ByteArray => Crypto.get().sign(privateKey, data, dsaEncoding);

    // Abstract method to verify a signature using a public key.
    abstract verify(
        publicKey: JsonWebKey,
        data: ByteArray,
        signature: ByteArray,
        dsaEncoding?: CryptoDsaEncoding,
    ): void;
    static readonly verify = (
        publicKey: JsonWebKey,
        data: ByteArray,
        signature: ByteArray,
        dsaEncoding?: CryptoDsaEncoding,
    ): void => Crypto.get().verify(publicKey, data, signature, dsaEncoding);

    // Abstract method to create a new cryptographic key pair.
    abstract createKeyPair(): PrivateKey;
    static readonly createKeyPair = (): PrivateKey => Crypto.get().createKeyPair();
}