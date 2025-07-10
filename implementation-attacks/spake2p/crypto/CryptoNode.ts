/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
    CRYPTO_AUTH_TAG_LENGTH,
    CRYPTO_EC_CURVE,
    CRYPTO_EC_KEY_BYTES,
    CRYPTO_ENCRYPT_ALGORITHM,
    CRYPTO_HASH_ALGORITHM,
    CRYPTO_SYMMETRIC_KEY_LENGTH,
    Crypto,
    CryptoDsaEncoding
} from "./Crypto";
import {
    PrivateKey,
} from "./Key"

import { ByteArray } from "../util/ByteArray";
import * as crypto from "crypto";

/**
 * Provider for the Crypto module, providing instances for the abstract methods.
 */
export class CryptoNode extends Crypto {

    /**
     * Encrypts data using AES-128-CCM with the provided key and nonce.
     * Optionally includes additional authenticated data (AAD).
     * Returns the encrypted data with the authentication tag appended.
     */
    encrypt(key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray {
        const cipher = crypto.createCipheriv(CRYPTO_ENCRYPT_ALGORITHM, key, nonce, {
            authTagLength: CRYPTO_AUTH_TAG_LENGTH,
        });
        if (aad !== undefined) {
            cipher.setAAD(aad, { plaintextLength: data.length });
        }
        const encrypted = cipher.update(data);
        cipher.final();
        return ByteArray.concat(encrypted, cipher.getAuthTag());
    }

    /**
     * Decrypts data using AES-128-CCM with the provided key and nonce.
     * Verifies the authentication tag and optionally includes AAD for integrity check.
     * Returns the decrypted data if the authentication is successful.
     */
    decrypt(key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray {
        const cipher = crypto.createDecipheriv(CRYPTO_ENCRYPT_ALGORITHM, key, nonce, {
            authTagLength: CRYPTO_AUTH_TAG_LENGTH,
        });
        const plaintextLength = data.length - CRYPTO_AUTH_TAG_LENGTH;
        if (aad !== undefined) {
            cipher.setAAD(aad, { plaintextLength });
        }
        cipher.setAuthTag(data.slice(plaintextLength));
        const result = cipher.update(data.slice(0, plaintextLength));
        cipher.final();
        return new ByteArray(result);
    }

    /**
     * Generates a random byte array of the specified length using Node.js's crypto library.
     */
    getRandomData(length: number): ByteArray {
        return new ByteArray(crypto.randomBytes(length));
    }

    /**
     * Generates an elliptic curve public key and returns it along with the ECDH context (which encapsulates the state and parameters).
     * Uses the `prime256v1` curve for key generation.
     */
    ecdhGeneratePublicKey(): { publicKey: ByteArray; ecdh: any } {
        const ecdh = crypto.createECDH(CRYPTO_EC_CURVE);
        ecdh.generateKeys();
        return { publicKey: new ByteArray(ecdh.getPublicKey()), ecdh: ecdh };
    }

    /**
     * Generates an elliptic curve public key and a shared secret using a peer's public key.
     * Returns both the generated public key and the shared secret.
     */
    ecdhGeneratePublicKeyAndSecret(peerPublicKey: ByteArray): { publicKey: ByteArray; sharedSecret: ByteArray } {
        const ecdh = crypto.createECDH(CRYPTO_EC_CURVE);
        ecdh.generateKeys();
        return {
            publicKey: new ByteArray(ecdh.getPublicKey()),
            sharedSecret: new ByteArray(ecdh.computeSecret(peerPublicKey)),
        };
    }

    /**
     * Computes a shared secret using a peer's public key and an ECDH object.
     */
    ecdhGenerateSecret(peerPublicKey: ByteArray, ecdh: crypto.ECDH): ByteArray {
        return new ByteArray(ecdh.computeSecret(peerPublicKey));
    }

    /**
     * Computes a cryptographic hash of the provided data using SHA-256.
     * Supports hashing both single ByteArrays and arrays of ByteArrays.
     */
    hash(data: ByteArray | ByteArray[]): ByteArray {
        const hasher = crypto.createHash(CRYPTO_HASH_ALGORITHM);
        if (Array.isArray(data)) {
            data.forEach(chunk => hasher.update(chunk));
        } else {
            hasher.update(data);
        }
        return new ByteArray(hasher.digest());
    }

    /**
     * Derives a cryptographic key from a secret, salt, and iteration count using PBKDF2 with SHA-256.
     * Returns a promise that resolves to the derived key.
     */
    pbkdf2(secret: ByteArray, salt: ByteArray, iteration: number, keyLength: number): Promise<ByteArray> {
        return new Promise<ByteArray>((resolver, rejecter) => {
            crypto.pbkdf2(secret, salt, iteration, keyLength, CRYPTO_HASH_ALGORITHM, (error, key) => {
                if (error !== null) rejecter(error);
                resolver(new ByteArray(key));
            });
        });
    }

    /**
     * Derives keys using HKDF (HMAC-based Extract-and-Expand Key Derivation Function) with SHA-256.
     * Takes a secret, salt, info, and optional length for the derived key.
     * Returns a promise that resolves to the derived key.
     */
    hkdf(
        secret: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: number = CRYPTO_SYMMETRIC_KEY_LENGTH,
    ): Promise<ByteArray> {
        return new Promise<ByteArray>((resolver, rejecter) => {
            crypto.hkdf(CRYPTO_HASH_ALGORITHM, secret, salt, info, length, (error, key) => {
                if (error !== null) rejecter(error);
                resolver(new ByteArray(key));
            });
        });
    }

    /**
     * Computes an HMAC (Hash-based Message Authentication Code) using SHA-256.
     * Returns the HMAC of the data using the provided key.
     */
    hmac(key: ByteArray, data: ByteArray): ByteArray {
        const hmac = crypto.createHmac(CRYPTO_HASH_ALGORITHM, key);
        hmac.update(data);
        return new ByteArray(hmac.digest());
    }

    /**
     * Signs data using a private key with SHA-256 and the specified DSA encoding format.
     * Supports signing both single ByteArrays and arrays of ByteArrays.
     */
    sign(
        privateKey: JsonWebKey,
        data: ByteArray | ByteArray[],
        dsaEncoding: CryptoDsaEncoding = "ieee-p1363",
    ): ByteArray {
        const signer = crypto.createSign(CRYPTO_HASH_ALGORITHM);
        if (Array.isArray(data)) {
            data.forEach(chunk => signer.update(chunk));
        } else {
            signer.update(data);
        }
        return new ByteArray(
            signer.sign({
                key: privateKey as any,
                format: "jwk",
                type: "pkcs8",
                dsaEncoding,
            }),
        );
    }

    /**
     * Verifies the authenticity of data using a public key, signature, and SHA-256.
     * Throws an error if the signature verification fails.
     */
    verify(
        publicKey: JsonWebKey,
        data: ByteArray,
        signature: ByteArray,
        dsaEncoding: CryptoDsaEncoding = "ieee-p1363",
    ) {
        const verifier = crypto.createVerify(CRYPTO_HASH_ALGORITHM);
        verifier.update(data);
        const success = verifier.verify(
            {
                key: publicKey as any,
                format: "jwk",
                type: "spki",
                dsaEncoding,
            },
            signature,
        );
        if (!success) throw new Error("Signature verification failed");
    }

    /**
     * Creates a new elliptic curve key pair using the `prime256v1` curve.
     * Returns a PrivateKey object containing the private key and the public key.
     */
    createKeyPair() {
        const ecdh = crypto.createECDH(CRYPTO_EC_CURVE);
        ecdh.generateKeys();

        // The key exported from Node doesn't include most-significant bytes that are 0.  This doesn't affect how we
        // currently use keys but it's a little weird so 0 pad to avoid future confusion
        const privateKey = new ByteArray(CRYPTO_EC_KEY_BYTES);
        const nodePrivateKey = ecdh.getPrivateKey();
        privateKey.set(nodePrivateKey, CRYPTO_EC_KEY_BYTES - nodePrivateKey.length);

        return PrivateKey(privateKey, { publicKey: ecdh.getPublicKey() });
    }
}
