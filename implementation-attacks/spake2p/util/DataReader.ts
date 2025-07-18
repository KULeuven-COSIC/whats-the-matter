/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The DataReader class is a utility for reading different types of data from a ByteArray (which is essentially a Uint8Array), 
 * while automatically advancing the read offset after each operation. 
 * It supports reading various integer and floating-point types, as well as strings and subarrays, in both little-endian and big-endian formats. 
 * This is useful for parsing binary data structures or formats where precise control over byte ordering and reading operations is needed.
 */

import { ByteArray, Endian } from "./ByteArray";

/** Reader that auto-increments its offset after each read. */
export class DataReader<E extends Endian> {
    private readonly littleEndian: boolean;
    private readonly dataView: DataView;
    private offset = 0;

    constructor(
        private readonly buffer: ByteArray,
        endian: E,
    ) {
        this.dataView = buffer.getDataView();
        this.littleEndian = endian === Endian.Little;
    }

    readUInt8() {
        return this.dataView.getUint8(this.getOffsetAndAdvance(1));
    }

    readUInt16() {
        return this.dataView.getUint16(this.getOffsetAndAdvance(2), this.littleEndian);
    }

    readUInt32() {
        return this.dataView.getUint32(this.getOffsetAndAdvance(4), this.littleEndian);
    }

    readUInt64() {
        return this.dataView.getBigUint64(this.getOffsetAndAdvance(8), this.littleEndian);
    }

    readInt8() {
        return this.dataView.getInt8(this.getOffsetAndAdvance(1));
    }

    readInt16() {
        return this.dataView.getInt16(this.getOffsetAndAdvance(2), this.littleEndian);
    }

    readInt32() {
        return this.dataView.getInt32(this.getOffsetAndAdvance(4), this.littleEndian);
    }

    readInt64() {
        return this.dataView.getBigInt64(this.getOffsetAndAdvance(8), this.littleEndian);
    }

    readFloat() {
        return this.dataView.getFloat32(this.getOffsetAndAdvance(4), this.littleEndian);
    }

    readDouble() {
        return this.dataView.getFloat64(this.getOffsetAndAdvance(8), this.littleEndian);
    }

    readUtf8String(length: number) {
        const offset = this.getOffsetAndAdvance(length);
        return new TextDecoder().decode(this.buffer.subarray(offset, offset + length));
    }

    readByteArray(length: number) {
        const offset = this.getOffsetAndAdvance(length);
        return this.buffer.subarray(offset, offset + length);
    }

    getRemainingBytesCount() {
        return this.dataView.byteLength - this.offset;
    }

    getRemainingBytes() {
        return this.buffer.subarray(this.offset);
    }

    getLength() {
        return this.dataView.byteLength;
    }

    setOffset(offset: number) {
        if (offset > this.dataView.byteLength) {
            throw new Error(`Offset ${offset} is out of bounds.`);
        }
        this.offset = offset;
    }

    private getOffsetAndAdvance(size: number) {
        const result = this.offset;
        this.offset += size;
        if (this.offset > this.dataView.byteLength) {
            this.offset = this.dataView.byteLength;
        }
        return result;
    }
}
