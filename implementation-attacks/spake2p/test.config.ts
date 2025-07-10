/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Crypto } from "./crypto/Crypto";
import { CryptoNode } from "./crypto/CryptoNode";

const TheCrypto = new CryptoNode();
Crypto.get = () => TheCrypto;
