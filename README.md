# GmSSL-Nodejs

GmSSL Node.js binding — Chinese National Standard Cryptographic Algorithms (SM2/SM3/SM4/SM9/ZUC) for Node.js.

## Overview

GmSSL-Nodejs provides TypeScript bindings to the [GmSSL](https://github.com/GmSSL) cryptographic library, enabling Node.js applications to use Chinese national standard cryptographic algorithms:

- **SM2** — Elliptic curve public key cryptography (key exchange, digital signature, encryption)
- **SM3** — Cryptographic hash function (256-bit digest)
- **SM4** — Block cipher (ECB, CBC, CTR, GCM modes)
- **SM9** — Identity-Based Cryptography (signature and encryption)
- **ZUC** — Stream cipher

## Prerequisites

- Node.js >= 16.0.0
- [GmSSL](https://github.com/guanzhi/GmSSL) library installed (version 3.1.0 or later)
- C++ build tools (`make`, `gcc`/`clang`)

### Installing GmSSL

#### macOS
```bash
# Clone and build GmSSL
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
mkdir build && cd build
cmake ..
make
sudo make install
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install -y cmake build-essential
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
mkdir build && cd build
cmake ..
make
sudo make install
sudo ldconfig
```

## Installation

```bash
npm install gmssl
```

## Quick Start

```typescript
import { Sm3, Sm2Key, Sm4Ctr, Random, versionStr } from 'gmssl';

// Version
console.log(versionStr());

// SM3 Hash
const sm3 = new Sm3();
sm3.update(Buffer.from('abc'));
const dgst = sm3.digest();
console.log(dgst.toString('hex'));

// SM2 Key Generation, Sign, and Verify
const sm2 = new Sm2Key();
sm2.generateKey();

const sm3hash = new Sm3();
sm3hash.update(Buffer.from('hello sm2'));
const hash = sm3hash.digest();

const signature = sm2.sign(hash);
const verified = sm2.verify(hash, signature);
console.log('SM2 verify:', verified);

// SM4-CTR Encryption
const key = Random.randBytes(16);
const iv = Random.randBytes(16);
const plaintext = Buffer.from('secret message');

const encrypt = new Sm4Ctr();
encrypt.init(key, iv);
const ciphertext = Buffer.concat([encrypt.update(plaintext), encrypt.finish()]);

const decrypt = new Sm4Ctr();
decrypt.init(key, iv);
const decrypted = Buffer.concat([decrypt.update(ciphertext), decrypt.finish()]);

console.log('SM4-CTR decrypt matches:', decrypted.equals(plaintext));
```

## API Reference

### Version

- `versionNum(): number` — Returns GmSSL library version number
- `versionStr(): string` — Returns GmSSL library version string

### Random

- `Random.randBytes(length: number): Buffer` — Generate cryptographically secure random bytes

### SM3 (Hash)

```typescript
class Sm3 {
  update(data: Buffer): void;
  digest(): Buffer;    // Returns 32-byte digest
  reset(): void;
}

class Sm3Hmac {
  constructor(key: Buffer);  // key: 16-64 bytes
  update(data: Buffer): void;
  generateMac(): Buffer;     // Returns 32-byte MAC
  reset(key: Buffer): void;
}

class Sm3Pbkdf2 {
  static deriveKey(pass: string, salt: Buffer, iter: number, keylen: number): Buffer;
}
```

### SM4 (Block Cipher)

```typescript
class Sm4 {
  constructor(key: Buffer, encrypt: boolean);  // key: 16 bytes
  encrypt(block: Buffer): Buffer;              // block: 16 bytes
}

class Sm4Cbc {
  init(key: Buffer, iv: Buffer, encrypt: boolean): void;
  update(data: Buffer): Buffer;
  finish(): Buffer;
}

class Sm4Ctr {
  init(key: Buffer, iv: Buffer): void;
  update(data: Buffer): Buffer;
  finish(): Buffer;
}

class Sm4Gcm {
  init(key: Buffer, iv: Buffer, aad: Buffer, taglen: number, encrypt: boolean): void;
  update(data: Buffer): Buffer;
  finish(): Buffer;  // Includes auth tag (encrypt) or verifies tag (decrypt)
}
```

### SM2 (Public Key Cryptography)

```typescript
class Sm2Key {
  generateKey(): void;
  sign(dgst: Buffer): Buffer;
  verify(dgst: Buffer, signature: Buffer): boolean;
  encrypt(plaintext: Buffer): Buffer;
  decrypt(ciphertext: Buffer): Buffer;
  computeZ(id: string): Buffer;
  importEncryptedPrivateKeyInfoPem(password: string, path: string): void;
  exportEncryptedPrivateKeyInfoPem(password: string, path: string): void;
  importPublicKeyInfoPem(path: string): void;
  exportPublicKeyInfoPem(path: string): void;
  importPrivateKeyInfoDer(der: Buffer): void;
  exportPrivateKeyInfoDer(): Buffer;
  importPublicKeyInfoDer(der: Buffer): void;
  exportPublicKeyInfoDer(): Buffer;
}

class Sm2Signature {
  init(key: Sm2Key, id: string, doSign: boolean): void;
  update(data: Buffer): void;
  sign(): Buffer;
  verify(signature: Buffer): boolean;
}
```

### SM9 (Identity-Based Cryptography)

```typescript
class Sm9SignMasterKey {
  generateMasterKey(): void;
  extractKey(id: string): Sm9SignKey;
  importEncryptedMasterKeyInfoPem(path: string, pass: string): void;
  exportEncryptedMasterKeyInfoPem(path: string, pass: string): void;
  importPublicMasterKeyPem(path: string): void;
  exportPublicMasterKeyPem(path: string): void;
}

class Sm9SignKey {
  getId(): string;
  importEncryptedPrivateKeyInfoPem(path: string, pass: string): void;
  exportEncryptedPrivateKeyInfoPem(path: string, pass: string): void;
}

class Sm9EncMasterKey {
  generateMasterKey(): void;
  extractKey(id: string): Sm9EncKey;
  encrypt(plaintext: Buffer, toId: string): Buffer;
  // PEM import/export methods...
}

class Sm9EncKey {
  getId(): string;
  decrypt(ciphertext: Buffer): Buffer;
  // PEM import/export methods...
}

class Sm9Signature {
  init(doSign: boolean): void;
  update(data: Buffer): void;
  sign(signKey: Sm9SignKey): Buffer;
  verify(signature: Buffer, masterPublicKey: Sm9SignMasterKey, signerId: string): boolean;
}
```

### ZUC (Stream Cipher)

```typescript
class Zuc {
  init(key: Buffer, iv: Buffer): void;  // key: 16 bytes, iv: 16 bytes
  update(data: Buffer): Buffer;
  finish(): Buffer;
}
```

### Certificate

```typescript
class Sm2Certificate {
  importPem(path: string): void;
  exportPem(path: string): void;
  getSerialNumber(): Buffer;
  getIssuer(): Buffer;
  getSubject(): Buffer;
  getNotBefore(): number;
  getNotAfter(): number;
  getSubjectPublicKey(): Sm2Key;
  verifyByCaCertificate(caCert: Sm2Certificate, sm2Id: string): boolean;
}
```

## Development

```bash
# Install dependencies
npm install

# Build native addon
npm run build:addon

# Build TypeScript
npm run build

# Build everything
npm run build:all

# Run tests
npm test
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
