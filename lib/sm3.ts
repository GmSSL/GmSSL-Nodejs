/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';

const SM3_DIGEST_SIZE = 32;
const SM3_HMAC_SIZE = 32;

/**
 * SM3 cryptographic hash algorithm.
 *
 * SM3 is a Chinese national standard cryptographic hash function
 * that produces a 256-bit (32-byte) digest.
 */
export class Sm3 {
  private ctx: any;

  constructor() {
    this.ctx = new native.Sm3Context();
    this.ctx.init();
  }

  /**
   * Update the hash with data.
   * @param data - Data to hash
   */
  update(data: Buffer): void {
    if (!Buffer.isBuffer(data)) {
      throw new Error('Expected Buffer');
    }
    if (data.length > 0) {
      this.ctx.update(data);
    }
  }

  /**
   * Finalize and return the hash digest.
   * @returns 32-byte SM3 digest
   */
  digest(): Buffer {
    return Buffer.from(this.ctx.digest());
  }

  /**
   * Reset the hash context for reuse.
   */
  reset(): void {
    this.ctx.reset();
  }
}

/**
 * HMAC-SM3 - Hash-based Message Authentication Code using SM3.
 */
export class Sm3Hmac {
  private ctx: any;
  private key: Buffer;

  /**
   * @param key - Key for HMAC (16-64 bytes)
   */
  constructor(key: Buffer) {
    if (!Buffer.isBuffer(key)) {
      throw new Error('Expected key as Buffer');
    }
    if (key.length < 16 || key.length > 64) {
      throw new Error('Invalid key length');
    }
    this.key = key;
    this.ctx = new native.Sm3HmacContext();
    this.ctx.init(key);
  }

  /**
   * Update the HMAC with data.
   * @param data - Data to authenticate
   */
  update(data: Buffer): void {
    if (!Buffer.isBuffer(data)) {
      throw new Error('Expected Buffer');
    }
    if (data.length > 0) {
      this.ctx.update(data);
    }
  }

  /**
   * Generate the MAC.
   * @returns 32-byte HMAC-SM3 tag
   */
  generateMac(): Buffer {
    return Buffer.from(this.ctx.generateMac());
  }

  /**
   * Reset with a new key.
   * @param key - New key (16-64 bytes)
   */
  reset(key: Buffer): void {
    if (!Buffer.isBuffer(key)) {
      throw new Error('Expected key as Buffer');
    }
    if (key.length < 16 || key.length > 64) {
      throw new Error('Invalid key length');
    }
    this.key = key;
    this.ctx.reset(key);
  }
}

/**
 * PBKDF2-HMAC-SM3 - Password-Based Key Derivation Function.
 */
export class Sm3Pbkdf2 {
  static readonly MAX_SALT_SIZE = 64;
  static readonly DEFAULT_SALT_SIZE = 8;
  static readonly MIN_ITER = 10000;
  static readonly MAX_ITER = 16777216;
  static readonly MAX_KEY_SIZE = 256;

  /**
   * Derive a key from a password using PBKDF2-HMAC-SM3.
   * @param pass - Password string
   * @param salt - Salt bytes
   * @param iter - Iteration count (10000 - 16777216)
   * @param keylen - Desired key length in bytes (max 256)
   * @returns Derived key
   */
  static deriveKey(pass: string, salt: Buffer, iter: number, keylen: number): Buffer {
    if (typeof pass !== 'string') {
      throw new Error('Expected password as string');
    }
    if (!Buffer.isBuffer(salt)) {
      throw new Error('Expected salt as Buffer');
    }
    if (salt.length > Sm3Pbkdf2.MAX_SALT_SIZE) {
      throw new Error('Invalid salt size');
    }
    if (!Number.isInteger(iter) || iter < Sm3Pbkdf2.MIN_ITER || iter > Sm3Pbkdf2.MAX_ITER) {
      throw new Error('Invalid iter value');
    }
    if (!Number.isInteger(keylen) || keylen <= 0 || keylen > Sm3Pbkdf2.MAX_KEY_SIZE) {
      throw new Error('Invalid key length');
    }
    return Buffer.from(native.sm3Pbkdf2(pass, salt, iter, keylen));
  }
}
