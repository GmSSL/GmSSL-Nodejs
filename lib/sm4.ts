/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';

const SM4_KEY_SIZE = 16;
const SM4_BLOCK_SIZE = 16;
const SM4_CBC_IV_SIZE = 16;
const SM4_CTR_IV_SIZE = 16;
const SM4_GCM_MAX_TAG_SIZE = 16;

/**
 * SM4 block cipher - ECB mode (single block encryption).
 *
 * SM4 is a Chinese national standard block cipher with
 * 128-bit (16-byte) key and 128-bit (16-byte) block size.
 */
export class Sm4 {
  static readonly KEY_SIZE = SM4_KEY_SIZE;
  static readonly BLOCK_SIZE = SM4_BLOCK_SIZE;

  private ctx: any;
  private encryptFlag: boolean;

  /**
   * @param key - 16-byte key
   * @param encrypt - true for encryption, false for decryption
   */
  constructor(key: Buffer, encrypt: boolean) {
    if (!Buffer.isBuffer(key)) {
      throw new Error('Expected key as Buffer');
    }
    if (key.length !== SM4_KEY_SIZE) {
      throw new Error('Invalid key length');
    }
    this.encryptFlag = encrypt;
    this.ctx = new native.Sm4Context();
    this.ctx.init(key, encrypt);
  }

  /**
   * Encrypt/decrypt a single 16-byte block.
   * Note: The method is named "encrypt" regardless of operation direction,
   * matching the underlying sm4_encrypt function.
   * @param block - 16-byte input block
   * @returns 16-byte output block
   */
  encrypt(block: Buffer): Buffer {
    if (!Buffer.isBuffer(block)) {
      throw new Error('Expected block as Buffer');
    }
    if (block.length !== SM4_BLOCK_SIZE) {
      throw new Error('Invalid block size');
    }
    return Buffer.from(this.ctx.encrypt(block));
  }
}

/**
 * SM4-CBC mode cipher.
 *
 * CBC (Cipher Block Chaining) mode requires a 16-byte IV.
 * Data size must be a multiple of the 16-byte block size.
 */
export class Sm4Cbc {
  static readonly KEY_SIZE = SM4_KEY_SIZE;
  static readonly IV_SIZE = SM4_CBC_IV_SIZE;
  static readonly BLOCK_SIZE = SM4_BLOCK_SIZE;

  private ctx: any;
  private encryptFlag: boolean;

  constructor() {
    this.encryptFlag = true;
    this.ctx = new native.Sm4CbcContext();
  }

  /**
   * Initialize the SM4-CBC context.
   * @param key - 16-byte key
   * @param iv - 16-byte initialization vector
   * @param encrypt - true for encryption, false for decryption
   */
  init(key: Buffer, iv: Buffer, encrypt: boolean): void {
    if (!Buffer.isBuffer(key) || key.length !== SM4_KEY_SIZE) {
      throw new Error('Invalid key length');
    }
    if (!Buffer.isBuffer(iv) || iv.length !== SM4_CBC_IV_SIZE) {
      throw new Error('Invalid IV length');
    }
    this.encryptFlag = encrypt;
    this.ctx.init(key, iv, encrypt);
  }

  /**
   * Process input data.
   * @param data - Input data (must be multiple of 16 bytes)
   * @returns Output data
   */
  update(data: Buffer): Buffer {
    if (!Buffer.isBuffer(data)) {
      throw new Error('Expected data as Buffer');
    }
    return Buffer.from(this.ctx.update(data));
  }

  /**
   * Finish and return any remaining output (including padding).
   * @returns Remaining output data
   */
  finish(): Buffer {
    return Buffer.from(this.ctx.finish());
  }
}

/**
 * SM4-CTR mode cipher.
 *
 * CTR (Counter) mode turns SM4 into a stream cipher.
 * Encryption and decryption are the same operation.
 */
export class Sm4Ctr {
  static readonly KEY_SIZE = SM4_KEY_SIZE;
  static readonly IV_SIZE = SM4_CTR_IV_SIZE;
  static readonly BLOCK_SIZE = SM4_BLOCK_SIZE;

  private ctx: any;

  constructor() {
    this.ctx = new native.Sm4CtrContext();
  }

  /**
   * Initialize the SM4-CTR context.
   * @param key - 16-byte key
   * @param iv - 16-byte initialization vector
   */
  init(key: Buffer, iv: Buffer): void {
    if (!Buffer.isBuffer(key) || key.length !== SM4_KEY_SIZE) {
      throw new Error('Invalid key length');
    }
    if (!Buffer.isBuffer(iv) || iv.length !== SM4_CTR_IV_SIZE) {
      throw new Error('Invalid IV length');
    }
    this.ctx.init(key, iv);
  }

  /**
   * Process input data.
   * @param data - Input data
   * @returns Output data
   */
  update(data: Buffer): Buffer {
    if (!Buffer.isBuffer(data)) {
      throw new Error('Expected data as Buffer');
    }
    return Buffer.from(this.ctx.update(data));
  }

  /**
   * Finish and return any remaining output.
   * @returns Remaining output data
   */
  finish(): Buffer {
    return Buffer.from(this.ctx.finish());
  }
}

/**
 * SM4-GCM mode - Authenticated Encryption with Associated Data.
 *
 * GCM (Galois/Counter Mode) provides both confidentiality and
 * authenticity. Supports Additional Authenticated Data (AAD).
 */
export class Sm4Gcm {
  static readonly KEY_SIZE = SM4_KEY_SIZE;
  static readonly MIN_IV_SIZE = 1;
  static readonly MAX_IV_SIZE = 64;
  static readonly DEFAULT_IV_SIZE = 12;
  static readonly MIN_TAG_SIZE = 8;
  static readonly MAX_TAG_SIZE = SM4_GCM_MAX_TAG_SIZE;
  static readonly DEFAULT_TAG_SIZE = 16;
  static readonly BLOCK_SIZE = SM4_BLOCK_SIZE;

  private ctx: any;
  private encryptFlag: boolean;

  constructor() {
    this.encryptFlag = true;
    this.ctx = new native.Sm4GcmContext();
  }

  /**
   * Initialize the SM4-GCM context.
   * @param key - 16-byte key
   * @param iv - Initialization vector (1-64 bytes, recommended 12)
   * @param aad - Additional Authenticated Data
   * @param taglen - Tag length in bytes (8-16, default 16)
   * @param encrypt - true for encryption, false for decryption
   */
  init(key: Buffer, iv: Buffer, aad: Buffer, taglen: number, encrypt: boolean): void {
    if (!Buffer.isBuffer(key) || key.length !== SM4_KEY_SIZE) {
      throw new Error('Invalid key length');
    }
    if (!Buffer.isBuffer(iv) || iv.length < 1 || iv.length > 64) {
      throw new Error('Invalid IV length');
    }
    if (!Buffer.isBuffer(aad)) {
      aad = Buffer.alloc(0);
    }
    if (!Number.isInteger(taglen) || taglen < 8 || taglen > 16) {
      throw new Error('Invalid tag length');
    }
    this.encryptFlag = encrypt;
    this.ctx.init(key, iv, aad, taglen, encrypt);
  }

  /**
   * Process input data.
   * @param data - Input data
   * @returns Output data
   */
  update(data: Buffer): Buffer {
    if (!Buffer.isBuffer(data)) {
      throw new Error('Expected data as Buffer');
    }
    return Buffer.from(this.ctx.update(data));
  }

  /**
   * Finish and return remaining output (includes authentication tag for encryption).
   * @returns Remaining output data
   */
  finish(): Buffer {
    return Buffer.from(this.ctx.finish());
  }
}
