/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';

const ZUC_KEY_SIZE = 16;
const ZUC_IV_SIZE = 16;

/**
 * ZUC stream cipher.
 *
 * ZUC (祖冲之) is a Chinese national standard stream cipher.
 * It uses a 128-bit (16-byte) key and a 128-bit (16-byte) IV.
 *
 * Note: ZUC encryption and decryption are identical operations (XOR-based).
 * For actual use, always pair ZUC with HMAC-SM3 for integrity protection.
 * Avoid encrypting large amounts of data with the same key+IV combination.
 */
export class Zuc {
  static readonly KEY_SIZE = ZUC_KEY_SIZE;
  static readonly IV_SIZE = ZUC_IV_SIZE;

  private ctx: any;

  constructor() {
    this.ctx = new native.ZucContext();
  }

  /**
   * Initialize the ZUC cipher.
   * @param key - 16-byte key
   * @param iv - 16-byte initialization vector
   */
  init(key: Buffer, iv: Buffer): void {
    if (!Buffer.isBuffer(key)) {
      throw new Error('Expected key as Buffer');
    }
    if (key.length !== ZUC_KEY_SIZE) {
      throw new Error('Invalid key length');
    }
    if (!Buffer.isBuffer(iv)) {
      throw new Error('Expected iv as Buffer');
    }
    if (iv.length !== ZUC_IV_SIZE) {
      throw new Error('Invalid IV length');
    }
    this.ctx.init(key, iv);
  }

  /**
   * Process input data (encrypt or decrypt).
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
