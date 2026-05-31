/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { Zuc, Random } from '../lib';

describe('ZUC', () => {
  test('ZUC encrypt and decrypt', () => {
    const key = Random.randBytes(Zuc.KEY_SIZE);
    const iv = Random.randBytes(Zuc.IV_SIZE);
    const plaintext = Buffer.from('Hello ZUC stream cipher! This is test data for encryption.');

    const zucEnc = new Zuc();
    zucEnc.init(key, iv);
    let ciphertext = zucEnc.update(plaintext);
    const last1 = zucEnc.finish();
    ciphertext = Buffer.concat([ciphertext, last1]);

    const zucDec = new Zuc();
    zucDec.init(key, iv);
    let decrypted = zucDec.update(ciphertext);
    const last2 = zucDec.finish();
    decrypted = Buffer.concat([decrypted, last2]);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('ZUC small data', () => {
    const key = Random.randBytes(Zuc.KEY_SIZE);
    const iv = Random.randBytes(Zuc.IV_SIZE);
    const plaintext = Buffer.from('x');

    const zuc = new Zuc();
    zuc.init(key, iv);
    const ciphertext = Buffer.concat([zuc.update(plaintext), zuc.finish()]);

    const zuc2 = new Zuc();
    zuc2.init(key, iv);
    const decrypted = Buffer.concat([zuc2.update(ciphertext), zuc2.finish()]);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('ZUC wrong key produces different output', () => {
    const key1 = Buffer.alloc(Zuc.KEY_SIZE, 0x11);
    const key2 = Buffer.alloc(Zuc.KEY_SIZE, 0x22);
    const iv = Random.randBytes(Zuc.IV_SIZE);
    const plaintext = Buffer.from('test message');

    const zuc1 = new Zuc();
    zuc1.init(key1, iv);
    const ciphertext = Buffer.concat([zuc1.update(plaintext), zuc1.finish()]);

    const zuc2 = new Zuc();
    zuc2.init(key2, iv);
    const decrypted = Buffer.concat([zuc2.update(ciphertext), zuc2.finish()]);

    expect(decrypted.equals(plaintext)).toBe(false);
  });

  test('ZUC rejects invalid key/IV length', () => {
    const zuc = new Zuc();

    expect(() => zuc.init(Buffer.alloc(15), Buffer.alloc(16))).toThrow();
    expect(() => zuc.init(Buffer.alloc(16), Buffer.alloc(8))).toThrow();
  });
});
