/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { Sm4, Sm4Cbc, Sm4Ctr, Sm4Gcm, Random } from '../lib';

describe('SM4', () => {
  test('SM4 encrypt known test vector', () => {
    const key = Buffer.from('1234567812345678');
    const plaintext = Buffer.from('block of message');
    const expectedHex = 'dd99d30fd7baf5af2930335d2554ddb7';

    const sm4 = new Sm4(key, true);
    const ciphertext = sm4.encrypt(plaintext);

    expect(ciphertext.toString('hex')).toBe(expectedHex);
  });

  test('SM4 encrypt and decrypt', () => {
    const key = Buffer.from('1234567812345678');
    const plaintext = Buffer.from('block of message');

    const sm4Enc = new Sm4(key, true);
    const ciphertext = sm4Enc.encrypt(plaintext);

    const sm4Dec = new Sm4(key, false);
    const decrypted = sm4Dec.encrypt(ciphertext);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM4 rejects invalid key length', () => {
    expect(() => new Sm4(Buffer.alloc(15), true)).toThrow();
    expect(() => new Sm4(Buffer.alloc(17), true)).toThrow();
  });

  test('SM4 rejects invalid block size', () => {
    const sm4 = new Sm4(Buffer.alloc(16, 0x41), true);
    expect(() => sm4.encrypt(Buffer.alloc(15))).toThrow();
  });
});

describe('SM4-CBC', () => {
  test('SM4-CBC encrypt and decrypt', () => {
    const key = Random.randBytes(Sm4Cbc.KEY_SIZE);
    const iv = Random.randBytes(Sm4Cbc.IV_SIZE);
    const plaintext = Buffer.from('Hello SM4-CBC mode! This is a test.');

    const enc = new Sm4Cbc();
    enc.init(key, iv, true);
    let ciphertext = enc.update(plaintext);
    const last1 = enc.finish();
    ciphertext = Buffer.concat([ciphertext, last1]);

    const dec = new Sm4Cbc();
    dec.init(key, iv, false);
    let decrypted = dec.update(ciphertext);
    const last2 = dec.finish();
    decrypted = Buffer.concat([decrypted, last2]);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM4-CBC wrong key fails decryption', () => {
    const key1 = Buffer.alloc(16, 0x11);
    const key2 = Buffer.alloc(16, 0x22);
    const iv = Random.randBytes(Sm4Cbc.IV_SIZE);
    const plaintext = Buffer.from('test data');

    const enc = new Sm4Cbc();
    enc.init(key1, iv, true);
    let ciphertext = enc.update(plaintext);
    const last = enc.finish();
    ciphertext = Buffer.concat([ciphertext, last]);

    const dec = new Sm4Cbc();
    dec.init(key2, iv, false);
    // Wrong key: either throws error (padding check) or produces wrong output
    try {
      const decrypted = dec.update(ciphertext);
      const decLast = dec.finish();
      const result = Buffer.concat([decrypted, decLast]);
      expect(result.equals(plaintext)).toBe(false);
    } catch (e) {
      // Error is also acceptable behavior
      expect(e).toBeDefined();
    }
  });
});

describe('SM4-CTR', () => {
  test('SM4-CTR encrypt and decrypt', () => {
    const key = Random.randBytes(Sm4Ctr.KEY_SIZE);
    const iv = Random.randBytes(Sm4Ctr.IV_SIZE);
    const plaintext = Buffer.from('Hello SM4-CTR mode! Testing stream cipher.');

    const enc = new Sm4Ctr();
    enc.init(key, iv);
    let ciphertext = enc.update(plaintext);
    const last1 = enc.finish();
    ciphertext = Buffer.concat([ciphertext, last1]);

    const dec = new Sm4Ctr();
    dec.init(key, iv);
    let decrypted = dec.update(ciphertext);
    const last2 = dec.finish();
    decrypted = Buffer.concat([decrypted, last2]);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM4-CTR small data', () => {
    const key = Random.randBytes(Sm4Ctr.KEY_SIZE);
    const iv = Random.randBytes(Sm4Ctr.IV_SIZE);
    const plaintext = Buffer.from('ab');

    const enc = new Sm4Ctr();
    enc.init(key, iv);
    const ciphertext = Buffer.concat([enc.update(plaintext), enc.finish()]);

    const dec = new Sm4Ctr();
    dec.init(key, iv);
    const decrypted = Buffer.concat([dec.update(ciphertext), dec.finish()]);

    expect(decrypted.equals(plaintext)).toBe(true);
  });
});

describe('SM4-GCM', () => {
  test('SM4-GCM encrypt and decrypt', () => {
    const key = Random.randBytes(Sm4Gcm.KEY_SIZE);
    const iv = Random.randBytes(Sm4Gcm.DEFAULT_IV_SIZE);
    const aad = Buffer.from('Additional Authenticated-only Data');
    const plaintext = Buffer.from('Hello SM4-GCM mode! Authenticated encryption.');

    const enc = new Sm4Gcm();
    enc.init(key, iv, aad, Sm4Gcm.DEFAULT_TAG_SIZE, true);
    let ciphertext = enc.update(plaintext);
    const last1 = enc.finish();
    ciphertext = Buffer.concat([ciphertext, last1]);

    const dec = new Sm4Gcm();
    dec.init(key, iv, aad, Sm4Gcm.DEFAULT_TAG_SIZE, false);
    let decrypted = dec.update(ciphertext);
    const last2 = dec.finish();
    decrypted = Buffer.concat([decrypted, last2]);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM4-GCM tampered ciphertext fails decryption', () => {
    const key = Random.randBytes(Sm4Gcm.KEY_SIZE);
    const iv = Random.randBytes(Sm4Gcm.DEFAULT_IV_SIZE);
    const aad = Buffer.from('AAD');
    const plaintext = Buffer.from('sensitive data');

    const enc = new Sm4Gcm();
    enc.init(key, iv, aad, Sm4Gcm.DEFAULT_TAG_SIZE, true);
    let ciphertext = enc.update(plaintext);
    const last = enc.finish();
    ciphertext = Buffer.concat([ciphertext, last]);

    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;

    const dec = new Sm4Gcm();
    dec.init(key, iv, aad, Sm4Gcm.DEFAULT_TAG_SIZE, false);
    expect(() => {
      dec.update(ciphertext);
      dec.finish();
    }).toThrow();
  });
});
