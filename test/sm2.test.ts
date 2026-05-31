/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { Sm2Key, Sm2Signature, Sm3, Random } from '../lib';
import * as fs from 'fs';

describe('SM2 Key', () => {
  test('SM2 generate key and compute Z', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const z = sm2.computeZ(Sm2Key.DEFAULT_ID);
    expect(z.length).toBe(32);
  });

  test('SM2 sign and verify', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    // Compute SM3 hash of data
    const sm3 = new Sm3();
    sm3.update(Buffer.from('hello sm2'));
    const dgst = sm3.digest();

    // Sign with private key
    const signature = sm2.sign(dgst);
    expect(signature.length).toBeGreaterThan(0);

    // Verify signature
    const verified = sm2.verify(dgst, signature);
    expect(verified).toBe(true);
  });

  test('SM2 verify wrong digest fails', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const dgst = Random.randBytes(32);
    const signature = sm2.sign(dgst);

    const wrongDgst = Random.randBytes(32);
    const verified = sm2.verify(wrongDgst, signature);
    expect(verified).toBe(false);
  });

  test('SM2 verify tampered signature fails', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const sm3 = new Sm3();
    sm3.update(Buffer.from('test message'));
    const dgst = sm3.digest();

    const signature = sm2.sign(dgst);

    // Tamper with signature
    const tamperedSig = Buffer.from(signature);
    tamperedSig[0] ^= 0x01;

    const verified = sm2.verify(dgst, tamperedSig);
    expect(verified).toBe(false);
  });

  test('SM2 encrypt and decrypt', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const plaintext = Buffer.from('Hello SM2!');
    const ciphertext = sm2.encrypt(plaintext);
    const decrypted = sm2.decrypt(ciphertext);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM2 encrypt and decrypt small message', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const plaintext = Buffer.from('x');
    const ciphertext = sm2.encrypt(plaintext);
    const decrypted = sm2.decrypt(ciphertext);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM2 PEM import/export', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const pemPass = 'Password';
    const priPem = '/tmp/sm2_test_pri.pem';
    const pubPem = '/tmp/sm2_test_pub.pem';

    // Export
    sm2.exportEncryptedPrivateKeyInfoPem(pemPass, priPem);
    sm2.exportPublicKeyInfoPem(pubPem);

    // Import private key
    const sm2pri = new Sm2Key();
    sm2pri.importEncryptedPrivateKeyInfoPem(pemPass, priPem);

    // Import public key
    const sm2pub = new Sm2Key();
    sm2pub.importPublicKeyInfoPem(pubPem);

    // Sign with imported private key
    const sm3 = new Sm3();
    sm3.update(Buffer.from('pem test'));
    const dgst = sm3.digest();
    const sig = sm2pri.sign(dgst);

    // Verify with imported public key
    expect(sm2pub.verify(dgst, sig)).toBe(true);

    // Cleanup
    try { fs.unlinkSync(priPem); } catch (e) {}
    try { fs.unlinkSync(pubPem); } catch (e) {}
  });

  test('SM2 DER import/export', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const priDer = sm2.exportPrivateKeyInfoDer();
    const pubDer = sm2.exportPublicKeyInfoDer();

    const sm2pri = new Sm2Key();
    sm2pri.importPrivateKeyInfoDer(priDer);

    const sm2pub = new Sm2Key();
    sm2pub.importPublicKeyInfoDer(pubDer);

    const sm3 = new Sm3();
    sm3.update(Buffer.from('der test'));
    const dgst = sm3.digest();
    const sig = sm2pri.sign(dgst);

    expect(sm2pub.verify(dgst, sig)).toBe(true);
  });

  test('SM2 compute Z consistency', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const z1 = sm2.computeZ(Sm2Key.DEFAULT_ID);
    const z2 = sm2.computeZ(Sm2Key.DEFAULT_ID);

    expect(z1.equals(z2)).toBe(true);
  });
});

describe('SM2 Signature (streaming)', () => {
  test('SM2 streaming sign and verify', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    // Streaming sign
    const signCtx = new Sm2Signature();
    signCtx.init(sm2, Sm2Signature.DEFAULT_ID, true);
    signCtx.update(Buffer.from('hello '));
    signCtx.update(Buffer.from('world'));
    const signature = signCtx.sign();

    // Streaming verify
    const verifyCtx = new Sm2Signature();
    verifyCtx.init(sm2, Sm2Signature.DEFAULT_ID, false);
    verifyCtx.update(Buffer.from('hello '));
    verifyCtx.update(Buffer.from('world'));
    const result = verifyCtx.verify(signature);

    expect(result).toBe(true);
  });

  test('SM2 streaming verify wrong data fails', () => {
    const sm2 = new Sm2Key();
    sm2.generateKey();

    const signCtx = new Sm2Signature();
    signCtx.init(sm2, Sm2Signature.DEFAULT_ID, true);
    signCtx.update(Buffer.from('original data'));
    const signature = signCtx.sign();

    const verifyCtx = new Sm2Signature();
    verifyCtx.init(sm2, Sm2Signature.DEFAULT_ID, false);
    verifyCtx.update(Buffer.from('different data'));
    const result = verifyCtx.verify(signature);

    expect(result).toBe(false);
  });
});
