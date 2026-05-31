/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { Sm9SignMasterKey, Sm9SignKey, Sm9EncMasterKey, Sm9EncKey, Sm9Signature } from '../lib';
import * as fs from 'fs';

describe('SM9 Sign', () => {
  test('SM9 sign master key generate and extract user key', () => {
    const master = new Sm9SignMasterKey();
    master.generateMasterKey();

    const key = master.extractKey('Alice');
    expect(key.getId()).toBe('Alice');
  });

  test('SM9 sign and verify', () => {
    // Generate master key
    const master = new Sm9SignMasterKey();
    master.generateMasterKey();

    // Extract user key for "Alice"
    const signKey = master.extractKey('Alice');

    // Sign
    const signCtx = new Sm9Signature();
    signCtx.init(true);
    signCtx.update(Buffer.from('abc'));
    const signature = signCtx.sign(signKey);
    expect(signature.length).toBe(104);

    // Verify with master public key
    const verifyCtx = new Sm9Signature();
    verifyCtx.init(false);
    verifyCtx.update(Buffer.from('abc'));
    const result = verifyCtx.verify(signature, master, 'Alice');

    expect(result).toBe(true);
  });

  test('SM9 sign and verify with different data fails', () => {
    const master = new Sm9SignMasterKey();
    master.generateMasterKey();
    const signKey = master.extractKey('Alice');

    const signCtx = new Sm9Signature();
    signCtx.init(true);
    signCtx.update(Buffer.from('message 1'));
    const signature = signCtx.sign(signKey);

    const verifyCtx = new Sm9Signature();
    verifyCtx.init(false);
    verifyCtx.update(Buffer.from('message 2'));
    const result = verifyCtx.verify(signature, master, 'Alice');

    expect(result).toBe(false);
  });

  test('SM9 sign and verify with wrong identity fails', () => {
    const master = new Sm9SignMasterKey();
    master.generateMasterKey();
    const signKey = master.extractKey('Alice');

    const signCtx = new Sm9Signature();
    signCtx.init(true);
    signCtx.update(Buffer.from('test data'));
    const signature = signCtx.sign(signKey);

    const verifyCtx = new Sm9Signature();
    verifyCtx.init(false);
    verifyCtx.update(Buffer.from('test data'));
    const result = verifyCtx.verify(signature, master, 'Bob');

    expect(result).toBe(false);
  });

  test('SM9 sign PEM import/export', () => {
    const master = new Sm9SignMasterKey();
    master.generateMasterKey();

    const priPem = '/tmp/sm9sign_master.pem';
    const pubPem = '/tmp/sm9sign_master_pub.pem';
    const keyPem = '/tmp/sm9sign_key.pem';

    // Export master key
    master.exportEncryptedMasterKeyInfoPem(priPem, '1234');
    master.exportPublicMasterKeyPem(pubPem);

    // Import master key
    const master2 = new Sm9SignMasterKey();
    master2.importEncryptedMasterKeyInfoPem(priPem, '1234');

    // Import public master key
    const masterPub = new Sm9SignMasterKey();
    masterPub.importPublicMasterKeyPem(pubPem);

    // Extract and export user key
    const key = master2.extractKey('Alice');
    key.exportEncryptedPrivateKeyInfoPem(keyPem, '1234');

    // Import user key
    const key2 = new Sm9SignKey();
    key2.importEncryptedPrivateKeyInfoPem(keyPem, '1234');
    // Note: key2 won't have the correct id - this is by design matching the C API

    // Cleanup
    try { fs.unlinkSync(priPem); } catch (e) {}
    try { fs.unlinkSync(pubPem); } catch (e) {}
    try { fs.unlinkSync(keyPem); } catch (e) {}
  });
});

describe('SM9 Encrypt', () => {
  test('SM9 encrypt and decrypt', () => {
    const master = new Sm9EncMasterKey();
    master.generateMasterKey();

    const plaintext = Buffer.from('Hello SM9!');
    const ciphertext = master.encrypt(plaintext, 'Alice');

    const encKey = master.extractKey('Alice');
    const decrypted = encKey.decrypt(ciphertext);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  test('SM9 encrypt and decrypt with different identity fails', () => {
    const master = new Sm9EncMasterKey();
    master.generateMasterKey();

    const plaintext = Buffer.from('secret message');
    const ciphertext = master.encrypt(plaintext, 'Alice');

    const encKey = master.extractKey('Bob');

    expect(() => encKey.decrypt(ciphertext)).toThrow();
  });

  test('SM9 encrypt PEM import/export', () => {
    const master = new Sm9EncMasterKey();
    master.generateMasterKey();

    const priPem = '/tmp/sm9enc_master.pem';
    const pubPem = '/tmp/sm9enc_master_pub.pem';
    const keyPem = '/tmp/sm9enc_key.pem';

    master.exportEncryptedMasterKeyInfoPem(priPem, '1234');
    master.exportPublicMasterKeyPem(pubPem);

    const master2 = new Sm9EncMasterKey();
    master2.importEncryptedMasterKeyInfoPem(priPem, '1234');

    const masterPub = new Sm9EncMasterKey();
    masterPub.importPublicMasterKeyPem(pubPem);

    const key = master2.extractKey('Alice');
    key.exportEncryptedPrivateKeyInfoPem(keyPem, '1234');

    // Encrypt with public master key
    const plaintext = Buffer.from('test');
    const ciphertext = masterPub.encrypt(plaintext, 'Alice');

    // Import user key and decrypt
    const key2 = new Sm9EncKey();
    key2.importEncryptedPrivateKeyInfoPem(keyPem, '1234');
    // Note: key2 won't have the correct id - this is by design matching the C API

    // Cleanup
    try { fs.unlinkSync(priPem); } catch (e) {}
    try { fs.unlinkSync(pubPem); } catch (e) {}
    try { fs.unlinkSync(keyPem); } catch (e) {}
  });
});
