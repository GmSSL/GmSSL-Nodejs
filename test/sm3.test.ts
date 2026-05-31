/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { Sm3, Sm3Hmac, Sm3Pbkdf2, Random } from '../lib';

describe('SM3', () => {
  test('SM3 hash of "abc"', () => {
    const expectedHex = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';

    const sm3 = new Sm3();
    sm3.update(Buffer.from('abc'));
    const dgst = sm3.digest();

    expect(dgst.toString('hex')).toBe(expectedHex);
  });

  test('SM3 empty hash', () => {
    const expectedHex = '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b';

    const sm3 = new Sm3();
    const dgst = sm3.digest();

    expect(dgst.toString('hex')).toBe(expectedHex);
  });

  test('SM3 incremental update', () => {
    const sm3a = new Sm3();
    sm3a.update(Buffer.from('hello '));
    sm3a.update(Buffer.from('world'));
    const dgst1 = sm3a.digest();

    const sm3b = new Sm3();
    sm3b.update(Buffer.from('hello world'));
    const dgst2 = sm3b.digest();

    expect(dgst1.equals(dgst2)).toBe(true);
  });

  test('SM3 reset', () => {
    const expectedHex = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';

    const sm3 = new Sm3();
    sm3.update(Buffer.from('abc'));
    expect(sm3.digest().toString('hex')).toBe(expectedHex);

    // Reset and use again
    sm3.reset();
    sm3.update(Buffer.from('abc'));
    expect(sm3.digest().toString('hex')).toBe(expectedHex);
  });

  test('SM3 hash of long message', () => {
    const data = Buffer.alloc(1024, 0x41); // 1024 'A's
    const sm3 = new Sm3();
    sm3.update(data);
    const dgst = sm3.digest();
    expect(dgst.length).toBe(32);
  });
});

describe('SM3 HMAC', () => {
  test('HMAC-SM3 with known test vector', () => {
    const key = Buffer.from('1234567812345678');
    const expectedHex = '0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080';

    const hmac = new Sm3Hmac(key);
    hmac.update(Buffer.from('abc'));
    const mac = hmac.generateMac();

    expect(mac.toString('hex')).toBe(expectedHex);
  });

  test('HMAC-SM3 reset with new key', () => {
    const key1 = Buffer.from('1234567812345678');
    const key2 = Buffer.from('8765432187654321');

    const hmac = new Sm3Hmac(key1);
    hmac.update(Buffer.from('test'));
    const mac1 = hmac.generateMac();

    hmac.reset(key2);
    hmac.update(Buffer.from('test'));
    const mac2 = hmac.generateMac();

    expect(mac1.equals(mac2)).toBe(false);
  });

  test('HMAC-SM3 rejects invalid key lengths', () => {
    // Too short
    expect(() => new Sm3Hmac(Buffer.alloc(8))).toThrow();
    // Too long
    expect(() => new Sm3Hmac(Buffer.alloc(65))).toThrow();
  });
});

describe('SM3 PBKDF2', () => {
  test('PBKDF2-SM3 with known test vector', () => {
    const passwd = 'password';
    const salt = Buffer.from('12345678');
    const iter = 10000;
    const keylen = 32;
    const expectedHex = 'ac5b4a93a130252181434970fa9d8e6f1083badecafc4409aaf0097c813e9fc6';

    const key = Sm3Pbkdf2.deriveKey(passwd, salt, iter, keylen);

    expect(key.toString('hex')).toBe(expectedHex);
  });

  test('PBKDF2-SM3 with different passwords give different keys', () => {
    const salt = Random.randBytes(8);
    const iter = 10000;
    const keylen = 16;

    const key1 = Sm3Pbkdf2.deriveKey('password1', salt, iter, keylen);
    const key2 = Sm3Pbkdf2.deriveKey('password2', salt, iter, keylen);

    expect(key1.equals(key2)).toBe(false);
  });
});
