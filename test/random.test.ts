/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { Random, versionNum, versionStr, GMSSL_NODEJS_VERSION } from '../lib';

describe('Random', () => {
  test('Generate random bytes', () => {
    const bytes = Random.randBytes(32);
    expect(bytes.length).toBe(32);
    expect(Buffer.isBuffer(bytes)).toBe(true);
  });

  test('Generate random bytes of various lengths', () => {
    for (const len of [1, 16, 32, 64, 128]) {
      const bytes = Random.randBytes(len);
      expect(bytes.length).toBe(len);
    }
  });

  test('Random bytes should be unique', () => {
    const a = Random.randBytes(32);
    const b = Random.randBytes(32);
    // Extremely unlikely to collide for 32 random bytes
    expect(a.equals(b)).toBe(false);
  });
});

describe('Version', () => {
  test('versionNum returns a number', () => {
    const ver = versionNum();
    expect(typeof ver).toBe('number');
    expect(ver).toBeGreaterThan(0);
  });

  test('versionStr returns a string', () => {
    const ver = versionStr();
    expect(typeof ver).toBe('string');
    expect(ver.length).toBeGreaterThan(0);
  });

  test('GMSSL_NODEJS_VERSION is defined', () => {
    expect(typeof GMSSL_NODEJS_VERSION).toBe('string');
    expect(GMSSL_NODEJS_VERSION).toContain('GmSSL');
  });
});
