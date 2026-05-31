/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';

/**
 * Generate cryptographically secure random bytes.
 */
export class Random {
  /**
   * Generate random bytes.
   * @param length - Number of random bytes to generate
   * @returns Buffer of random bytes
   */
  static randBytes(length: number): Buffer {
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error('Invalid length');
    }
    return Buffer.from(native.randBytes(length));
  }
}
