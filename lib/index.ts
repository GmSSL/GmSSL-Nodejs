/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import native from './native';

// Re-export constants
export const SM3_DIGEST_SIZE: number = native.SM3_DIGEST_SIZE;
export const SM3_HMAC_MIN_KEY_SIZE: number = native.SM3_HMAC_MIN_KEY_SIZE;
export const SM3_HMAC_MAX_KEY_SIZE: number = native.SM3_HMAC_MAX_KEY_SIZE;
export const SM3_HMAC_SIZE: number = native.SM3_HMAC_SIZE;
export const SM3_PBKDF2_MIN_ITER: number = native.SM3_PBKDF2_MIN_ITER;
export const SM3_PBKDF2_MAX_ITER: number = native.SM3_PBKDF2_MAX_ITER;
export const SM3_PBKDF2_MAX_SALT_SIZE: number = native.SM3_PBKDF2_MAX_SALT_SIZE;
export const SM3_PBKDF2_DEFAULT_SALT_SIZE: number = native.SM3_PBKDF2_DEFAULT_SALT_SIZE;
export const SM3_PBKDF2_MAX_KEY_SIZE: number = native.SM3_PBKDF2_MAX_KEY_SIZE;
export const SM4_KEY_SIZE: number = native.SM4_KEY_SIZE;
export const SM4_BLOCK_SIZE: number = native.SM4_BLOCK_SIZE;
export const SM4_CBC_IV_SIZE: number = native.SM4_CBC_IV_SIZE;
export const SM4_CTR_IV_SIZE: number = native.SM4_CTR_IV_SIZE;
export const SM4_GCM_MIN_IV_SIZE: number = native.SM4_GCM_MIN_IV_SIZE;
export const SM4_GCM_MAX_IV_SIZE: number = native.SM4_GCM_MAX_IV_SIZE;
export const SM4_GCM_DEFAULT_IV_SIZE: number = native.SM4_GCM_DEFAULT_IV_SIZE;
export const SM4_GCM_DEFAULT_TAG_SIZE: number = native.SM4_GCM_DEFAULT_TAG_SIZE;
export const SM4_GCM_MAX_TAG_SIZE: number = native.SM4_GCM_MAX_TAG_SIZE;
export const SM2_DEFAULT_ID: string = native.SM2_DEFAULT_ID;
export const SM2_MAX_SIGNATURE_SIZE: number = native.SM2_MAX_SIGNATURE_SIZE;
export const SM2_MIN_PLAINTEXT_SIZE: number = native.SM2_MIN_PLAINTEXT_SIZE;
export const SM2_MAX_PLAINTEXT_SIZE: number = native.SM2_MAX_PLAINTEXT_SIZE;
export const SM2_MIN_CIPHERTEXT_SIZE: number = native.SM2_MIN_CIPHERTEXT_SIZE;
export const SM2_MAX_CIPHERTEXT_SIZE: number = native.SM2_MAX_CIPHERTEXT_SIZE;
export const SM9_MAX_ID_SIZE: number = native.SM9_MAX_ID_SIZE;
export const SM9_MAX_PLAINTEXT_SIZE: number = native.SM9_MAX_PLAINTEXT_SIZE;
export const SM9_MAX_CIPHERTEXT_SIZE: number = native.SM9_MAX_CIPHERTEXT_SIZE;
export const SM9_SIGNATURE_SIZE: number = native.SM9_SIGNATURE_SIZE;
export const ZUC_KEY_SIZE: number = native.ZUC_KEY_SIZE;
export const ZUC_IV_SIZE: number = native.ZUC_IV_SIZE;

export const GMSSL_NODEJS_VERSION: string = native.GMSSL_NODEJS_VERSION;

/**
 * Get GmSSL library version number
 */
export function versionNum(): number {
  return native.versionNum();
}

/**
 * Get GmSSL library version string
 */
export function versionStr(): string {
  return native.versionStr();
}

// Algorithm classes
export { Random } from './random';
export { Sm3, Sm3Hmac, Sm3Pbkdf2 } from './sm3';
export { Sm4, Sm4Cbc, Sm4Ctr, Sm4Gcm } from './sm4';
export { Sm2Key, Sm2Signature } from './sm2';
export { Sm9SignMasterKey, Sm9SignKey, Sm9EncMasterKey, Sm9EncKey, Sm9Signature } from './sm9';
export { Zuc } from './zuc';
export { Sm2Certificate } from './cert';
