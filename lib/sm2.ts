/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';

const SM2_DEFAULT_ID = '1234567812345678';
const SM2_MAX_PLAINTEXT_SIZE = 255;
const SM2_MAX_SIGNATURE_SIZE = 72;
const SM3_DIGEST_SIZE = 32;

/**
 * SM2 key pair for signing/verification and encryption/decryption.
 *
 * SM2 is a Chinese national standard elliptic curve public key
 * cryptographic algorithm based on the SM2 curve.
 */
export class Sm2Key {
  static readonly DEFAULT_ID = SM2_DEFAULT_ID;
  static readonly MAX_PLAINTEXT_SIZE = SM2_MAX_PLAINTEXT_SIZE;

  private ctx: any;

  constructor() {
    this.ctx = new native.Sm2KeyContext();
  }

  /**
   * Generate a new SM2 key pair.
   */
  generateKey(): void {
    this.ctx.generateKey();
  }

  /**
   * Import a private key from DER-encoded data.
   * @param der - DER-encoded private key info
   */
  importPrivateKeyInfoDer(der: Buffer): void {
    if (!Buffer.isBuffer(der)) {
      throw new Error('Expected DER data as Buffer');
    }
    this.ctx.importPrivateKeyInfoDer(der);
  }

  /**
   * Export the private key as DER-encoded data.
   * @returns DER-encoded private key info
   */
  exportPrivateKeyInfoDer(): Buffer {
    return Buffer.from(this.ctx.exportPrivateKeyInfoDer());
  }

  /**
   * Import a public key from DER-encoded data.
   * @param der - DER-encoded public key info
   */
  importPublicKeyInfoDer(der: Buffer): void {
    if (!Buffer.isBuffer(der)) {
      throw new Error('Expected DER data as Buffer');
    }
    this.ctx.importPublicKeyInfoDer(der);
  }

  /**
   * Export the public key as DER-encoded data.
   * @returns DER-encoded public key info
   */
  exportPublicKeyInfoDer(): Buffer {
    return Buffer.from(this.ctx.exportPublicKeyInfoDer());
  }

  /**
   * Import an encrypted private key from a PEM file.
   * @param password - Password to decrypt the key
   * @param path - Path to the PEM file
   */
  importEncryptedPrivateKeyInfoPem(password: string, path: string): void {
    this.ctx.importEncryptedPrivateKeyInfoPem(password, path);
  }

  /**
   * Export the private key to an encrypted PEM file.
   * @param password - Password to encrypt the key
   * @param path - Output file path
   */
  exportEncryptedPrivateKeyInfoPem(password: string, path: string): void {
    this.ctx.exportEncryptedPrivateKeyInfoPem(password, path);
  }

  /**
   * Import a public key from a PEM file.
   * @param path - Path to the PEM file
   */
  importPublicKeyInfoPem(path: string): void {
    this.ctx.importPublicKeyInfoPem(path);
  }

  /**
   * Export the public key to a PEM file.
   * @param path - Output file path
   */
  exportPublicKeyInfoPem(path: string): void {
    this.ctx.exportPublicKeyInfoPem(path);
  }

  /**
   * Compute the SM2 Z value for a given ID.
   * @param id - Signer identifier string (default: "1234567812345678")
   * @returns 32-byte hash value Z
   */
  computeZ(id: string = SM2_DEFAULT_ID): Buffer {
    return Buffer.from(this.ctx.computeZ(id));
  }

  /**
   * Sign a digest using the SM2 private key.
   * @param dgst - 32-byte SM3 digest to sign
   * @returns SM2 signature (DER-encoded, variable length)
   */
  sign(dgst: Buffer): Buffer {
    if (!Buffer.isBuffer(dgst)) {
      throw new Error('Expected digest as Buffer');
    }
    if (dgst.length !== SM3_DIGEST_SIZE) {
      throw new Error('Invalid digest size');
    }
    return Buffer.from(this.ctx.sign(dgst));
  }

  /**
   * Verify an SM2 signature against a digest.
   * @param dgst - 32-byte SM3 digest
   * @param signature - Signature to verify
   * @returns true if signature is valid
   */
  verify(dgst: Buffer, signature: Buffer): boolean {
    if (!Buffer.isBuffer(dgst) || !Buffer.isBuffer(signature)) {
      throw new Error('Expected digest and signature as Buffer');
    }
    if (dgst.length !== SM3_DIGEST_SIZE) {
      return false;
    }
    return this.ctx.verify(dgst, signature);
  }

  /**
   * Encrypt plaintext using the SM2 public key.
   * @param plaintext - Data to encrypt (max 255 bytes)
   * @returns Encrypted ciphertext
   */
  encrypt(plaintext: Buffer): Buffer {
    if (!Buffer.isBuffer(plaintext)) {
      throw new Error('Expected plaintext as Buffer');
    }
    if (plaintext.length > SM2_MAX_PLAINTEXT_SIZE) {
      throw new Error('Plaintext too long');
    }
    return Buffer.from(this.ctx.encrypt(plaintext));
  }

  /**
   * Decrypt ciphertext using the SM2 private key.
   * @param ciphertext - Data to decrypt
   * @returns Decrypted plaintext
   */
  decrypt(ciphertext: Buffer): Buffer {
    if (!Buffer.isBuffer(ciphertext)) {
      throw new Error('Expected ciphertext as Buffer');
    }
    return Buffer.from(this.ctx.decrypt(ciphertext));
  }
}

/**
 * SM2 Signature context for streaming sign/verify operations.
 */
export class Sm2Signature {
  static readonly DEFAULT_ID = SM2_DEFAULT_ID;

  private ctx: any;

  constructor() {
    this.ctx = new native.Sm2SignatureContext();
  }

  /**
   * Initialize for signing or verification.
   * @param key - Sm2Key (must have private key for signing)
   * @param id - Signer identifier
   * @param doSign - true for signing, false for verification
   */
  init(key: Sm2Key, id: string, doSign: boolean): void {
    this.ctx.init((key as any).ctx, id, doSign);
  }

  /**
   * Update with data to sign/verify.
   * @param data - Data to process
   */
  update(data: Buffer): void {
    if (!Buffer.isBuffer(data)) {
      throw new Error('Expected data as Buffer');
    }
    if (data.length > 0) {
      this.ctx.update(data);
    }
  }

  /**
   * Finish signing and return the signature.
   * @returns SM2 signature (DER-encoded)
   */
  sign(): Buffer {
    return Buffer.from(this.ctx.sign());
  }

  /**
   * Finish verification and return result.
   * @param signature - Signature to verify
   * @returns true if signature is valid
   */
  verify(signature: Buffer): boolean {
    if (!Buffer.isBuffer(signature)) {
      throw new Error('Expected signature as Buffer');
    }
    return this.ctx.verify(signature);
  }
}
