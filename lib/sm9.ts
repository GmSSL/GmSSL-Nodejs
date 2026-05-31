/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';

const SM9_MAX_PLAINTEXT_SIZE = 255;

/**
 * SM9 Sign Master Key.
 *
 * SM9 is a Chinese national standard Identity-Based Cryptography (IBC)
 * algorithm. The master key is used to generate user keys for signing.
 */
export class Sm9SignMasterKey {
  private ctx: any;

  constructor() {
    this.ctx = new native.Sm9SignMasterKeyContext();
  }

  /**
   * Generate a new SM9 sign master key pair.
   */
  generateMasterKey(): void {
    this.ctx.generateMasterKey();
  }

  /**
   * Import an encrypted sign master key from a PEM file.
   * @param path - Path to the PEM file
   * @param pass - Password to decrypt the key
   */
  importEncryptedMasterKeyInfoPem(path: string, pass: string): void {
    this.ctx.importEncryptedMasterKeyInfoPem(path, pass);
  }

  /**
   * Export the sign master key to an encrypted PEM file.
   * @param path - Output file path
   * @param pass - Password to encrypt the key
   */
  exportEncryptedMasterKeyInfoPem(path: string, pass: string): void {
    this.ctx.exportEncryptedMasterKeyInfoPem(path, pass);
  }

  /**
   * Import a public sign master key from a PEM file.
   * @param path - Path to the PEM file
   */
  importPublicMasterKeyPem(path: string): void {
    this.ctx.importPublicMasterKeyPem(path);
  }

  /**
   * Export the public sign master key to a PEM file.
   * @param path - Output file path
   */
  exportPublicMasterKeyPem(path: string): void {
    this.ctx.exportPublicMasterKeyPem(path);
  }

  /**
   * Extract a user sign key for the given identity.
   * @param id - User identity string (max 63 bytes)
   * @returns Sm9SignKey for the user
   */
  extractKey(id: string): Sm9SignKey {
    const keyObj = this.ctx.extractKey(id);
    const key = new Sm9SignKey();
    key.setContext(keyObj, id);
    return key;
  }
}

/**
 * SM9 Sign Key (user key for signing).
 */
export class Sm9SignKey {
  private ctx: any;
  private id: string = '';

  constructor() {
  }

  /** @internal */
  setContext(ctx: any, id: string): void {
    this.ctx = ctx;
    this.id = id;
  }

  private ensureContext(): any {
    if (!this.ctx) {
      const native = require('./native').default;
      this.ctx = new native.Sm9SignKeyContext();
    }
    return this.ctx;
  }

  /**
   * Get the identity associated with this key.
   * @returns Identity string
   */
  getId(): string {
    return this.ctx.getId();
  }

  /**
   * Import an encrypted sign key from a PEM file.
   * @param path - Path to the PEM file
   * @param pass - Password to decrypt the key
   */
  importEncryptedPrivateKeyInfoPem(path: string, pass: string): void {
    this.ensureContext().importEncryptedPrivateKeyInfoPem(path, pass);
  }

  /**
   * Export the sign key to an encrypted PEM file.
   * @param path - Output file path
   * @param pass - Password to encrypt the key
   */
  exportEncryptedPrivateKeyInfoPem(path: string, pass: string): void {
    this.ensureContext().exportEncryptedPrivateKeyInfoPem(path, pass);
  }

  /** @internal */
  getContext(): any {
    return this.ensureContext();
  }
}

/**
 * SM9 Encryption Master Key.
 *
 * The master key is used to generate user keys for encryption/decryption.
 */
export class Sm9EncMasterKey {
  static readonly MAX_PLAINTEXT_SIZE = SM9_MAX_PLAINTEXT_SIZE;

  private ctx: any;

  constructor() {
    this.ctx = new native.Sm9EncMasterKeyContext();
  }

  /**
   * Generate a new SM9 encryption master key pair.
   */
  generateMasterKey(): void {
    this.ctx.generateMasterKey();
  }

  /**
   * Import an encrypted encryption master key from a PEM file.
   * @param path - Path to the PEM file
   * @param pass - Password to decrypt the key
   */
  importEncryptedMasterKeyInfoPem(path: string, pass: string): void {
    this.ctx.importEncryptedMasterKeyInfoPem(path, pass);
  }

  /**
   * Export the encryption master key to an encrypted PEM file.
   * @param path - Output file path
   * @param pass - Password to encrypt the key
   */
  exportEncryptedMasterKeyInfoPem(path: string, pass: string): void {
    this.ctx.exportEncryptedMasterKeyInfoPem(path, pass);
  }

  /**
   * Import a public encryption master key from a PEM file.
   * @param path - Path to the PEM file
   */
  importPublicMasterKeyPem(path: string): void {
    this.ctx.importPublicMasterKeyPem(path);
  }

  /**
   * Export the public encryption master key to a PEM file.
   * @param path - Output file path
   */
  exportPublicMasterKeyPem(path: string): void {
    this.ctx.exportPublicMasterKeyPem(path);
  }

  /**
   * Extract a user encryption key for the given identity.
   * @param id - User identity string
   * @returns Sm9EncKey for the user
   */
  extractKey(id: string): Sm9EncKey {
    const keyObj = this.ctx.extractKey(id);
    const key = new Sm9EncKey();
    key.setContext(keyObj, id);
    return key;
  }

  /**
   * Encrypt plaintext for a recipient identity.
   * @param plaintext - Data to encrypt (max 255 bytes)
   * @param toId - Recipient identity
   * @returns Encrypted ciphertext
   */
  encrypt(plaintext: Buffer, toId: string): Buffer {
    if (!Buffer.isBuffer(plaintext)) {
      throw new Error('Expected plaintext as Buffer');
    }
    if (plaintext.length > SM9_MAX_PLAINTEXT_SIZE) {
      throw new Error('Plaintext too long');
    }
    return Buffer.from(this.ctx.encrypt(plaintext, toId));
  }
}

/**
 * SM9 Encryption Key (user key for decryption).
 */
export class Sm9EncKey {
  private ctx: any;
  private id: string = '';

  constructor() {
  }

  /** @internal */
  setContext(ctx: any, id: string): void {
    this.ctx = ctx;
    this.id = id;
  }

  private ensureContext(): any {
    if (!this.ctx) {
      const native = require('./native').default;
      this.ctx = new native.Sm9EncKeyContext();
    }
    return this.ctx;
  }

  /**
   * Get the identity associated with this key.
   * @returns Identity string
   */
  getId(): string {
    return this.ensureContext().getId();
  }

  /**
   * Import an encrypted encryption key from a PEM file.
   * @param path - Path to the PEM file
   * @param pass - Password to decrypt the key
   */
  importEncryptedPrivateKeyInfoPem(path: string, pass: string): void {
    this.ensureContext().importEncryptedPrivateKeyInfoPem(path, pass);
  }

  /**
   * Export the encryption key to an encrypted PEM file.
   * @param path - Output file path
   * @param pass - Password to encrypt the key
   */
  exportEncryptedPrivateKeyInfoPem(path: string, pass: string): void {
    this.ensureContext().exportEncryptedPrivateKeyInfoPem(path, pass);
  }

  /**
   * Decrypt ciphertext using the user's encryption key.
   * @param ciphertext - Data to decrypt
   * @returns Decrypted plaintext
   */
  decrypt(ciphertext: Buffer): Buffer {
    if (!Buffer.isBuffer(ciphertext)) {
      throw new Error('Expected ciphertext as Buffer');
    }
    return Buffer.from(this.ensureContext().decrypt(ciphertext));
  }
}

/**
 * SM9 Signature context for streaming sign/verify operations.
 */
export class Sm9Signature {
  private ctx: any;

  constructor() {
    this.ctx = new native.Sm9SignatureContext();
  }

  /**
   * Initialize for signing or verification.
   * @param doSign - true for signing, false for verification
   */
  init(doSign: boolean): void {
    this.ctx.init(doSign);
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
   * @param signKey - Sm9SignKey to sign with
   * @returns SM9 signature (104 bytes)
   */
  sign(signKey: Sm9SignKey): Buffer {
    return Buffer.from(this.ctx.sign(signKey.getContext()));
  }

  /**
   * Finish verification and return result.
   * @param signature - Signature to verify
   * @param masterPublicKey - Sm9SignMasterKey (with public key loaded)
   * @param signerId - Identity of the signer
   * @returns true if signature is valid
   */
  verify(signature: Buffer, masterPublicKey: Sm9SignMasterKey, signerId: string): boolean {
    if (!Buffer.isBuffer(signature)) {
      throw new Error('Expected signature as Buffer');
    }
    return this.ctx.verify(signature, (masterPublicKey as any).ctx, signerId);
  }
}
