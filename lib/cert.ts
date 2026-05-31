/**
 * Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

import native from './native';
import { Sm2Key } from './sm2';

const SM2_DEFAULT_ID = '1234567812345678';

/**
 * SM2 X.509 Certificate.
 *
 * Supports parsing, validation, and key extraction from X.509 certificates
 * that use the SM2 curve for public key cryptography.
 */
export class Sm2Certificate {
  private cert: Buffer | null;

  constructor() {
    this.cert = null;
  }

  /**
   * Get the raw certificate bytes.
   * @returns DER-encoded certificate
   */
  getBytes(): Buffer {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return this.cert;
  }

  /**
   * Import a certificate from a PEM file.
   * @param path - Path to the PEM file
   */
  importPem(path: string): void {
    this.cert = Buffer.from(native.certFromPem(path));
  }

  /**
   * Export the certificate to a PEM file.
   * @param path - Output file path
   */
  exportPem(path: string): void {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    native.certToPem(this.cert, path);
  }

  /**
   * Get the certificate serial number.
   * @returns Serial number as Buffer
   */
  getSerialNumber(): Buffer {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return Buffer.from(native.certGetSerialNumber(this.cert));
  }

  /**
   * Get the issuer distinguished name.
   * @returns Issuer info as DER-encoded Buffer
   */
  getIssuer(): Buffer {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return Buffer.from(native.certGetIssuer(this.cert));
  }

  /**
   * Get the subject distinguished name.
   * @returns Subject info as DER-encoded Buffer
   */
  getSubject(): Buffer {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return Buffer.from(native.certGetSubject(this.cert));
  }

  /**
   * Get the notBefore validity date.
   * @returns Unix timestamp (seconds)
   */
  getNotBefore(): number {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return native.certGetNotBefore(this.cert);
  }

  /**
   * Get the notAfter validity date.
   * @returns Unix timestamp (seconds)
   */
  getNotAfter(): number {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return native.certGetNotAfter(this.cert);
  }

  /**
   * Extract the subject's SM2 public key from the certificate.
   * @returns Sm2Key with the public key loaded
   */
  getSubjectPublicKey(): Sm2Key {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    const key = new Sm2Key();
    // Directly assign the native context
    (key as any).ctx = native.certGetSubjectPublicKey(this.cert);
    return key;
  }

  /**
   * Verify this certificate against a CA certificate.
   * @param caCert - The CA certificate to verify against
   * @param sm2Id - SM2 ID for verification (default: "1234567812345678")
   * @returns true if verification succeeds
   */
  verifyByCaCertificate(caCert: Sm2Certificate, sm2Id: string = SM2_DEFAULT_ID): boolean {
    if (!this.cert) {
      throw new Error('Certificate not loaded');
    }
    return native.certVerifyByCaCert(this.cert, caCert.getBytes(), sm2Id);
  }
}
