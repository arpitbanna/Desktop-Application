/**
 * TrustRoot Mobile - Cryptographic Utilities
 * Safe CSPRNG, SHA-256 digests, Base64 conversions, and Canonical Signing formatting.
 * NEVER uses Math.random() for any cryptographic secrets or identifiers.
 */

import * as crypto from 'crypto';

/**
 * Generate cryptographically secure random bytes using CSPRNG
 */
export function getSecureRandomBytes(byteCount: number): Uint8Array {
  if (typeof crypto !== 'undefined' && crypto.randomBytes) {
    return new Uint8Array(crypto.randomBytes(byteCount));
  }
  // WebCrypto fallback for standard environments
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
    const array = new Uint8Array(byteCount);
    globalThis.crypto.getRandomValues(array);
    return array;
  }
  throw new Error('FATAL: No certified CSPRNG available in execution environment.');
}

/**
 * Generate a cryptographically secure random UUID v4
 */
export function generateSecureUUID(): string {
  const bytes = getSecureRandomBytes(16);
  // Set version to 0100 (v4)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant to 10xx (RFC 4122)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  
  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Compute SHA-256 hash of a buffer or string, returning hex string
 */
export function sha256Hex(data: Uint8Array | string): string {
  const hash = crypto.createHash('sha256');
  if (typeof data === 'string') {
    hash.update(data, 'utf8');
  } else {
    hash.update(data);
  }
  return hash.digest('hex');
}

/**
 * Compute SHA-256 hash returning raw bytes
 */
export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  const hash = crypto.createHash('sha256');
  if (typeof data === 'string') {
    hash.update(data, 'utf8');
  } else {
    hash.update(data);
  }
  return new Uint8Array(hash.digest());
}

/**
 * Encode Uint8Array to RFC 4648 standard Base64
 */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Decode Base64 string to Uint8Array
 */
export function fromBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * UTF-8 string to Uint8Array
 */
export function utf8ToBytes(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'utf8'));
}

/**
 * Uint8Array to UTF-8 string
 */
export function bytesToUtf8(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('utf8');
}

/**
 * Convert raw public key bytes to standard SHA-256 fingerprint
 */
export function computeKeyFingerprint(publicKeyBytesOrPem: Uint8Array | string): string {
  const hex = sha256Hex(publicKeyBytesOrPem);
  // Format as Colon-Separated Fingerprint e.g. 3A:7B:9C:... (first 16 bytes for display)
  return hex.match(/.{1,2}/g)?.slice(0, 16).join(':').toUpperCase() || hex;
}

/**
 * Canonical Signing String Constructor
 * Binds packageId, recipientKeyId, deviceKeyId, nonce, wrappedAesKey, authTag, and ciphertextSha256
 */
export function constructCanonicalSigningPayload(params: {
  packageId: string;
  recipientKeyId: string;
  deviceKeyId: string;
  nonce: string;
  wrappedAesKey: string;
  authenticationTag: string;
  ciphertextSha256: string;
}): string {
  return [
    'TRUSTROOT-v1',
    params.packageId,
    params.recipientKeyId,
    params.deviceKeyId,
    params.nonce,
    params.wrappedAesKey,
    params.authenticationTag,
    params.ciphertextSha256
  ].join(':');
}
