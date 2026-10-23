/**
 * TrustRoot Mobile - Hybrid Package Encryption & Verification Tests
 * Validates AES-256-GCM authenticated encryption, RSA-OAEP key wrapping,
 * AAD integrity, tamper detection, and test recipient recovery.
 */

import { packageService } from '../src/services/packageService';
import { securityService } from '../src/services/securityService';
import {
  RECIPIENT_PRIMARY_TEST,
  RECIPIENT_SECONDARY_TEST,
  TEST_ONLY_RECIPIENT_PRIVATE_KEYS
} from '../src/services/recipientKeys';
import { utf8ToBytes, sha256Hex, fromBase64, toBase64 } from '../src/utils/cryptoUtils';

describe('TrustRoot Mobile - Hybrid Encryption & Verification Lab', () => {
  beforeAll(async () => {
    // Generate active device identity key for test run
    await securityService.generateDeviceKey('test_device_key_pkg', 'EC_P256', true);
  });

  test('1. Encrypt non-empty sample binary payload successfully', async () => {
    const samplePayload = utf8ToBytes('UIDAI-TEST-BIOMETRIC-SAMPLE-HASH-DATA-9876543210');
    const result = await packageService.encryptPayload({
      payloadBytes: samplePayload,
      payloadType: 'application/octet-stream',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    expect(result.package).toBeDefined();
    expect(result.package.version).toBe('1.0');
    expect(result.package.encryptionAlgorithm).toBe('AES-256-GCM');
    expect(result.package.keyWrappingAlgorithm).toBe('RSA-OAEP-SHA256');
    expect(result.package.recipientKeyId).toBe(RECIPIENT_PRIMARY_TEST.keyId);
    expect(result.package.nonce).toBeDefined();
    expect(result.package.ciphertext).toBeDefined();
    expect(result.package.authenticationTag).toBeDefined();
    expect(result.package.wrappedAesKey).toBeDefined();
    expect(result.package.deviceSignature).toBeDefined();
    expect(result.package.payloadSha256).toBe(sha256Hex(samplePayload));
    expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  test('2. Reject empty or zero-byte payload safely', async () => {
    const emptyPayload = new Uint8Array(0);
    await expect(
      packageService.encryptPayload({
        payloadBytes: emptyPayload,
        payloadType: 'text/plain',
        recipient: RECIPIENT_PRIMARY_TEST
      })
    ).rejects.toThrow('Payload cannot be empty or zero bytes.');
  });

  test('3. Authorized test recipient decrypts and recovers exact original bytes', async () => {
    const originalText = 'CONFIDENTIAL-SAMPLE-OFFLINE-AADHAAR-TEST-BLOB-2026';
    const originalBytes = utf8ToBytes(originalText);
    const originalSha256 = sha256Hex(originalBytes);

    const enc = await packageService.encryptPayload({
      payloadBytes: originalBytes,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    const dec = await packageService.verifyAndDecryptPackage({
      pkg: enc.package,
      recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId],
      expectedOriginalSha256: originalSha256
    });

    expect(dec.isVerified).toBe(true);
    expect(dec.isTampered).toBe(false);
    expect(dec.signatureValid).toBe(true);
    expect(dec.gcmTagValid).toBe(true);
    expect(dec.payloadMatch).toBe(true);
    expect(dec.recoveredPayloadSha256).toBe(originalSha256);

    const recoveredBytes = fromBase64(dec.recoveredPayloadBase64!);
    expect(Buffer.from(recoveredBytes).toString('utf8')).toBe(originalText);
  });

  test('4. Tampering: Modified ciphertext FAILS authenticated decryption', async () => {
    const originalBytes = utf8ToBytes('SENSITIVE-DATA-TO-BE-TAMPERED');
    const enc = await packageService.encryptPayload({
      payloadBytes: originalBytes,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    const tampered = packageService.createTamperedPackage(enc.package, 'MODIFY_CIPHERTEXT');
    expect(tampered.ciphertext).not.toBe(enc.package.ciphertext);

    const dec = await packageService.verifyAndDecryptPackage({
      pkg: tampered,
      recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId]
    });

    expect(dec.isVerified).toBe(false);
    expect(dec.isTampered).toBe(true);
    expect(dec.gcmTagValid).toBe(false);
    expect(dec.tamperReason).toContain('Authenticated GCM tag validation failed');
  });

  test('5. Tampering: Modified Authentication Tag FAILS decryption', async () => {
    const originalBytes = utf8ToBytes('TEST-PAYLOAD-FOR-AUTH-TAG-TAMPERING');
    const enc = await packageService.encryptPayload({
      payloadBytes: originalBytes,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    const tampered = packageService.createTamperedPackage(enc.package, 'MODIFY_AUTH_TAG');
    const dec = await packageService.verifyAndDecryptPackage({
      pkg: tampered,
      recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId]
    });

    expect(dec.isVerified).toBe(false);
    expect(dec.isTampered).toBe(true);
    expect(dec.gcmTagValid).toBe(false);
  });

  test('6. Tampering: Modified Authenticated Additional Data (AAD) FAILS decryption', async () => {
    const originalBytes = utf8ToBytes('TEST-PAYLOAD-FOR-AAD-TAMPERING');
    const enc = await packageService.encryptPayload({
      payloadBytes: originalBytes,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    const tampered = packageService.createTamperedPackage(enc.package, 'MODIFY_AAD_METADATA');
    const dec = await packageService.verifyAndDecryptPackage({
      pkg: tampered,
      recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId]
    });

    expect(dec.isVerified).toBe(false);
    expect(dec.isTampered).toBe(true);
    expect(dec.gcmTagValid).toBe(false);
  });

  test('7. Wrong recipient key CANNOT recover payload (RSA-OAEP failure)', async () => {
    const originalBytes = utf8ToBytes('TEST-PAYLOAD-INTENDED-FOR-PRIMARY-RECIPIENT');
    const enc = await packageService.encryptPayload({
      payloadBytes: originalBytes,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST // Encrypted with PRIMARY recipient public key
    });

    // Attempt decryption with SECONDARY recipient private key
    const dec = await packageService.verifyAndDecryptPackage({
      pkg: enc.package,
      recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_SECONDARY_TEST.keyId]
    });

    expect(dec.isVerified).toBe(false);
    expect(dec.isTampered).toBe(true);
    expect(dec.gcmTagValid).toBe(false);
    expect(dec.tamperReason).toContain('Recipient key unwrap failure');
  });

  test('8. Tampering: Modified Device Signature is detected and rejected', async () => {
    const originalBytes = utf8ToBytes('TEST-PAYLOAD-SIGNATURE-TAMPERING');
    const enc = await packageService.encryptPayload({
      payloadBytes: originalBytes,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    const tampered = packageService.createTamperedPackage(enc.package, 'MODIFY_SIGNATURE');
    const dec = await packageService.verifyAndDecryptPackage({
      pkg: tampered,
      recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId]
    });

    expect(dec.isVerified).toBe(false);
    expect(dec.signatureValid).toBe(false);
  });

  test('9. Freshness: Two consecutive encryptions of identical payload yield different nonces & ciphertexts', async () => {
    const payload = utf8ToBytes('IDENTICAL-PAYLOAD-MULTIPLE-RUNS');
    const enc1 = await packageService.encryptPayload({
      payloadBytes: payload,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });
    const enc2 = await packageService.encryptPayload({
      payloadBytes: payload,
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    // Nonces must be unique (CSPRNG 96-bit)
    expect(enc1.package.nonce).not.toBe(enc2.package.nonce);
    // Ciphertexts must differ due to fresh key and fresh nonce
    expect(enc1.package.ciphertext).not.toBe(enc2.package.ciphertext);
    // Package IDs must differ
    expect(enc1.package.packageId).not.toBe(enc2.package.packageId);
  });
});
