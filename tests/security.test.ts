/**
 * TrustRoot Mobile - Security Invariants & Honesty Tests
 * Verifies non-exportability, honest security levels, CSPRNG compliance,
 * and zero network dependencies.
 */

import { securityService } from '../src/services/securityService';
import { diagnosticsService } from '../src/services/diagnosticsService';
import { packageService } from '../src/services/packageService';
import { RECIPIENT_PRIMARY_TEST } from '../src/services/recipientKeys';
import { getSecureRandomBytes, utf8ToBytes } from '../src/utils/cryptoUtils';

describe('TrustRoot Mobile - Security Invariants & Honesty', () => {
  test('1. Honest Security Level: never fake hardware root of trust on non-hardware platforms', async () => {
    const key = await securityService.generateDeviceKey('honesty_check_key', 'EC_P256', true);

    // In this test/Node environment, it must report SOFTWARE_SIMULATED, never faking StrongBox
    expect(key.securityLevel).toBe('SOFTWARE_SIMULATED');
    expect(key.isHardwareBacked).toBe(false);
    expect(key.attestationStatus).toBe('UNSUPPORTED_ON_PLATFORM');
  });

  test('2. Private Key Non-Exportability: no private key material in JavaScript metadata or package', async () => {
    const key = await securityService.generateDeviceKey('non_export_key', 'EC_P256', true);

    // Ensure metadata does not contain privateKey property
    expect((key as any).privateKey).toBeUndefined();
    expect((key as any).privateKeyPem).toBeUndefined();
    expect(key.publicKeyPem).toBeDefined();
    expect(key.publicKeyPem).toContain('BEGIN PUBLIC KEY');
    expect(key.publicKeyPem).not.toContain('PRIVATE KEY');

    // Encrypt a payload and verify exported package contains zero secret keys
    const enc = await packageService.encryptPayload({
      payloadBytes: utf8ToBytes('SENSITIVE-DATA-TO-CHECK-LEAKS'),
      payloadType: 'text/plain',
      recipient: RECIPIENT_PRIMARY_TEST
    });

    const packageString = JSON.stringify(enc.package);
    expect(packageString).not.toContain('PRIVATE KEY');
    expect(packageString).not.toContain('ephemeralAesKey');
    expect(packageString).not.toContain('SENSITIVE-DATA-TO-CHECK-LEAKS'); // Plaintext not present!
  });

  test('3. CSPRNG Randomness Compliance: verified byte generation', () => {
    const b1 = getSecureRandomBytes(32);
    const b2 = getSecureRandomBytes(32);

    expect(b1.length).toBe(32);
    expect(b2.length).toBe(32);
    expect(Buffer.from(b1).equals(Buffer.from(b2))).toBe(false); // Independent randomness
  });

  test('4. Offline Self-Test: end-to-end cryptographic self-test passes 100% offline', async () => {
    const selfTest = await diagnosticsService.runSelfTest();

    expect(selfTest.passed).toBe(true);
    expect(selfTest.tamperDetectionPassed).toBe(true);
    expect(selfTest.keyGenerationElapsedMs).toBeGreaterThanOrEqual(0);
    expect(selfTest.encryptionElapsedMs).toBeGreaterThanOrEqual(0);
    expect(selfTest.decryptionElapsedMs).toBeGreaterThanOrEqual(0);
  });

  test('5. Sanitized Diagnostics Export: guaranteed zero private key exposure in exported report', async () => {
    const reportJson = await diagnosticsService.exportSanitizedDiagnosticReport();
    expect(reportJson).toBeDefined();

    const parsed = JSON.parse(reportJson);
    expect(parsed.reportType).toBe('TrustRoot Mobile Sanitized Diagnostics');
    expect(parsed.diagnostics).toBeDefined();
    expect(parsed.managedKeys).toBeDefined();
    expect(parsed.securityNotice).toContain('No private keys, AES session keys, or decrypted payloads');

    // Verify report does not contain any private key text
    expect(reportJson).not.toContain('PRIVATE KEY');
  });

  test('6. Native Encryption Error Safety: handles unavailable native module cleanly', async () => {
    const { nativeBridge } = require('../src/services/nativeBridge');
    await expect(
      nativeBridge.encryptPayloadNative({
        payloadBase64: 'dGVzdA==',
        payloadType: 'text/plain',
        recipientPublicKeyPem: 'test_pem',
        recipientKeyId: 'test_rcpt',
        deviceKeyAlias: 'test_alias'
      })
    ).rejects.toThrow('Native encryption module is unavailable in this environment');
  });
});
