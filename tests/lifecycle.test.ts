/**
 * TrustRoot Mobile - Key Lifecycle & Policy Tests
 * Validates key generation, fingerprinting, expiration enforcement,
 * rotation history, local revocation registry, and sanitized audit logging.
 */

import { securityService } from '../src/services/securityService';
import { lifecycleService } from '../src/services/lifecycleService';
import { DeviceKeyMetadata } from '../src/types/security';

describe('TrustRoot Mobile - Key Lifecycle Management', () => {
  beforeEach(() => {
    lifecycleService._resetForTesting();
  });

  test('1. Generate device key and compute stable public key fingerprint', async () => {
    const key = await securityService.generateDeviceKey('test_key_lc_1', 'EC_P256', true);

    expect(key).toBeDefined();
    expect(key.keyId).toBeDefined();
    expect(key.keyId).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2}){15}$/); // Colon separated fingerprint
    expect(key.algorithm).toBe('EC_P256');
    expect(key.status).toBe('ACTIVE');
    expect(key.publicKeyPem).toContain('BEGIN PUBLIC KEY');
  });

  test('2. Two generated keys have unique identifiers', async () => {
    const key1 = await securityService.generateDeviceKey('key_pair_1', 'EC_P256', true);
    const key2 = await securityService.generateDeviceKey('key_pair_2', 'EC_P256', true);

    expect(key1.keyId).not.toBe(key2.keyId);
    expect(key1.alias).not.toBe(key2.alias);
  });

  test('3. Key Expiry policy enforcement rejects expired keys', async () => {
    const key = await securityService.generateDeviceKey('test_key_expiry', 'EC_P256', true);

    // Active key validity check passes
    const validityActive = await lifecycleService.checkKeyValidity(key);
    expect(validityActive.isValid).toBe(true);

    // Simulate expired key (1 hour in the past)
    const expiredKey: DeviceKeyMetadata = {
      ...key,
      expiresAt: new Date(Date.now() - 3600 * 1000).toISOString()
    };

    const validityExpired = await lifecycleService.checkKeyValidity(expiredKey);
    expect(validityExpired.isValid).toBe(false);
    expect(validityExpired.status).toBe('EXPIRED');
    expect(validityExpired.reason).toContain('Key expired');
  });

  test('4. Key Rotation generates fresh key, archives previous, preserves audit history', async () => {
    const initialKey = await securityService.generateDeviceKey('rot_test_init', 'EC_P256', true);
    expect(initialKey.status).toBe('ACTIVE');

    const rotatedKey = await securityService.rotateDeviceKey('EC_P256', true);

    expect(rotatedKey.keyId).not.toBe(initialKey.keyId);
    expect(rotatedKey.status).toBe('ACTIVE');

    const history = lifecycleService.getRotationHistory();
    expect(history.length).toBeGreaterThanOrEqual(1);
    expect(history[0].oldKeyId).toBe(initialKey.keyId);
    expect(history[0].newKeyId).toBe(rotatedKey.keyId);

    const auditLogs = lifecycleService.getAuditLogs();
    const rotationLog = auditLogs.find(e => e.action === 'KEY_ROTATED');
    expect(rotationLog).toBeDefined();
    expect(rotationLog?.status).toBe('SUCCESS');
  });

  test('5. Local Revocation registry rejects signing attempts with revoked keys', async () => {
    const key = await securityService.generateDeviceKey('test_key_revocation', 'EC_P256', true);

    // Revoke locally
    await lifecycleService.revokeKeyLocally(key.keyId, 'Suspected device compromise test');

    const revocationList = lifecycleService.getRevocationList();
    expect(revocationList.some(r => r.keyId === key.keyId)).toBe(true);

    const validity = await lifecycleService.checkKeyValidity(key);
    expect(validity.isValid).toBe(false);
    expect(validity.status).toBe('REVOKED');
    expect(validity.reason).toContain('Suspected device compromise test');

    // Attempting to sign with revoked key must reject
    await expect(securityService.signChallenge('TEST_CHALLENGE', key.alias)).rejects.toThrow(
      /Key validity check failed.*revoked/
    );
  });

  test('6. Keystore deletion removes key entry and records warning audit event', async () => {
    const key = await securityService.generateDeviceKey('test_key_delete_target', 'EC_P256', true);

    const deleted = await securityService.deleteDeviceKey(key.alias);
    expect(deleted).toBe(true);

    const auditLogs = lifecycleService.getAuditLogs();
    const deleteLog = auditLogs.find(e => e.action === 'KEY_DELETED');
    expect(deleteLog).toBeDefined();
    expect(deleteLog?.status).toBe('WARNING');
    expect(deleteLog?.details).toContain('Device key deleted from keystore');
  });

  test('7. Audit logging preserves privacy: zero secrets or private keys in logs', async () => {
    await securityService.generateDeviceKey('audit_privacy_test', 'EC_P256', true);
    await securityService.signChallenge('BENCHMARK_CHALLENGE');

    const logs = lifecycleService.getAuditLogs();
    expect(logs.length).toBeGreaterThan(0);

    for (const entry of logs) {
      // Must never contain private key markers or raw secret indicators
      expect(entry.details).not.toContain('PRIVATE KEY');
      expect(entry.details).not.toContain('ephemeralAesKey');
      expect(entry.details).not.toContain('BEGIN RSA PRIVATE');
    }
  });

  test('8. NativeBridge key rotation generates unique key alias and updates metadata', async () => {
    const { nativeBridge } = require('../src/services/nativeBridge');
    const key = await nativeBridge.generateDeviceKey('nb_rot_init', 'EC_P256', true);
    const rotated = await nativeBridge.rotateDeviceKey('nb_rot_init', 'EC_P256', true);

    expect(rotated.alias).not.toBe(key.alias);
    expect(rotated.keyId).not.toBe(key.keyId);
    expect(rotated.status).toBe('ACTIVE');
  });
});
