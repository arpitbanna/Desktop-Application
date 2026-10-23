/**
 * TrustRoot Mobile - Platform Diagnostics & Integrity Service
 * Performs self-tests, hardware capability inspection, algorithm matrix verification,
 * and sanitized diagnostic report generation.
 */

import { Platform } from 'react-native';
import { PlatformDiagnostics } from '../types/security';
import { nativeBridge } from './nativeBridge';
import { lifecycleService } from './lifecycleService';
import { securityService } from './securityService';
import { packageService } from './packageService';
import { RECIPIENT_PRIMARY_TEST, TEST_ONLY_RECIPIENT_PRIVATE_KEYS } from './recipientKeys';
import { utf8ToBytes } from '../utils/cryptoUtils';

export interface SelfTestResult {
  passed: boolean;
  timestamp: string;
  keyGenerationElapsedMs: number;
  encryptionElapsedMs: number;
  decryptionElapsedMs: number;
  tamperDetectionPassed: boolean;
  detectedSecurityLevel: string;
  error?: string;
}

class DiagnosticsService {
  /**
   * Fetch current hardware and platform diagnostic status
   */
  async getDiagnostics(): Promise<PlatformDiagnostics> {
    const rawDiagnostics = await nativeBridge.getDiagnostics();
    const managedKeys = lifecycleService.getManagedKeys();
    const auditLogs = lifecycleService.getAuditLogs();

    return {
      ...rawDiagnostics,
      activeKeysCount: managedKeys.filter(k => k.status === 'ACTIVE').length,
      auditEventsCount: auditLogs.length,
      lastTestTimestamp: new Date().toISOString()
    };
  }

  /**
   * Run an offline end-to-end cryptographic self-test
   */
  async runSelfTest(): Promise<SelfTestResult> {
    const timestamp = new Date().toISOString();
    try {
      // 1. Generate or verify active device key
      const keyGenStart = Date.now();
      let key = await securityService.getActiveKeyMetadata();
      if (!key || key.status !== 'ACTIVE') {
        key = await securityService.generateDeviceKey(
          `test_selftest_${Date.now()}`,
          'EC_P256',
          true
        );
      }
      const keyGenerationElapsedMs = Date.now() - keyGenStart;

      // 2. Encrypt a synthetic test vector payload
      const testPayload = utf8ToBytes('UIDAI-ROOT-OF-TRUST-DIAGNOSTIC-PAYLOAD-2026');
      const encResult = await packageService.encryptPayload({
        payloadBytes: testPayload,
        payloadType: 'text/plain',
        recipient: RECIPIENT_PRIMARY_TEST
      });

      // 3. Decrypt and verify valid package
      const decResult = await packageService.verifyAndDecryptPackage({
        pkg: encResult.package,
        recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId]
      });

      // 4. Test tamper detection
      const tamperedPkg = packageService.createTamperedPackage(
        encResult.package,
        'MODIFY_CIPHERTEXT'
      );
      const tamperResult = await packageService.verifyAndDecryptPackage({
        pkg: tamperedPkg,
        recipientPrivateKeyPem: TEST_ONLY_RECIPIENT_PRIVATE_KEYS[RECIPIENT_PRIMARY_TEST.keyId]
      });

      const tamperDetectionPassed = tamperResult.isTampered && !tamperResult.isVerified;
      const passed = decResult.isVerified && tamperDetectionPassed;

      await lifecycleService.logAuditEvent(
        'DIAGNOSTIC_RUN',
        passed ? 'SUCCESS' : 'WARNING',
        `Self-test completed. Verified: ${decResult.isVerified}, Tamper Detected: ${tamperDetectionPassed}, Level: ${key.securityLevel}`,
        key.keyId,
        encResult.package.packageId
      );

      return {
        passed,
        timestamp,
        keyGenerationElapsedMs,
        encryptionElapsedMs: encResult.elapsedMs,
        decryptionElapsedMs: decResult.elapsedMs,
        tamperDetectionPassed,
        detectedSecurityLevel: key.securityLevel
      };
    } catch (err: any) {
      await lifecycleService.logAuditEvent(
        'DIAGNOSTIC_RUN',
        'FAILURE',
        `Diagnostic self-test failed: ${err.message}`
      );
      return {
        passed: false,
        timestamp,
        keyGenerationElapsedMs: 0,
        encryptionElapsedMs: 0,
        decryptionElapsedMs: 0,
        tamperDetectionPassed: false,
        detectedSecurityLevel: 'ERROR',
        error: err.message
      };
    }
  }

  /**
   * Export a sanitized diagnostic report as JSON string
   * STRICT GUARANTEE: Never includes private keys, AES keys, or decrypted payloads.
   */
  async exportSanitizedDiagnosticReport(): Promise<string> {
    const diag = await this.getDiagnostics();
    const keys = lifecycleService.getManagedKeys().map(k => ({
      keyId: k.keyId,
      alias: k.alias,
      algorithm: k.algorithm,
      keySize: k.keySize,
      securityLevel: k.securityLevel,
      isHardwareBacked: k.isHardwareBacked,
      attestationStatus: k.attestationStatus,
      purposes: k.purposes,
      createdAt: k.createdAt,
      expiresAt: k.expiresAt,
      status: k.status,
      publicKeyPem: k.publicKeyPem // Public keys are non-secret
    }));
    const audit = lifecycleService.getAuditLogs().slice(0, 50);

    const report = {
      reportType: 'TrustRoot Mobile Sanitized Diagnostics',
      generatedAt: new Date().toISOString(),
      offlineGuarantee: '100% Offline Local Architecture',
      diagnostics: diag,
      managedKeys: keys,
      auditLogSample: audit,
      securityNotice:
        'This diagnostic report contains strictly public metadata, platform security levels, and sanitized event logs. No private keys, AES session keys, or decrypted payloads are stored or exported.'
    };

    return JSON.stringify(report, null, 2);
  }
}

export const diagnosticsService = new DiagnosticsService();
