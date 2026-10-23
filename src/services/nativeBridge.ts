/**
 * TrustRoot Mobile - Native Cryptography Bridge
 * Provides a unified typed interface between React Native and platform native modules.
 *
 * Android: com.trustroot.security.TrustRootSecurityModule (Kotlin / Android Keystore)
 * iOS: TrustRootSecurityBridge (Swift / Secure Enclave & Keychain)
 * Simulator / Test Environment: Authenticated Software Cryptographic Provider
 *
 * HONESTY ENFORCEMENT:
 * Simulator/Test runs strictly report `isHardwareBacked: false` and `securityLevel: 'SOFTWARE_SIMULATED'`.
 * Never claims hardware root of trust when running in software!
 */

import { NativeModules, Platform } from 'react-native';
import * as crypto from 'crypto';
import {
  DeviceKeyMetadata,
  HardwareSecurityLevel,
  KeyAlgorithm,
  PlatformDiagnostics
} from '../types/security';
import {
  computeKeyFingerprint,
  sha256Hex,
  toBase64,
  fromBase64
} from '../utils/cryptoUtils';

const { TrustRootSecurityModule } = NativeModules;

// In-memory keystore simulation for unit testing / simulator fallback
interface SimulatedKeyEntry {
  alias: string;
  metadata: DeviceKeyMetadata;
  privateKeyPem: string; // ONLY exists in simulator fallback; native hardware private keys are strictly non-exportable
}

const simulatedKeyStore: Map<string, SimulatedKeyEntry> = new Map();

class NativeSecurityBridge {
  public isNativeAvailable(): boolean {
    return (
      TrustRootSecurityModule !== undefined &&
      TrustRootSecurityModule !== null &&
      typeof TrustRootSecurityModule.generateDeviceKey === 'function'
    );
  }

  /**
   * Generate device identity key inside platform security module
   */
  async generateDeviceKey(
    alias: string,
    algorithm: KeyAlgorithm = 'EC_P256',
    preferStrongBox: boolean = true
  ): Promise<DeviceKeyMetadata> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.generateDeviceKey(alias, algorithm, preferStrongBox);
    }

    // High-fidelity Software Simulation for Jest / Development without native binary
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(); // 1 year

    let publicKeyPem = '';
    let privateKeyPem = '';
    let keySize = 256;

    if (algorithm === 'EC_P256') {
      const ecdh = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      publicKeyPem = ecdh.publicKey;
      privateKeyPem = ecdh.privateKey;
      keySize = 256;
    } else {
      const rsa = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      publicKeyPem = rsa.publicKey;
      privateKeyPem = rsa.privateKey;
      keySize = 2048;
    }

    const keyId = computeKeyFingerprint(publicKeyPem);

    const metadata: DeviceKeyMetadata = {
      keyId,
      alias,
      algorithm,
      keySize,
      securityLevel: 'SOFTWARE_SIMULATED',
      isHardwareBacked: false,
      isNonExportable: true,
      attestationStatus: 'UNSUPPORTED_ON_PLATFORM',
      purposes: ['SIGN', 'VERIFY'],
      digestAlgorithms: ['SHA-256'],
      createdAt,
      expiresAt,
      status: 'ACTIVE',
      publicKeyPem
    };

    simulatedKeyStore.set(alias, {
      alias,
      metadata,
      privateKeyPem
    });

    return metadata;
  }

  /**
   * Retrieve metadata for a key alias
   */
  async getKeyMetadata(alias: string): Promise<DeviceKeyMetadata | null> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.getKeyMetadata(alias);
    }

    const entry = simulatedKeyStore.get(alias);
    return entry ? { ...entry.metadata } : null;
  }

  /**
   * Sign canonical string using device identity private key
   */
  async signPayload(alias: string, canonicalString: string): Promise<string> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.signPayload(alias, canonicalString);
    }

    const entry = simulatedKeyStore.get(alias);
    if (!entry) {
      throw new Error(`Device key with alias '${alias}' not found in Keystore`);
    }

    if (entry.metadata.status !== 'ACTIVE') {
      throw new Error(`Device key is in ${entry.metadata.status} state. Signing rejected.`);
    }

    const sign = crypto.createSign('SHA256');
    sign.update(canonicalString);
    sign.end();
    const signature = sign.sign(entry.privateKeyPem);
    return signature.toString('base64');
  }

  /**
   * Verify signature using device public key
   */
  async verifyDeviceSignature(
    publicKeyPem: string,
    canonicalString: string,
    signatureBase64: string
  ): Promise<boolean> {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(canonicalString);
      verify.end();
      const sigBuf = Buffer.from(signatureBase64, 'base64');
      return verify.verify(publicKeyPem, sigBuf);
    } catch {
      return false;
    }
  }

  /**
   * Query the detected hardware security level
   */
  async getHardwareSecurityLevel(): Promise<HardwareSecurityLevel> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.getHardwareSecurityLevel();
    }
    return 'SOFTWARE_SIMULATED';
  }

  /**
   * Permanently delete device key from platform keystore
   */
  async deleteDeviceKey(alias: string): Promise<boolean> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.deleteDeviceKey(alias);
    }

    const entry = simulatedKeyStore.get(alias);
    if (entry) {
      entry.metadata.status = 'DELETED';
      simulatedKeyStore.delete(alias);
      return true;
    }
    return false;
  }

  /**
   * Rotate device identity key
   */
  async rotateDeviceKey(
    oldAlias: string,
    algorithm: KeyAlgorithm = 'EC_P256',
    preferStrongBox: boolean = true
  ): Promise<DeviceKeyMetadata> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.rotateDeviceKey(oldAlias, preferStrongBox);
    }
    const newVersion = Date.now();
    const newAlias = `trustroot_device_identity_v${newVersion}`;
    return await this.generateDeviceKey(newAlias, algorithm, preferStrongBox);
  }

  /**
   * Encrypt payload natively if supported on device
   */
  async encryptPayloadNative(params: {
    payloadBase64: string;
    payloadType: string;
    recipientPublicKeyPem: string;
    recipientKeyId: string;
    deviceKeyAlias: string;
  }): Promise<{ packageJson: string; packageId: string; elapsedMs: number }> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.encryptPayload(
        params.payloadBase64,
        params.payloadType,
        params.recipientPublicKeyPem,
        params.recipientKeyId,
        params.deviceKeyAlias
      );
    }
    throw new Error('Native encryption module is unavailable in this environment');
  }

  /**
   * Get diagnostic report from platform
   */
  async getDiagnostics(): Promise<PlatformDiagnostics> {
    if (this.isNativeAvailable()) {
      return await TrustRootSecurityModule.getDiagnostics();
    }

    const isMac = process.platform === 'darwin';
    return {
      platform: 'node',
      osVersion: process.version,
      deviceModel: isMac ? 'macOS Test Host' : 'Node.js Runtime',
      strongBoxAvailable: false,
      teeAvailable: false,
      secureEnclaveAvailable: false,
      keyAttestationSupported: false,
      rsaOaepHardwareSupported: false,
      detectedSecurityLevel: 'SOFTWARE_SIMULATED',
      offlineStatus: 'OFFLINE_VERIFIED',
      activeKeysCount: simulatedKeyStore.size,
      auditEventsCount: 0,
      supportedDigests: ['SHA-256', 'SHA-384', 'SHA-512'],
      supportedAlgorithms: ['EC_P256', 'RSA_2048', 'RSA_4096', 'AES-256-GCM']
    };
  }

  /**
   * Reset simulated storage (for automated test cleanup)
   */
  _resetSimulation() {
    simulatedKeyStore.clear();
  }
}

export const nativeBridge = new NativeSecurityBridge();
