/**
 * TrustRoot Mobile - Device Security Service
 * Manages device identity keys, challenge signing, hardware attestation inspection,
 * and key integrity verification.
 */

import { nativeBridge } from './nativeBridge';
import { DeviceKeyMetadata, HardwareSecurityLevel, KeyAlgorithm } from '../types/security';
import { lifecycleService } from './lifecycleService';

export const DEFAULT_DEVICE_KEY_ALIAS = 'trustroot_device_identity_v1';

class SecurityService {
  private activeAlias: string = DEFAULT_DEVICE_KEY_ALIAS;

  /**
   * Get active key alias
   */
  getActiveAlias(): string {
    return this.activeAlias;
  }

  /**
   * Set active key alias
   */
  setActiveAlias(alias: string) {
    this.activeAlias = alias;
  }

  /**
   * Generate a fresh device identity key
   */
  async generateDeviceKey(
    alias: string = this.activeAlias,
    algorithm: KeyAlgorithm = 'EC_P256',
    preferStrongBox: boolean = true
  ): Promise<DeviceKeyMetadata> {
    const metadata = await nativeBridge.generateDeviceKey(alias, algorithm, preferStrongBox);
    this.activeAlias = alias;

    // Record lifecycle event
    await lifecycleService.recordKeyGeneration(metadata);

    return metadata;
  }

  /**
   * Get metadata for current active device key
   */
  async getActiveKeyMetadata(): Promise<DeviceKeyMetadata | null> {
    return await nativeBridge.getKeyMetadata(this.activeAlias);
  }

  /**
   * Sign a challenge (e.g. verifier challenge or canonical digest)
   */
  async signChallenge(challengeText: string, alias: string = this.activeAlias): Promise<string> {
    const metadata = await nativeBridge.getKeyMetadata(alias);
    if (!metadata) {
      throw new Error(`Device identity key '${alias}' not found. Please generate a key first.`);
    }

    // Verify key validity before signing
    const validity = await lifecycleService.checkKeyValidity(metadata);
    if (!validity.isValid) {
      throw new Error(`Key validity check failed: ${validity.reason}`);
    }

    return await nativeBridge.signPayload(alias, challengeText);
  }

  /**
   * Verify a signature against a device public key
   */
  async verifySignature(
    publicKeyPem: string,
    challengeText: string,
    signatureBase64: string
  ): Promise<boolean> {
    return await nativeBridge.verifyDeviceSignature(publicKeyPem, challengeText, signatureBase64);
  }

  /**
   * Rotate device identity key
   */
  async rotateDeviceKey(
    algorithm: KeyAlgorithm = 'EC_P256',
    preferStrongBox: boolean = true
  ): Promise<DeviceKeyMetadata> {
    const oldMetadata = await this.getActiveKeyMetadata();
    const oldAlias = this.activeAlias;

    const newMetadata = await nativeBridge.rotateDeviceKey(oldAlias, algorithm, preferStrongBox);
    this.activeAlias = newMetadata.alias;

    // Record rotation in lifecycle service
    await lifecycleService.recordKeyRotation(oldMetadata, newMetadata);

    return newMetadata;
  }

  /**
   * Delete current device key
   */
  async deleteDeviceKey(alias: string = this.activeAlias): Promise<boolean> {
    const metadata = await nativeBridge.getKeyMetadata(alias);
    if (!metadata) return false;

    const deleted = await nativeBridge.deleteDeviceKey(alias);
    if (deleted) {
      await lifecycleService.recordKeyDeletion(metadata);
    }
    return deleted;
  }

  /**
   * Query the detected hardware security level
   */
  async getHardwareSecurityLevel(): Promise<HardwareSecurityLevel> {
    return await nativeBridge.getHardwareSecurityLevel();
  }
}

export const securityService = new SecurityService();
