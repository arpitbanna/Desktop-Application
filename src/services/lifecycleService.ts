/**
 * TrustRoot Mobile - Key Lifecycle Manager
 * Implements local key lifecycle tracking, rotation records, expiry enforcement,
 * local revocation management, and safe audit event logging.
 *
 * All operations execute 100% offline.
 */

import {
  AuditEvent,
  DeviceKeyMetadata,
  KeyLifecycleStatus
} from '../types/security';
import { generateSecureUUID } from '../utils/cryptoUtils';

export interface KeyRotationRecord {
  oldKeyId: string;
  newKeyId: string;
  oldAlias: string;
  newAlias: string;
  rotatedAt: string;
}

export interface RevocationEntry {
  keyId: string;
  revokedAt: string;
  reason: string;
}

class LifecycleService {
  private auditLogs: AuditEvent[] = [];
  private rotationHistory: KeyRotationRecord[] = [];
  private revocationRegistry: Map<string, RevocationEntry> = new Map();
  private managedKeys: Map<string, DeviceKeyMetadata> = new Map();

  /**
   * Log a security audit event (strictly sanitized - no secrets)
   */
  async logAuditEvent(
    action: AuditEvent['action'],
    status: AuditEvent['status'],
    details: string,
    keyId?: string,
    packageId?: string
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      id: generateSecureUUID(),
      timestamp: new Date().toISOString(),
      action,
      status,
      details,
      keyId,
      packageId
    };

    this.auditLogs.unshift(event);
    if (this.auditLogs.length > 200) {
      this.auditLogs.pop(); // Keep last 200 events
    }
    return event;
  }

  /**
   * Record new key generation
   */
  async recordKeyGeneration(metadata: DeviceKeyMetadata) {
    this.managedKeys.set(metadata.alias, { ...metadata });
    await this.logAuditEvent(
      'KEY_GENERATED',
      'SUCCESS',
      `New device key generated. Algorithm: ${metadata.algorithm}, Size: ${metadata.keySize} bits, Security: ${metadata.securityLevel}`,
      metadata.keyId
    );
  }

  /**
   * Record key rotation
   */
  async recordKeyRotation(
    oldMetadata: DeviceKeyMetadata | null,
    newMetadata: DeviceKeyMetadata
  ) {
    this.managedKeys.set(newMetadata.alias, { ...newMetadata });

    if (oldMetadata) {
      const oldEntry = this.managedKeys.get(oldMetadata.alias);
      if (oldEntry) {
        oldEntry.status = 'EXPIRED';
      }

      this.rotationHistory.unshift({
        oldKeyId: oldMetadata.keyId,
        newKeyId: newMetadata.keyId,
        oldAlias: oldMetadata.alias,
        newAlias: newMetadata.alias,
        rotatedAt: new Date().toISOString()
      });
    }

    await this.logAuditEvent(
      'KEY_ROTATED',
      'SUCCESS',
      `Key rotated from ${oldMetadata ? oldMetadata.alias : 'none'} to ${newMetadata.alias}`,
      newMetadata.keyId
    );
  }

  /**
   * Record key deletion
   */
  async recordKeyDeletion(metadata: DeviceKeyMetadata) {
    const entry = this.managedKeys.get(metadata.alias);
    if (entry) {
      entry.status = 'DELETED';
    }

    await this.logAuditEvent(
      'KEY_DELETED',
      'WARNING',
      `Device key deleted from keystore: alias '${metadata.alias}'. Key ID: ${metadata.keyId}`,
      metadata.keyId
    );
  }

  /**
   * Locally revoke a key
   */
  async revokeKeyLocally(keyId: string, reason: string = 'User initiated local revocation') {
    const revokedAt = new Date().toISOString();
    this.revocationRegistry.set(keyId, { keyId, revokedAt, reason });

    // Update status in managed keys
    for (const key of this.managedKeys.values()) {
      if (key.keyId === keyId) {
        key.status = 'REVOKED';
      }
    }

    await this.logAuditEvent(
      'KEY_REVOKED',
      'WARNING',
      `Key locally revoked: ${keyId}. Reason: ${reason}`,
      keyId
    );
  }

  /**
   * Check whether a key is valid for cryptographic operations
   */
  async checkKeyValidity(metadata: DeviceKeyMetadata): Promise<{
    isValid: boolean;
    status: KeyLifecycleStatus;
    reason?: string;
  }> {
    // 1. Check local revocation
    if (this.revocationRegistry.has(metadata.keyId)) {
      const rev = this.revocationRegistry.get(metadata.keyId)!;
      return {
        isValid: false,
        status: 'REVOKED',
        reason: `Key was locally revoked on ${rev.revokedAt}: ${rev.reason}`
      };
    }

    // 2. Check deletion
    if (metadata.status === 'DELETED') {
      return {
        isValid: false,
        status: 'DELETED',
        reason: 'Key has been permanently deleted from keystore'
      };
    }

    // 3. Check expiration timestamp
    const now = new Date();
    const expiry = new Date(metadata.expiresAt);
    if (now > expiry) {
      return {
        isValid: false,
        status: 'EXPIRED',
        reason: `Key expired on ${metadata.expiresAt} (Local policy enforcement)`
      };
    }

    return {
      isValid: true,
      status: 'ACTIVE'
    };
  }

  /**
   * Get all managed keys and their status
   */
  getManagedKeys(): DeviceKeyMetadata[] {
    return Array.from(this.managedKeys.values());
  }

  /**
   * Get rotation history
   */
  getRotationHistory(): KeyRotationRecord[] {
    return [...this.rotationHistory];
  }

  /**
   * Get revocation registry
   */
  getRevocationList(): RevocationEntry[] {
    return Array.from(this.revocationRegistry.values());
  }

  /**
   * Get audit log entries
   */
  getAuditLogs(): AuditEvent[] {
    return [...this.auditLogs];
  }

  /**
   * Clear state for unit testing
   */
  _resetForTesting() {
    this.auditLogs = [];
    this.rotationHistory = [];
    this.revocationRegistry.clear();
    this.managedKeys.clear();
  }
}

export const lifecycleService = new LifecycleService();
