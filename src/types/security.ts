/**
 * TrustRoot Mobile - Security Type Definitions
 * UIDAI Hardware-Enabled Root of Trust & Offline Mobile PKI
 */

export type HardwareSecurityLevel =
  | 'STRONGBOX'              // Android StrongBox dedicated hardware HSM
  | 'TRUSTED_ENVIRONMENT'   // Android TEE (TrustZone)
  | 'SECURE_ENCLAVE'        // Apple Secure Enclave
  | 'SOFTWARE_BACKED'       // Android / iOS software keystore fallback
  | 'SOFTWARE_SIMULATED';   // Test harness / Simulator (explicitly documented)

export type KeyAlgorithm = 'EC_P256' | 'RSA_2048' | 'RSA_4096';

export type KeyLifecycleStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'DELETED';

export interface DeviceKeyMetadata {
  keyId: string;                     // SHA-256 fingerprint of public key
  alias: string;                     // Platform keystore alias
  algorithm: KeyAlgorithm;           // Key algorithm
  keySize: number;                   // Size in bits (256, 2048, etc.)
  securityLevel: HardwareSecurityLevel;
  isHardwareBacked: boolean;         // True only if genuinely StrongBox/TEE/SecureEnclave
  isNonExportable: boolean;          // Hardware-enforced non-exportability
  attestationStatus: 'VALID_HARDWARE_ATTESTED' | 'NOT_ATTESTED' | 'UNSUPPORTED_ON_PLATFORM';
  attestationCertChain?: string[];   // Base64-encoded X.509 cert chain if available
  purposes: string[];                // ['SIGN', 'VERIFY']
  digestAlgorithms: string[];        // ['SHA-256']
  createdAt: string;                 // ISO-8601
  expiresAt: string;                 // ISO-8601
  status: KeyLifecycleStatus;
  publicKeyPem: string;              // Standard PEM public key (safe to export/share)
}

export interface RecipientKeyInfo {
  keyId: string;
  label: string;
  organization: string;
  algorithm: 'RSA_2048' | 'RSA_4096';
  keyWrappingAlgorithm: 'RSA-OAEP-SHA256';
  publicKeyPem: string;
  fingerprintSha256: string;
  isTestKey: boolean;                // Explicit disclosure flag
}

export interface EncryptedPackage {
  version: '1.0';
  packageId: string;                 // Unique UUID v4
  createdAt: string;                 // ISO-8601
  payloadType: string;               // MIME type e.g. 'image/jpeg', 'application/octet-stream'
  payloadSize: number;               // Unencrypted payload size in bytes
  payloadSha256: string;             // SHA-256 hash of original payload
  encryptionAlgorithm: 'AES-256-GCM';
  keyWrappingAlgorithm: 'RSA-OAEP-SHA256';
  recipientKeyId: string;            // ID of recipient whose public key wrapped the AES key
  deviceKeyId: string;               // ID of device key that signed the canonical package
  nonce: string;                     // Base64 96-bit AES-GCM IV
  ciphertext: string;                // Base64 ciphertext
  authenticationTag: string;         // Base64 128-bit GCM tag
  wrappedAesKey: string;             // Base64 RSA-OAEP wrapped 256-bit AES key
  deviceSignature: string;           // Base64 digital signature of canonical digest
  securityLevel: HardwareSecurityLevel;
  isHardwareBacked: boolean;
  aad: string;                       // Base64 canonical Authenticated Additional Data
}

export interface DecryptionVerificationResult {
  isVerified: boolean;
  isTampered: boolean;
  tamperReason?: string;
  recoveredPayloadBase64?: string;
  recoveredPayloadSha256?: string;
  payloadMatch: boolean;
  signatureValid: boolean;
  gcmTagValid: boolean;
  elapsedMs: number;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  action:
    | 'KEY_GENERATED'
    | 'KEY_ROTATED'
    | 'KEY_REVOKED'
    | 'KEY_DELETED'
    | 'PAYLOAD_ENCRYPTED'
    | 'PACKAGE_VERIFIED'
    | 'TAMPER_DETECTED'
    | 'DIAGNOSTIC_RUN';
  keyId?: string;
  packageId?: string;
  status: 'SUCCESS' | 'WARNING' | 'FAILURE';
  details: string;
  // Note: NO private keys, AES keys, or decrypted sensitive payloads ever stored in audit events
}

export interface PlatformDiagnostics {
  platform: 'android' | 'ios' | 'simulator' | 'node';
  osVersion: string;
  deviceModel: string;
  strongBoxAvailable: boolean;
  teeAvailable: boolean;
  secureEnclaveAvailable: boolean;
  keyAttestationSupported: boolean;
  rsaOaepHardwareSupported: boolean;
  detectedSecurityLevel: HardwareSecurityLevel;
  offlineStatus: 'AIRPLANE_MODE_CONFIRMED' | 'OFFLINE_VERIFIED' | 'CONNECTED';
  activeKeysCount: number;
  auditEventsCount: number;
  lastTestTimestamp?: string;
  supportedDigests: string[];
  supportedAlgorithms: string[];
}
