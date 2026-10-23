/**
 * TrustRoot Mobile - Hybrid Package Encryption & Verification Service
 *
 * Implements the hybrid cryptography pipeline:
 * 1. Fresh CSPRNG AES-256 session key & unique 96-bit nonce
 * 2. Authenticated Additional Data (AAD) binding header metadata
 * 3. AES-256-GCM bulk payload encryption with 128-bit tag
 * 4. RSA-OAEP (SHA-256) wrapping of the AES key using Recipient Public Key
 * 5. Device Identity Key digital signature over the canonical package digest
 * 6. Zeroing of ephemeral secret keys
 * 7. Verification, tamper detection, and test recipient offline decryption
 */

import * as crypto from 'crypto';
import {
  DecryptionVerificationResult,
  DeviceKeyMetadata,
  EncryptedPackage,
  RecipientKeyInfo
} from '../types/security';
import {
  constructCanonicalSigningPayload,
  fromBase64,
  generateSecureUUID,
  getSecureRandomBytes,
  sha256Bytes,
  sha256Hex,
  toBase64,
  utf8ToBytes
} from '../utils/cryptoUtils';
import { securityService } from './securityService';
import { lifecycleService } from './lifecycleService';
import { nativeBridge } from './nativeBridge';

export type TamperType =
  | 'MODIFY_CIPHERTEXT'
  | 'MODIFY_AUTH_TAG'
  | 'MODIFY_AAD_METADATA'
  | 'MODIFY_SIGNATURE'
  | 'MODIFY_WRAPPED_KEY';

class PackageService {
  /**
   * Encrypt a binary or image payload using hybrid cryptography
   */
  async encryptPayload(params: {
    payloadBytes: Uint8Array;
    payloadType: string;
    recipient: RecipientKeyInfo;
    deviceKeyAlias?: string;
  }): Promise<{ package: EncryptedPackage; elapsedMs: number }> {
    const startTime = Date.now();
    const { payloadBytes, payloadType, recipient, deviceKeyAlias } = params;

    if (!payloadBytes || payloadBytes.length === 0) {
      throw new Error('Payload cannot be empty or zero bytes.');
    }

    // 1. Get Device Key Metadata and ensure it is valid
    const activeAlias = deviceKeyAlias || securityService.getActiveAlias();
    const deviceKey = await securityService.getActiveKeyMetadata();
    if (!deviceKey) {
      throw new Error(
        `Active device key not found for alias '${activeAlias}'. Please generate a device identity key first.`
      );
    }

    const validity = await lifecycleService.checkKeyValidity(deviceKey);
    if (!validity.isValid) {
      throw new Error(`Device key cannot be used for encryption: ${validity.reason}`);
    }

    // Delegate to native hardware module if running on Android or iOS
    if (nativeBridge.isNativeAvailable()) {
      try {
        const nativeResult = await nativeBridge.encryptPayloadNative({
          payloadBase64: toBase64(payloadBytes),
          payloadType,
          recipientPublicKeyPem: recipient.publicKeyPem,
          recipientKeyId: recipient.keyId,
          deviceKeyAlias: activeAlias
        });
        const parsedPkg: EncryptedPackage = JSON.parse(nativeResult.packageJson);
        await lifecycleService.logAuditEvent(
          'PAYLOAD_ENCRYPTED',
          'SUCCESS',
          `Native hardware encrypted payload (${payloadType}, ${payloadBytes.length} bytes) to recipient '${recipient.keyId}'.`,
          deviceKey.keyId,
          parsedPkg.packageId
        );
        return { package: parsedPkg, elapsedMs: Math.round(nativeResult.elapsedMs) };
      } catch (err: any) {
        console.warn('Native encryption failed, using fallback:', err.message);
      }
    }

    // 2. Compute Payload SHA-256
    const payloadSha256 = sha256Hex(payloadBytes);
    const packageId = `pkg_${generateSecureUUID().replace(/-/g, '').slice(0, 16)}`;
    const createdAt = new Date().toISOString();

    // 3. Generate Fresh Ephemeral AES-256 Key (32 bytes) and Nonce (12 bytes) using CSPRNG
    const ephemeralAesKey = getSecureRandomBytes(32);
    const nonceBytes = getSecureRandomBytes(12);

    // 4. Construct Authenticated Additional Data (AAD) Header
    const aadObject = {
      version: '1.0',
      packageId,
      createdAt,
      recipientKeyId: recipient.keyId,
      deviceKeyId: deviceKey.keyId,
      payloadSha256
    };
    const aadJsonString = JSON.stringify(aadObject);
    const aadBytes = utf8ToBytes(aadJsonString);

    // 5. Encrypt Payload using AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ephemeralAesKey), Buffer.from(nonceBytes));
    cipher.setAAD(Buffer.from(aadBytes));
    const ciphertextBuffer = Buffer.concat([cipher.update(Buffer.from(payloadBytes)), cipher.final()]);
    const authTagBuffer = cipher.getAuthTag();

    const ciphertextBase64 = toBase64(new Uint8Array(ciphertextBuffer));
    const nonceBase64 = toBase64(nonceBytes);
    const authTagBase64 = toBase64(new Uint8Array(authTagBuffer));
    const aadBase64 = toBase64(aadBytes);

    // 6. Wrap AES Key using Recipient RSA Public Key (RSA-OAEP with SHA-256)
    let wrappedKeyBuffer: Buffer;
    try {
      wrappedKeyBuffer = crypto.publicEncrypt(
        {
          key: recipient.publicKeyPem,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        Buffer.from(ephemeralAesKey)
      );
    } catch (err: any) {
      throw new Error(`RSA-OAEP Key Wrapping failed with recipient public key: ${err.message}`);
    }
    const wrappedAesKeyBase64 = toBase64(new Uint8Array(wrappedKeyBuffer));

    // 7. Security: Zero out ephemeral plaintext AES key buffer from memory
    ephemeralAesKey.fill(0);

    // 8. Construct Canonical Digest and Sign using Hardware Device Identity Key
    const ciphertextSha256 = sha256Hex(new Uint8Array(ciphertextBuffer));
    const canonicalString = constructCanonicalSigningPayload({
      packageId,
      recipientKeyId: recipient.keyId,
      deviceKeyId: deviceKey.keyId,
      nonce: nonceBase64,
      wrappedAesKey: wrappedAesKeyBase64,
      authenticationTag: authTagBase64,
      ciphertextSha256
    });

    const deviceSignature = await securityService.signChallenge(canonicalString, activeAlias);

    const elapsedMs = Date.now() - startTime;

    const encryptedPackage: EncryptedPackage = {
      version: '1.0',
      packageId,
      createdAt,
      payloadType,
      payloadSize: payloadBytes.length,
      payloadSha256,
      encryptionAlgorithm: 'AES-256-GCM',
      keyWrappingAlgorithm: 'RSA-OAEP-SHA256',
      recipientKeyId: recipient.keyId,
      deviceKeyId: deviceKey.keyId,
      nonce: nonceBase64,
      ciphertext: ciphertextBase64,
      authenticationTag: authTagBase64,
      wrappedAesKey: wrappedAesKeyBase64,
      deviceSignature,
      securityLevel: deviceKey.securityLevel,
      isHardwareBacked: deviceKey.isHardwareBacked,
      aad: aadBase64
    };

    // 9. Log audit event
    await lifecycleService.logAuditEvent(
      'PAYLOAD_ENCRYPTED',
      'SUCCESS',
      `Encrypted payload (${payloadType}, ${payloadBytes.length} bytes) to recipient '${recipient.keyId}'. AES-256-GCM + RSA-OAEP-SHA256.`,
      deviceKey.keyId,
      packageId
    );

    return { package: encryptedPackage, elapsedMs };
  }

  /**
   * Verify and Decrypt an Encrypted Package in the Verification Lab
   */
  async verifyAndDecryptPackage(params: {
    pkg: EncryptedPackage;
    recipientPrivateKeyPem: string;
    devicePublicKeyPem?: string;
    expectedOriginalSha256?: string;
  }): Promise<DecryptionVerificationResult> {
    const startTime = Date.now();
    const { pkg, recipientPrivateKeyPem, devicePublicKeyPem, expectedOriginalSha256 } = params;

    let signatureValid = false;
    let gcmTagValid = false;
    let payloadMatch = false;
    let recoveredPayloadBase64: string | undefined;
    let recoveredPayloadSha256: string | undefined;

    // 1. Verify Device Identity Signature over Canonical Digest
    try {
      const ciphertextBytes = fromBase64(pkg.ciphertext);
      const ciphertextSha256 = sha256Hex(ciphertextBytes);
      const canonicalString = constructCanonicalSigningPayload({
        packageId: pkg.packageId,
        recipientKeyId: pkg.recipientKeyId,
        deviceKeyId: pkg.deviceKeyId,
        nonce: pkg.nonce,
        wrappedAesKey: pkg.wrappedAesKey,
        authenticationTag: pkg.authenticationTag,
        ciphertextSha256
      });

      // Use provided device public key or active device key
      let pubKeyPem = devicePublicKeyPem;
      if (!pubKeyPem) {
        const activeKey = await securityService.getActiveKeyMetadata();
        if (activeKey && activeKey.keyId === pkg.deviceKeyId) {
          pubKeyPem = activeKey.publicKeyPem;
        }
      }

      if (pubKeyPem) {
        signatureValid = await securityService.verifySignature(pubKeyPem, canonicalString, pkg.deviceSignature);
      }
    } catch {
      signatureValid = false;
    }

    // 2. Unwrap AES Key using Recipient Private Key (RSA-OAEP-SHA256)
    let unwrappedAesKey: Buffer;
    try {
      const wrappedKeyBuffer = Buffer.from(fromBase64(pkg.wrappedAesKey));
      unwrappedAesKey = crypto.privateDecrypt(
        {
          key: recipientPrivateKeyPem,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        wrappedKeyBuffer
      );
    } catch (err: any) {
      const elapsedMs = Date.now() - startTime;
      await lifecycleService.logAuditEvent(
        'TAMPER_DETECTED',
        'FAILURE',
        `RSA-OAEP key unwrapping failed. Incorrect private key or tampered wrapped key. Details: ${err.message}`,
        pkg.deviceKeyId,
        pkg.packageId
      );
      return {
        isVerified: false,
        isTampered: true,
        tamperReason: `Recipient key unwrap failure: ${err.message}`,
        payloadMatch: false,
        signatureValid,
        gcmTagValid: false,
        elapsedMs
      };
    }

    // 3. Decrypt Payload using AES-256-GCM and verify AAD + Authentication Tag
    try {
      const nonceBuffer = Buffer.from(fromBase64(pkg.nonce));
      const ciphertextBuffer = Buffer.from(fromBase64(pkg.ciphertext));
      const tagBuffer = Buffer.from(fromBase64(pkg.authenticationTag));
      const aadBuffer = Buffer.from(fromBase64(pkg.aad));

      const decipher = crypto.createDecipheriv('aes-256-gcm', unwrappedAesKey, nonceBuffer);
      decipher.setAAD(aadBuffer);
      decipher.setAuthTag(tagBuffer);

      const plaintextBuffer = Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
      gcmTagValid = true;

      // Zero out unwrapped secret key from memory immediately
      unwrappedAesKey.fill(0);

      recoveredPayloadBase64 = plaintextBuffer.toString('base64');
      recoveredPayloadSha256 = sha256Hex(new Uint8Array(plaintextBuffer));

      // 4. Verify Payload SHA-256 match
      payloadMatch = recoveredPayloadSha256 === pkg.payloadSha256;
      if (expectedOriginalSha256) {
        payloadMatch = payloadMatch && (recoveredPayloadSha256 === expectedOriginalSha256);
      }
    } catch (err: any) {
      // Zero out unwrapped secret key if error occurred
      unwrappedAesKey.fill(0);
      const elapsedMs = Date.now() - startTime;
      await lifecycleService.logAuditEvent(
        'TAMPER_DETECTED',
        'FAILURE',
        `Authenticated decryption failed. Ciphertext, nonce, tag, or AAD metadata modified: ${err.message}`,
        pkg.deviceKeyId,
        pkg.packageId
      );
      return {
        isVerified: false,
        isTampered: true,
        tamperReason: `Authenticated GCM tag validation failed: ${err.message}`,
        payloadMatch: false,
        signatureValid,
        gcmTagValid: false,
        elapsedMs
      };
    }

    const elapsedMs = Date.now() - startTime;
    const isVerified = signatureValid && gcmTagValid && payloadMatch;

    await lifecycleService.logAuditEvent(
      'PACKAGE_VERIFIED',
      isVerified ? 'SUCCESS' : 'WARNING',
      `Verification ${isVerified ? 'PASSED' : 'FAILED'}. Signature: ${signatureValid}, GCM Tag: ${gcmTagValid}, Payload Match: ${payloadMatch}`,
      pkg.deviceKeyId,
      pkg.packageId
    );

    return {
      isVerified,
      isTampered: !isVerified,
      tamperReason: isVerified
        ? undefined
        : !signatureValid
        ? 'Device digital signature mismatch'
        : !payloadMatch
        ? 'Recovered payload SHA-256 does not match original digest'
        : undefined,
      recoveredPayloadBase64,
      recoveredPayloadSha256,
      payloadMatch,
      signatureValid,
      gcmTagValid,
      elapsedMs
    };
  }

  /**
   * Produce a tampered version of a package to demonstrate detection in the Verification Lab
   */
  createTamperedPackage(pkg: EncryptedPackage, tamperType: TamperType): EncryptedPackage {
    const tampered: EncryptedPackage = JSON.parse(JSON.stringify(pkg));

    switch (tamperType) {
      case 'MODIFY_CIPHERTEXT': {
        const bytes = fromBase64(tampered.ciphertext);
        if (bytes.length > 5) {
          bytes[4] ^= 0x5a; // Flip bits in ciphertext
        } else {
          bytes[0] ^= 0xff;
        }
        tampered.ciphertext = toBase64(bytes);
        break;
      }
      case 'MODIFY_AUTH_TAG': {
        const tagBytes = fromBase64(tampered.authenticationTag);
        tagBytes[0] ^= 0x01; // Corrupt single bit of GCM tag
        tampered.authenticationTag = toBase64(tagBytes);
        break;
      }
      case 'MODIFY_AAD_METADATA': {
        // Alter the Authenticated Additional Data
        const aadBytes = fromBase64(tampered.aad);
        aadBytes[aadBytes.length - 2] ^= 0x07;
        tampered.aad = toBase64(aadBytes);
        break;
      }
      case 'MODIFY_SIGNATURE': {
        const sigBytes = fromBase64(tampered.deviceSignature);
        sigBytes[sigBytes.length - 1] ^= 0xaa; // Corrupt signature bytes
        tampered.deviceSignature = toBase64(sigBytes);
        break;
      }
      case 'MODIFY_WRAPPED_KEY': {
        const keyBytes = fromBase64(tampered.wrappedAesKey);
        keyBytes[10] ^= 0xcc; // Corrupt wrapped key byte
        tampered.wrappedAesKey = toBase64(keyBytes);
        break;
      }
    }

    return tampered;
  }
}

export const packageService = new PackageService();
