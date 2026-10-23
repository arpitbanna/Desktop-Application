# TrustRoot Mobile
### Hardware-Backed Device Identity and Offline Data Protection
**UIDAI Hardware-Enabled Root of Trust — Offline Mobile PKI Encryption Prototype**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![React Native](https://img.shields.io/badge/React_Native-0.74-61DAFB.svg)](https://reactnative.dev/)
[![Offline First](https://img.shields.io/badge/Network-100%25_Offline-success.svg)](#offline-first-architecture)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

---

## 1. Project Overview & Problem Statement

Issued under the **Ministry of Electronics and Information Technology (MeitY)** by **UIDAI**, this solution addresses the challenge of establishing a hardware-backed cryptographic identity and protecting sensitive biometric/document data locally on mobile devices without any backend or cloud dependency.

### Core Objectives:
1. **Hardware Root of Trust**: Generate non-exportable asymmetric cryptographic key pairs within device security silicon (Android Keystore with StrongBox/TEE; Apple Secure Enclave).
2. **Hybrid Offline Encryption**: Protect biometric/document images locally using fresh ephemeral **AES-256-GCM** keys wrapped via intended recipient's **RSA-OAEP** public key.
3. **Hardware Non-Repudiation**: Bind payload metadata to the physical device identity through hardware-generated digital signatures over canonical package digests.
4. **Lifecycle Management**: Implement local key rotation, expiry enforcement, local revocation registry, and secure deletion.
5. **Authenticity & Honest Security**: Never fake hardware protection, attestation, or algorithm support. Accurately report platform capabilities on Android, iOS, and simulator environments.

---

## 2. Architecture & Cryptographic Design

TrustRoot Mobile enforces a strict mathematical separation between the **Device Identity Key** and the **Recipient Encryption Key**.

```
+-----------------------------------------------------------------------------------------+
|                                    TRUSTROOT ARCHITECTURE                               |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|  [ Physical Device Security Hardware ]                                                  |
|  Android Keystore (StrongBox/TEE) | Apple Secure Enclave (EC P-256)                     |
|  - Generates Device Identity Key                                                        |
|  - Private key is NON-EXPORTABLE (never leaves secure hardware boundary)                |
|  - Signs canonical package digest: SHA256(packageId:rcptId:devId:nonce:tag:ciphertext)  |
|                                                                                         |
|  [ Ephemeral Session Layer (Zero Network / Airplane Mode) ]                             |
|  - Generates fresh 256-bit AES key & 96-bit nonce via CSPRNG (SecureRandom)            |
|  - Encrypts payload with AES-256-GCM + Authenticated Additional Data (AAD)              |
|  - Produces 128-bit authentication tag                                                  |
|  - Immediately overwrites ephemeral AES key in memory post-encryption                   |
|                                                                                         |
|  [ Recipient Asymmetric Wrapping ]                                                      |
|  - Wraps ephemeral AES key using Recipient RSA-2048/4096 Public Key (RSA-OAEP-SHA256)    |
|  - Device client NEVER possesses recipient's private key in production                  |
|  - Test harness includes isolated synthetic test recipient private key for lab verify   |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Technology Stack

- **Shared Mobile Application**: React Native (0.74.x), TypeScript (5.4.x), React Navigation, Lucide React Native, React Native Safe Area Context.
- **Android Native Security Module**: Kotlin, Android Keystore, StrongBox Keymaster/KeyMint (API 28+), TEE Keymaster, Android Key Attestation (X.509 chains), RSA-OAEP with explicit SHA-256 parameters.
- **iOS Native Security Module**: Swift (6.x), Apple Security framework, Secure Enclave (`kSecAttrTokenIDSecureEnclave`), Apple CryptoKit, Keychain access controls.
- **Testing & Verification**: Jest, ts-jest, Node.js native crypto, Swift native standalone verification suite.

---

## 4. Platform Limitations & Security Matrix

| Platform / Environment | Device Identity Key | Non-Exportable Private Key | Bulk AES-256-GCM | Recipient RSA-OAEP Wrapping | Hardware Attestation |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Android (StrongBox HSM)** | EC P-256 / RSA-2048 | Hardware Enforced | ARMv8 CPU Crypto | Keystore / Cipher API | Google Root X.509 Chain |
| **Android (TEE TrustZone)** | EC P-256 / RSA-2048 | Hardware Enforced | ARMv8 CPU Crypto | Keystore / Cipher API | Google Root X.509 Chain |
| **iOS (Secure Enclave)** | EC P-256 Only | Hardware Enforced | ARMv8 CPU Crypto | Security Framework (Host) | App Attest (Network only) |
| **Emulator / Simulator** | Simulated (Software) | OS Memory Only | Software / Crypto | Platform Crypto | Unsupported |

> **Honest Disclosure — iOS Secure Enclave Boundary**:
> Apple's Secure Enclave coprocessor hardware strictly supports NIST P-256 elliptic curve (`secp256r1`) cryptography. It does **not** support RSA key operations or bulk AES-GCM encryption inside the Enclave. Therefore, TrustRoot Mobile generates the Device Identity Key in the Secure Enclave (EC P-256), while RSA-OAEP recipient key wrapping executes via Apple's platform Security framework in application memory.

---

## 5. Encrypted Package Structure

Every encrypted package is a versioned, self-contained, authenticated JSON object:

```json
{
  "version": "1.0",
  "packageId": "pkg_9f3a1e2b4c8d",
  "createdAt": "2026-10-24T00:23:59.000Z",
  "payloadType": "image/png",
  "payloadSize": 80,
  "payloadSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "encryptionAlgorithm": "AES-256-GCM",
  "keyWrappingAlgorithm": "RSA-OAEP-SHA256",
  "recipientKeyId": "rcpt_uidai_test_2026",
  "deviceKeyId": "B6:7A:41:48:97:93:2A:44:8D:1F:19:D8:F8:78:8F:D6",
  "nonce": "X1l4OG5vbmNlZGF0YTEy",
  "ciphertext": "base64EncodedCiphertextData...",
  "authenticationTag": "MTI4Yml0QXV0aFRhZzEyOA==",
  "wrappedAesKey": "base64EncodedWrappedKeyBlob...",
  "deviceSignature": "MEUCIQD...base64DERSignature...",
  "securityLevel": "STRONGBOX",
  "isHardwareBacked": true,
  "aad": "eyJ2ZXJzaW9uIjoiMS4wIiwicGFja2FnZUlkIjoicGtnXzlmM2ExZTJiNGM4ZCJ9"
}
```

---

## 6. Installation & Development Commands

### Prerequisites
- Node.js >= 18 (Tested on Node.js v24)
- npm >= 10
- Java JDK >= 17 (for Android build)
- Xcode Command Line Tools / Swift >= 5.10 (for iOS Swift parsing)

### Setup & Testing
```bash
# Clone and install dependencies
npm install

# Run static type checks (zero errors)
npm run typecheck

# Run automated security test suite (21 tests)
npm test

# Run tests with coverage
npm run test:coverage
```

### Running the Application
```bash
# Start Metro bundler
npm run start

# Run on Android device / emulator
npm run android

# Run on iOS device / simulator
npm run ios
```

---

## 7. 3-Minute Hackathon Live Demonstration Flow

1. **Launch App**: Open TrustRoot Mobile. Inspect the **Detected Security Level** and verified **Airplane Mode Ready** badge.
2. **Device Identity**: Navigate to **Identity** tab. Observe the public key fingerprint and verify that private key bytes are non-exportable. Tap **Sign with Hardware Key** to execute a live challenge signature.
3. **Airplane Mode Hybrid Encryption**: Turn ON Airplane Mode. Switch to **Encrypt** tab. Select synthetic face image `synthetic_resident_face.png`. Select test recipient `rcpt_uidai_test_2026`. Tap **Start Hybrid Encryption**. Observe elapsed time (~2-4ms).
4. **Verification & Decryption**: Tap **Open in Verification & Tamper Lab**. Tap **Verify Integrity & Decrypt**. Observe that the test recipient successfully decrypts the payload and that the recovered SHA-256 matches the original byte-for-byte.
5. **Adversary Tamper Detection**: Tap **Tamper Ciphertext (Flip Bits)**. Tap **Verify Integrity & Decrypt**. Observe immediate cryptographic rejection: `"Authenticated GCM tag validation failed"`.
6. **Key Lifecycle & Rotation**: Switch to **Lifecycle** tab. Rotate device key to generate a fresh identity while preserving the rotation audit trail.
7. **Diagnostics & Audit Log**: Switch to **Diagnostics** tab. View the sanitized audit log (zero secrets stored) and export the sanitized JSON report.

---

## 8. Threat Model & Mitigations Summary

| Threat | Implemented Mitigation | Limitation / Non-Guarantee |
| :--- | :--- | :--- |
| **Private Key Extraction** | Key generated inside hardware Keystore/SE; non-exportable flag. | Silicon-level physical decapping / side-channel attacks. |
| **Package Tampering** | AES-GCM 128-bit authentication tag + AAD + Hardware signature. | Does not prevent denial-of-service / packet dropping. |
| **Recipient Substitution** | Recipient public key fingerprint bound into AAD and signature. | Compromised APK binary containing rogue recipient key. |
| **Software Fallback Faking** | Native inspection of KeyInfo security level; honest badge display. | Custom rogue OS kernel designed to lie about KeyInfo flags. |
| **Offline Revocation** | Local expiry policy and local revocation blacklist enforcement. | Real-time discovery of remote revocations while offline. |

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for full analysis of all 11 threats.

---

## 9. Documentation Index

- [Architecture Specification](docs/ARCHITECTURE.md)
- [Cryptographic Protocol Specification](docs/CRYPTOGRAPHY.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Platform Support & Limitations](docs/PLATFORM_LIMITATIONS.md)
- [Testing Guide](docs/TESTING.md)
- [Live Demo Guide](docs/DEMO_GUIDE.md)

---

## 10. License
Licensed under the Apache License, Version 2.0. Built for UIDAI Hackathon Evaluation.
