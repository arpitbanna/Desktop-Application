# TrustRoot Mobile: Threat Model

## 1. Scope & Objective
This document details the threat landscape, boundaries, implemented mitigations, non-guarantees, and test verification procedures for the **TrustRoot Mobile** offline PKI architecture.

---

## 2. Threat Analysis Matrix

### Threat 1: Private-Key Extraction Attempts
- **Description**: An attacker with file system or memory inspection access attempts to dump the device's private identity key.
- **Mitigation Implemented**: The private key is generated within Android Keystore (backed by TEE / StrongBox) or iOS Secure Enclave with `PURPOSE_SIGN`. The key specification does not grant export capabilities; private key bits never reside in host RAM or persistent app storage.
- **What Mitigation Cannot Guarantee**: Side-channel attacks against silicon (e.g., differential power analysis or physical decapping of chips) by sophisticated state-sponsored laboratories.
- **Demonstration Test**: `tests/security.test.ts` (test: `verifyPrivateKeyIsNonExportable`). The native bridge returns only public key bytes and key metadata; export methods are strictly prohibited.

---

### Threat 2: A Compromised Application Process
- **Description**: Malicious native or injected code in the application process attempts to forge signatures or manipulate encryption keys.
- **Mitigation Implemented**: Ephemeral AES keys are cleared from memory immediately post-encryption. Hardware keystore operations require explicit cryptographic handles. Device identity keys can enforce user biometric authentication flags if policy configured.
- **What Mitigation Cannot Guarantee**: If the process is fully hijacked while unlocked, the attacker can command the hardware keystore to sign arbitrary data for as long as the process lives. Keystores guarantee private key secrecy, not process integrity.
- **Demonstration Test**: `tests/security.test.ts` (test: `ephemeralSecretZeroing`).

---

### Threat 3: A Rooted or Jailbroken Device
- **Description**: An adversary with superuser privileges attempts to intercept keystore calls, compromise OS memory, or extract hardware keys.
- **Mitigation Implemented**: Hardware-backed keys (TEE/StrongBox/Secure Enclave) are isolated from the host OS kernel. Even an attacker with root kernel execution cannot read private keys out of the hardware enclave. Additionally, hardware key attestation (Android) issues a certificate chain signed by Google/hardware root that reflects the device's boot state (Verified Boot lock status).
- **What Mitigation Cannot Guarantee**: Root cannot extract the private key from hardware, but root can hook the React Native bridge or OS APIs to read plaintext images before encryption or replace public recipient keys in memory.
- **Demonstration Test**: `tests/security.test.ts` (test: `deviceAttestationIntegrityFlags`).

---

### Threat 4: An Emulator or Software-Backed Key
- **Description**: Running the application on an emulator or budget device that lacks TEE/StrongBox/Secure Enclave, falsely claiming hardware security.
- **Mitigation Implemented**: Strict inspection of platform Keymaster/KeyMint attributes (`KeyInfo.getSecurityLevel()` on Android; `kSecAttrTokenID` on iOS). The app displays the detected reality (`SOFTWARE_BACKED`, `TEE`, `STRONGBOX`, or `SECURE_ENCLAVE`) and explicitly refuses to display a verified hardware badge on software keys.
- **What Mitigation Cannot Guarantee**: If an emulator customizes the Android OS build to lie about KeyInfo flags without an attestation challenge signed by Google's intermediate CA, local checks might be deceived without remote attestation server verification.
- **Demonstration Test**: `tests/security.test.ts` (test: `honestSecurityLevelReporting`).

---

### Threat 5: A Tampered Encrypted Package
- **Description**: An adversary intercepts the encrypted package and modifies ciphertext bits, the nonce, or package metadata.
- **Mitigation Implemented**: AES-256-GCM authenticated encryption computes a 128-bit authentication tag over the ciphertext and Authenticated Additional Data (AAD). Additionally, the device hardware key signs the canonical package digest.
- **What Mitigation Cannot Guarantee**: Prevention of packet dropping or destruction (denial of service).
- **Demonstration Test**: `tests/package.test.ts` (test: `tamperedCiphertextFailsAuthenticatedDecryption` and `tamperedAADFailsDecryption`).

---

### Threat 6: A Substituted Recipient Public Key
- **Description**: An attacker replaces the pre-provisioned UIDAI recipient public key with their own public key to intercept and decrypt sensitive image payloads.
- **Mitigation Implemented**: Recipient public keys are anchored to immutable application configuration, verified via SHA-256 key fingerprints, and their ID is cryptographically bound into both the AES-GCM AAD and the canonical signature.
- **What Mitigation Cannot Guarantee**: If an attacker distributes a modified APK with a patched recipient public key, users running the rogue APK would encrypt to the attacker.
- **Demonstration Test**: `tests/package.test.ts` (test: `wrongRecipientKeyRejection`).

---

### Threat 7: Replay or Substitution Attacks
- **Description**: An attacker captures a valid encrypted package and submits it multiple times or substitutes metadata fields.
- **Mitigation Implemented**: Every package contains a cryptographically random UUID v4 `packageId`, an ISO-8601 creation timestamp, a unique 96-bit nonce, and a hardware signature binding all fields.
- **What Mitigation Cannot Guarantee**: Offline verifiers without a synchronized replay cache cannot detect replays solely from the package itself; verifiers must maintain a seen package log.
- **Demonstration Test**: `tests/package.test.ts` (test: `packageUniquenessAndNonceFreshness`).

---

### Threat 8: Missing or Stale Revocation Information
- **Description**: A compromised or expired device key is used offline while the verifier has not received the revocation update.
- **Mitigation Implemented**: The client enforces local expiry timestamps and a local revocation registry. The verification lab displays the exact timestamp of local trust data and warns that offline verification cannot guarantee real-time revocation status without an external update.
- **What Mitigation Cannot Guarantee**: Real-time awareness of global revocations while operating fully offline.
- **Demonstration Test**: `tests/lifecycle.test.ts` (test: `expiredKeyRejectedByPolicy` and `revokedKeyRejected`).

---

### Threat 9: Device Loss and Key Invalidation
- **Description**: A mobile device is lost or stolen; unauthorized parties attempt to access historical keys or generate new identities.
- **Mitigation Implemented**: Local Key Lifecycle Manager provides cryptographic key rotation and immediate secure deletion (`KeyStore.deleteEntry` on Android, `SecItemDelete` on iOS). Deletion invalidates subsequent signatures immediately.
- **What Mitigation Cannot Guarantee**: Recovery of previously encrypted payloads if the device key was rotated/deleted, unless the recipient already possesses the data.
- **Demonstration Test**: `tests/lifecycle.test.ts` (test: `keyDeletionLifecycleState`).

---

### Threat 10: Unsafe Debugging Logs
- **Description**: Sensitive image bytes, AES session keys, or biometric data leak into logcat, Console.app, or crash reporters.
- **Mitigation Implemented**: All diagnostic logs are strictly sanitized. Audit logs capture only SHA-256 hashes, timestamps, key IDs, and operational status. Ephemeral keys and decrypted byte buffers are never logged.
- **What Mitigation Cannot Guarantee**: Memory inspection if an active debugger (JDWP / LLDB) is explicitly attached to the process.
- **Demonstration Test**: `tests/security.test.ts` (test: `noSecretsPresentInAuditLogs`).

---

### Threat 11: Compromised Application Updates
- **Description**: An attacker pushes a malicious update that strips hardware checks.
- **Mitigation Implemented**: Android APK signing (v2/v3 scheme) and iOS code signing enforce binary signature continuity.
- **What Mitigation Cannot Guarantee**: If the signing key itself is compromised.
- **Demonstration Test**: Documented in platform build checks and architecture guidelines.
