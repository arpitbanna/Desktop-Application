# TrustRoot Mobile: Platform Limitations & Support Matrix

## 1. Executive Summary
Different operating systems and hardware platforms possess fundamentally disparate cryptographic capabilities. **TrustRoot Mobile** adheres to an uncompromised principle of honest security reporting: the system never fakes hardware-backed status, attestation certificates, or unsupported algorithm execution.

---

## 2. Platform Support Matrix

| Feature | Android (StrongBox) | Android (TEE) | iOS (Secure Enclave) | iOS (Standard Keychain) | Emulator / Simulator / Node |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Device Key Pair: EC P-256** | Supported (Hardware) | Supported (Hardware) | Supported (Hardware) | Supported (Software/OS) | Supported (Software) |
| **Device Key Pair: RSA-2048** | Supported (Hardware) | Supported (Hardware) | **Not Supported by Enclave** | Supported (Software/OS) | Supported (Software) |
| **Hardware Attestation (X.509)** | Supported (Google Root) | Supported (Google Root) | App Attest (Network only) | Not Supported | Not Supported |
| **Private Key Non-Exportability**| Hardware-enforced | Hardware-enforced | Hardware-enforced | OS-enforced | Simulated only |
| **AES-256-GCM Bulk Encryption** | ARMv8 CPU Crypto | ARMv8 CPU Crypto | ARMv8 CPU Crypto | ARMv8 CPU Crypto | WebCrypto / Software |
| **RSA-OAEP Key Wrapping** | Keystore / Cipher API| Keystore / Cipher API| Security Framework (Host)| Security Framework | Node / WebCrypto |
| **Offline Airplane Mode Execution**| 100% Fully Functional| 100% Fully Functional| 100% Fully Functional| 100% Fully Functional| 100% Fully Functional |

---

## 3. Platform-Specific Architectural Realities

### 3.1 Android Keystore (StrongBox vs TEE vs Software)
- **StrongBox Keymaster/KeyMint**: A dedicated physical hardware security module (HSM) with isolated CPU, RAM, and secure storage (e.g., Titan M chip on Google Pixel, Knox Vault on Samsung). API level 28+ required. Keys generated with `setIsStrongBoxBacked(true)` reside in this discrete chip.
- **Trusted Execution Environment (TEE)**: An isolated execution environment running on the main SoC (ARM TrustZone) separate from Android OS.
- **Key Attestation**: Android supports generating an X.509 certificate chain signed by a Google root CA certifying whether the key was generated in TEE or StrongBox, and verifying device boot state.
- **RSA-OAEP**: Supported in Android Keystore, but developers must explicitly specify `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` to avoid legacy SHA-1 defaults.

### 3.2 iOS Secure Enclave vs Security Framework
- **Secure Enclave Cryptographic Boundary**:
  Apple's Secure Enclave is a hardware coprocessor that **only supports NIST P-256 elliptic curve (`secp256r1`) cryptography** for ECDSA signatures and ECDH key agreement.
- **The RSA Disparity**:
  The Secure Enclave **does not support RSA key generation or RSA-OAEP encryption**. Any application claiming "Hardware-backed RSA encryption inside the Apple Secure Enclave" is factually incorrect.
- **TrustRoot Implementation Strategy**:
  - The iOS **Device Identity Key** is generated inside the Secure Enclave as an **EC P-256 key** (`kSecAttrTokenIDSecureEnclave`), guaranteeing non-exportable hardware identity.
  - The **Hybrid Recipient Key Wrapping** (RSA-OAEP) is executed using Apple's platform `Security` framework in application memory, using the recipient's public key.
  - This architecture achieves genuine hardware root-of-trust identity while strictly conforming to Apple's documented hardware capabilities.

### 3.3 Offline Revocation Constraints
- A mobile device operating in airplane mode cannot query remote Certificate Revocation Lists (CRL) or Online Certificate Status Protocol (OCSP) responders.
- The client enforces locally stored revocation policies and expiry windows.
- Any claim that an offline device has "real-time global revocation awareness" is false; trust state synchronization requires future reconciliation.
