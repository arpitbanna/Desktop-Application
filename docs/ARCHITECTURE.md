# TrustRoot Mobile: Architecture Specification

## 1. Executive Summary
**TrustRoot Mobile** implements a hardware-backed root-of-trust identity and offline hybrid cryptographic data protection model for mobile clients (Android & iOS), aligned with UIDAI offline security requirements.

The system enforces a strict separation of concerns across cryptographic roles, trust boundaries, and platform capabilities without any cloud or network dependency.

---

## 2. Fundamental Cryptographic Role Distinction

A critical architectural requirement is distinguishing between the **Device Identity Key** and the **Recipient Encryption Key**. Conflating these two concepts creates severe security vulnerabilities, unauthorized decryption access, or broken key lifecycle management.

```
+---------------------------------------------------------------------------------------+
|                                    TRUSTROOT MOBILE                                   |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|   [ Device Identity Key (Asymmetric EC P-256 or RSA-2048) ]                           |
|   - Generated inside Hardware Keystore / Secure Enclave / StrongBox                   |
|   - Private key is NON-EXPORTABLE (never leaves secure hardware boundary)             |
|   - Role: Authenticate device, sign challenges, sign encrypted package canonical digest|
|   - Identifier: SHA-256 fingerprint of public key                                     |
|   - Lifecycle: Rotation, Expiry, Revocation state, Keystore deletion                  |
|                                                                                       |
|   [ Recipient Public Encryption Key (RSA-2048/4096 OAEP) ]                            |
|   - Pre-provisioned certificate / public key of authorized recipient (e.g., UIDAI)    |
|   - Test Environment: Clearly labeled, locally provisioned synthetic recipient key    |
|   - Role: Wrap the ephemeral AES-256 payload key                                      |
|   - Device NEVER possesses recipient's private key in production                      |
|                                                                                       |
|   [ Ephemeral Hybrid Session Key (AES-256-GCM) ]                                      |
|   - Fresh 256-bit key generated per payload via platform CSPRNG (SecureRandom)        |
|   - Unique 96-bit (12-byte) initialization vector / nonce                             |
|   - Role: Bulk symmetric encryption of biometric/document binary payload              |
|   - Authenticates package metadata via Authenticated Additional Data (AAD)            |
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

### A. Device Identity Key
1. **Ownership**: Generated and owned by the physical mobile device.
2. **Generation**: Initialized in hardware-backed storage (`Android Keystore` backed by TEE / StrongBox Keymaster/KeyMint; iOS `Secure Enclave` via `kSecAttrTokenIDSecureEnclave` / CryptoKit).
3. **Exportability**: Private key material is permanently non-exportable. It cannot be read into application memory, serialized to disk, or transmitted to JavaScript.
4. **Purpose**:
   - Establishes a hardware-bound cryptographic identifier.
   - Provides digital signatures over transaction challenges and package canonical digests.
   - Proves origin authenticity through Key Attestation certificate chains (where supported by Android StrongBox/TEE).
   - Supports key rotation, validity windows, and local revocation states.

### B. Recipient Encryption Key
1. **Ownership**: Owned by the authorized data processing authority (e.g., UIDAI Central Identity Data Repository or authorized offline verifier).
2. **Key Material on Device**: Only the **Public Key** (`recipientPublicKey`) is provisioned on the mobile client.
3. **Purpose**: Used by the mobile device exclusively to wrap (encrypt) the ephemeral symmetric AES key using RSA-OAEP.
4. **Test Recipient Distinction**: For demonstration and offline lab verification, a clearly isolated **Test Recipient Key Pair** is provisioned. The test private key is strictly isolated to the Verification Lab test harness and explicitly documented as synthetic test material.

---

## 3. Hybrid Encryption Workflow

Directly encrypting large binary payloads (such as high-resolution face images or biometric blobs) using asymmetric RSA is cryptographically improper and technically impossible due to RSA message length limits ($M_{\text{len}} \le k - 2 h_{\text{len}} - 2$).

TrustRoot Mobile executes an authenticated hybrid encryption scheme:

```
[ Sample Binary / Image Payload ] (e.g., 250 KB)
        │
        ├──> SHA-256 Digest ──> payloadSha256
        │
        ▼
[ Fresh AES-256 Key (CSPRNG) ] + [ 96-bit Nonce ]
        │
        ├─────────────────────────────┐
        ▼                             ▼
[ AES-256-GCM Encryptor ]      [ RSA-OAEP Key Wrapper ]
  (Payload + AAD Header)         (Recipient Public Key + SHA-256)
        │                             │
        ├──> Ciphertext               ├──> wrappedAesKey
        └──> Auth Tag (128-bit)       │
        │                             │
        └──────────────┬──────────────┘
                       ▼
         [ Canonical Package Header ]
         (Version, IDs, Nonce, Tag, AAD)
                       │
                       ▼
          [ Device Identity Key (HW) ]
          Signs Canonical Package Digest
                       │
                       ▼
         [ Complete TrustRoot Package ]
```

### Protocol Steps:
1. **Payload Ingestion**: Read the sample binary/image data into memory. Compute its reference `payloadSha256`.
2. **Ephemeral Key Generation**: Generate a fresh 256-bit symmetric key (`K_aes`) and a unique 96-bit nonce (`IV`) using platform-certified CSPRNG (`java.security.SecureRandom` on Android, `SecRandomCopyBytes` / `SymmetricKey` on iOS).
3. **Authenticated Additional Data (AAD)**: Formulate the canonical JSON metadata header (version, package ID, creation timestamp, recipient key ID, device key ID, payload SHA-256).
4. **Bulk Symmetric Encryption**: Encrypt the payload using `AES-256-GCM` with `K_aes`, `IV`, and `AAD`. This produces the ciphertext and a 128-bit authentication tag.
5. **Asymmetric Key Wrapping**: Wrap `K_aes` using the Recipient RSA Public Key via `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
6. **Device Origin Signature**: Compute the canonical SHA-256 digest over `{packageId, recipientKeyId, deviceKeyId, nonce, wrappedAesKey, authTag, ciphertextSha256}`. Request the hardware-backed Device Identity Key to sign this digest (`SHA256withECDSA` or `SHA256withRSA`).
7. **Package Assembly**: Serialize into a versioned JSON package with Base64-encoded binary elements.
8. **Memory Cleansing**: Immediately overwrite ephemeral plaintext AES key material in memory.

---

## 4. Hardware Boundary and Honest Security Claims

Modern mobile security chips have distinct operational capabilities that must not be misrepresented:

| Operation | Android (StrongBox / TEE) | iOS (Secure Enclave) | Host OS / App Crypto |
| :--- | :---: | :---: | :---: |
| **Device Key Generation (P-256 EC)** | Yes (TEE/StrongBox) | Yes (`kSecAttrTokenIDSecureEnclave`) | N/A |
| **Device Key Generation (RSA-2048)** | Yes (Keystore TEE/StrongBox) | No (Secure Enclave is EC P-256 only) | Fallback in Keychain |
| **Private Key Non-Exportability** | Hardware Enforced | Hardware Enforced | OS Keychain Enforced |
| **Digital Signature Generation** | Inside TEE/StrongBox | Inside Secure Enclave | App Runtime |
| **Hardware Key Attestation** | Supported (X.509 Chain) | DeviceCheck / App Attest | None |
| **Bulk AES-256-GCM Encryption** | Host CPU / Android Crypto | Host CPU / CryptoKit | Host Crypto Library |
| **RSA-OAEP Key Wrapping** | Android Keystore / Cipher | Security Framework (Host) | Platform Crypto |

### Honest Disclosure Rules:
- **No False Claims**: The application explicitly reports whether an operation ran in Secure Hardware (`STRONGBOX`, `TEE`, `SECURE_ENCLAVE`) or Software (`SOFTWARE_BACKED`, `SIMULATOR`).
- **Secure Enclave Algorithm Boundary**: Apple Secure Enclave hardware strictly supports elliptic curve `secp256r1` (P-256) signing and decryption. It does **not** perform RSA operations inside the Enclave. Therefore, on iOS, the Device Identity Key is generated as an EC P-256 key inside the Secure Enclave, while RSA-OAEP recipient key wrapping is executed by Apple's host Security framework.
- **Bulk Encryption Boundary**: Bulk symmetric encryption (AES-256-GCM) executes on the mobile SoC application processor using optimized hardware crypto extensions (ARMv8-A Cryptographic Extensions), not within the constrained memory of the Secure Enclave or StrongBox.

---

## 5. Offline Operation Assurance
- 100% Zero-Network guarantee for key generation, signing, encryption, package verification, and rotation.
- In-memory local verification lab allows immediate testing in simulated or genuine Airplane Mode.
- Revocation enforcement checks local policy rules and timestamp boundaries without network queries.
