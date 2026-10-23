# TrustRoot Mobile: Cryptographic Design Specification

## 1. Overview
TrustRoot Mobile implements a standard-compliant, offline-first hybrid cryptosystem tailored for mobile hardware root of trust. This document outlines the explicit mathematical primitives, parameter selections, key hierarchies, and encoding rules.

---

## 2. Algorithm Parameters Matrix

| Purpose | Algorithm / Primitive | Specific Parameters | Standards Reference |
| :--- | :--- | :--- | :--- |
| **Device Key Pair (Android)** | RSA or EC P-256 | RSA: 2048-bit, e=65537<br>EC: secp256r1 (NIST P-256) | FIPS 186-4, RFC 5480 |
| **Device Key Pair (iOS)** | EC P-256 | `secp256r1`, Secure Enclave bound | Apple Platform Security Guide |
| **Device Signature** | ECDSA or RSA-PSS | `SHA256withECDSA` (DER-encoded)<br>`SHA256withRSA` | ANSI X9.62, RFC 8017 |
| **Bulk Symmetric Encryption**| AES-GCM | Key: 256 bits (32 bytes)<br>IV/Nonce: 96 bits (12 bytes)<br>Tag: 128 bits (16 bytes) | NIST SP 800-38D |
| **Key Wrapping** | RSA-OAEP | Recipient RSA 2048/4096-bit<br>Hash: SHA-256<br>MGF: MGF1 with SHA-256 | RFC 8017 (PKCS #1 v2.2) |
| **Digest / Hashing** | SHA-256 | Output: 256 bits (32 bytes) | FIPS 180-4 |
| **Random Number Generation** | CSPRNG | Android: `SecureRandom`<br>iOS: `SecRandomCopyBytes` / CryptoKit | NIST SP 800-90A |

---

## 3. Detailed Cryptographic Protocols

### 3.1 Device Identity Generation
- **Android**:
  Generated via `android.security.keystore.KeyGenParameterSpec.Builder`:
  ```kotlin
  KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setKeySize(256) // EC secp256r1 or 2048 for RSA
      .setIsStrongBoxBacked(isStrongBoxRequested) // StrongBox if available
      .setUserAuthenticationRequired(false) // Offline operational policy
      .build()
  ```
- **iOS**:
  Generated via `kSecAttrTokenIDSecureEnclave` attributes:
  ```swift
  let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      [.privateKeyUsage],
      nil
  )
  let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
          kSecAttrIsPermanent as String: true,
          kSecAttrApplicationTag as String: tag,
          kSecAccessControl as String: access
      ]
  ]
  ```

### 3.2 Ephemeral AES-256-GCM Payload Encryption
For every payload (image or binary blob):
1. **Fresh Session Key**: $K \leftarrow \text{CSPRNG}(256 \text{ bits})$.
2. **Fresh Nonce**: $IV \leftarrow \text{CSPRNG}(96 \text{ bits})$. Never reused under any circumstances.
3. **Form Authenticated Additional Data (AAD)**:
   Canonical UTF-8 JSON containing:
   $$\text{AAD} = \text{CanonicalJSON}(\{ \text{version}, \text{packageId}, \text{createdAt}, \text{recipientKeyId}, \text{deviceKeyId}, \text{payloadSha256} \})$$
4. **Encrypt**:
   $$(C, T) = \text{AES-GCM-Encrypt}(K, IV, \text{PlaintextPayload}, \text{AAD})$$
   where $C$ is ciphertext and $T$ is the 128-bit authentication tag.

### 3.3 Asymmetric Key Wrapping (RSA-OAEP)
The session key $K$ is wrapped using the intended Recipient's RSA Public Key:
$$W = \text{RSA-OAEP-Wrap}(PK_{\text{recipient}}, K)$$
- **Mask Generation Function**: MGF1 using SHA-256.
- **OAEP Digest**: SHA-256.
- **Label / Parameter**: Empty string `""`.
- If an older platform Keystore only allows default SHA-1 OAEP or requires explicit parameter specification, the package metadata explicitly declares `keyWrappingAlgorithm: "RSA-OAEP-SHA256"`.

### 3.4 Canonical Package Signing
To cryptographically bind the payload and metadata to the device hardware identity:
1. Construct the Canonical Signing String:
   $$M_{\text{sign}} = \text{"TRUSTROOT-v1:"} \parallel \text{packageId} \parallel \text{":"} \parallel \text{recipientKeyId} \parallel \text{":"} \parallel \text{deviceKeyId} \parallel \text{":"} \parallel \text{nonce} \parallel \text{":"} \parallel \text{wrappedAesKey} \parallel \text{":"} \parallel \text{authTag} \parallel \text{":"} \parallel \text{SHA256}(C)$$
2. Generate Signature:
   $$S = \text{Sign}(SK_{\text{device}}, \text{SHA256}(M_{\text{sign}}))$$
   The private key $SK_{\text{device}}$ never leaves the hardware boundary.

---

## 4. Package Format & Serialization

All binary buffers are encoded using standard RFC 4648 Base64:

```json
{
  "version": "1.0",
  "packageId": "pkg_9f3a1e2b4c8d",
  "createdAt": "2026-10-24T00:23:59.000Z",
  "payloadType": "image/jpeg",
  "payloadSize": 245760,
  "payloadSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "encryptionAlgorithm": "AES-256-GCM",
  "keyWrappingAlgorithm": "RSA-OAEP-SHA256",
  "recipientKeyId": "rcpt_uidai_test_2026",
  "deviceKeyId": "dev_3a7b9c1d",
  "nonce": "X1l4OG5vbmNlZGF0YTEy",
  "ciphertext": "base64EncodedCiphertextData...",
  "authenticationTag": "MTI4Yml0QXV0aFRhZzEyOA==",
  "wrappedAesKey": "base64EncodedWrappedKeyBlob...",
  "deviceSignature": "MEUCIQD...base64DERSignature...",
  "hardwareAttested": true,
  "securityLevel": "STRONGBOX"
}
```

---

## 5. Security & Tamper Detection Guarantees

1. **Confidentiality**: Only the entity possessing the recipient's private key ($SK_{\text{recipient}}$) can unwrap the AES key.
2. **Integrity & Authenticity**: Any modification to $C$, $IV$, or AAD metadata causes AES-GCM tag verification to immediately fail ($T \ne T'$).
3. **Non-Repudiation of Origin**: The device hardware signature $S$ guarantees that the package originated from the specific device possessing $SK_{\text{device}}$.
4. **No Key Reuse**: Each package uses a freshly generated 256-bit AES key and nonce.
