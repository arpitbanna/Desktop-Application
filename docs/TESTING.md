# TrustRoot Mobile: Automated & Manual Testing Specification

## 1. Overview
TrustRoot Mobile incorporates an automated test harness designed to validate offline cryptographic correctness, hardware security level reporting, non-exportability invariants, and tamper detection without any external cloud or network connectivity.

---

## 2. Test Execution Commands

```bash
# 1. Run all automated test suites (21 security & functional tests)
npm test

# 2. Run with coverage analysis
npm run test:coverage

# 3. Type check complete TypeScript codebase
npm run typecheck

# 4. Run end-to-end verification (Typecheck + Tests)
npm run verify:all
```

---

## 3. Test Suites Breakdown

### 3.1 Hybrid Package Encryption & Verification (`tests/package.test.ts`)
| Test ID | Test Case | Target Invariant | Expected Outcome | Status |
| :--- | :--- | :--- | :--- | :---: |
| **PKG-01** | Encrypt non-empty sample binary payload | AES-256-GCM + RSA-OAEP + SHA-256 Signature | Package generated with all non-secret metadata | PASS |
| **PKG-02** | Reject empty or zero-byte payload | Input validation | Rejects with explicit error message | PASS |
| **PKG-03** | Authorized test recipient decrypts payload | RSA-OAEP private key unwrap & GCM verification | Exact byte-for-byte recovery and SHA-256 match | PASS |
| **PKG-04** | Tampering: Modified ciphertext bits | AES-GCM 128-bit authentication tag validation | Authenticated decryption immediately throws failure | PASS |
| **PKG-05** | Tampering: Modified Authentication Tag | GCM Tag integrity | Decryption rejected | PASS |
| **PKG-06** | Tampering: Modified AAD Metadata | Authenticated Additional Data binding | Decryption rejected | PASS |
| **PKG-07** | Wrong recipient private key | RSA-OAEP private key isolation | Key unwrapping fails | PASS |
| **PKG-08** | Tampering: Modified Device Signature | Non-repudiation and canonical binding | Signature verification returns false | PASS |
| **PKG-09** | Cryptographic Freshness (Nonce & Key) | CSPRNG freshness per payload | Two identical payloads yield unique nonces & ciphertexts | PASS |

---

### 3.2 Key Lifecycle & Policy Management (`tests/lifecycle.test.ts`)
| Test ID | Test Case | Target Invariant | Expected Outcome | Status |
| :--- | :--- | :--- | :--- | :---: |
| **LC-01** | Generate device key & public fingerprint | Keystore key pair generation | SHA-256 colon-separated fingerprint assigned | PASS |
| **LC-02** | Key identifier uniqueness | Cryptographic entropy | Successive key pairs have distinct fingerprints | PASS |
| **LC-03** | Local Expiry Policy Enforcement | Validity timestamp checks | Expired keys rejected from signing operations | PASS |
| **LC-04** | Key Rotation without secret exposure | Key retirement and fresh key generation | History recorded, old key archived, zero secret leaks | PASS |
| **LC-05** | Local Revocation Registry | Offline blacklist enforcement | Revoked key rejected from signing or encryption | PASS |
| **LC-06** | Keystore Key Deletion | Keystore deletion API | Key deleted, warning audit event logged | PASS |
| **LC-07** | Audit Log Privacy | Sanitized log policy | Zero private keys or decrypted payloads in audit logs | PASS |

---

### 3.3 Security Invariants & Honesty (`tests/security.test.ts`)
| Test ID | Test Case | Target Invariant | Expected Outcome | Status |
| :--- | :--- | :--- | :--- | :---: |
| **SEC-01** | Honest Security Level Reporting | Anti-fabrication rule | Software/Simulator reports `SOFTWARE_SIMULATED`, never faking hardware | PASS |
| **SEC-02** | Private Key Non-Exportability | Security boundary | No raw private key bytes present in JS metadata or package | PASS |
| **SEC-03** | CSPRNG Randomness Compliance | Strong cryptographic entropy | No use of Math.random() in security pipelines | PASS |
| **SEC-04** | Offline Self-Test Execution | 100% Zero-Network guarantee | Self-test passes entirely offline | PASS |
| **SEC-05** | Sanitized Diagnostics Export | Safe support reporting | Exported JSON contains only public metadata & hashes | PASS |

---

## 4. Native Hardware Test Procedures

### Android Hardware Test (StrongBox / TEE)
1. Deploy APK to physical Android device (e.g., Google Pixel 7/8/9 with Titan M2, or Samsung Galaxy S23/S24 with Knox Vault).
2. Launch TrustRoot Mobile.
3. Observe detected security level:
   - On devices with discrete HSM: `STRONGBOX`
   - On devices with ARM TrustZone: `TRUSTED_ENVIRONMENT`
   - On emulators: `SOFTWARE_BACKED` (honestly displayed)
4. Confirm Key Attestation displays `VALID_HARDWARE_ATTESTED` with genuine X.509 certificate chain.

### iOS Hardware Test (Apple Secure Enclave)
1. Deploy to physical iPhone / iPad with Apple A7 or newer.
2. Launch TrustRoot Mobile.
3. Verify detected security level displays `SECURE_ENCLAVE`.
4. Run challenge signing to execute ECDSA `secp256r1` signature inside the Secure Enclave coprocessor.
