# Changelog
All notable changes to the **TrustRoot Mobile** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-24
### Added
- **Hardware Root of Trust**: Native key generation modules for Android Keystore (StrongBox HSM / TEE) and Apple Secure Enclave (EC P-256).
- **Private Key Non-Exportability**: Silicon-enforced containment ensuring private keys cannot be dumped from application memory or OS kernel.
- **Offline Hybrid Encryption**: Ephemeral AES-256-GCM bulk payload encryption with 96-bit unique nonces and Authenticated Additional Data (AAD).
- **Asymmetric Key Wrapping**: Recipient RSA-OAEP wrapping with explicit SHA-256 and MGF1/SHA-256 digest parameters.
- **Canonical Package Signing**: Hardware digital signatures binding package metadata, recipient key ID, nonce, wrapped key, and ciphertext digest.
- **Verification Lab & Tamper Suite**: Authenticated test recipient decryption and interactive adversary tamper injection (ciphertext, tag, AAD, and signature tampering).
- **Key Lifecycle Manager**: Local key rotation, expiry enforcement, local revocation registry, and keystore deletion with user safety warnings.
- **Security Diagnostics**: Platform capability inspection, zero-network self-test benchmark, sanitized audit logging, and exportable JSON diagnostics.
- **Cybersecurity Dark UI**: Polished 7-screen React Native interface adhering to accessibility and visual contrast standards.
- **Automated Test Suite**: 23 Jest tests covering hybrid encryption, tamper rejection, key policy, and privacy invariants (86.7% coverage).
- **CI & Documentation**: Comprehensive technical guides (Architecture, Threat Model, Cryptography, Platform Limitations, Testing, Demo Guide, and GitHub Actions CI workflow).

### Fixed
- Fixed iOS bridge export for `rotateDeviceKey` in `TrustRootSecurityBridge.swift` and `TrustRootSecurityBridge.m`.
- Fixed `getKeyMetadata` in `HardwareKeyManager.swift` to inspect existing Keychain attributes without regenerating key pairs.
- Added native encryption delegation in `packageService.ts` for native mobile runtimes.
- Configured clean `.gitignore` to protect credentials, keystores, and build outputs.
