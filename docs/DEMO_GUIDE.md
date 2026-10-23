# TrustRoot Mobile: Hackathon Live Demonstration Guide

## 1. Overview & Setup
This guide provides an exact, reproducible **3 to 5 minute live demonstration workflow** for hackathon judges and evaluators, showcasing offline hardware root of trust, hybrid encryption, and tamper detection.

---

## 2. Live Demo Script (Step-by-Step)

### Step 1: Launch & Hardware Capability Inspection (Time: 0:00 - 0:45)
1. Launch the application.
2. Direct the evaluator's attention to the **Security Dashboard**:
   - Point out the **Green Airplane Mode Badge** ("100% OFFLINE — ZERO NETWORK DEPENDENCY").
   - Highlight the **Detected Security Level** (`STRONGBOX`, `TEE`, `SECURE_ENCLAVE`, or `SOFTWARE_SIMULATED`).
   - Emphasize the **Authenticity Commitment**: the app strictly displays actual hardware capabilities and never displays a fake "100% Secure" label.

### Step 2: Device Identity Key & Non-Exportability (Time: 0:45 - 1:30)
1. Navigate to the **Identity** tab.
2. Point out:
   - **Key ID (Public Key SHA-256 Fingerprint)**: Generated inside platform secure keystore.
   - **Private Key Non-Exportability Banner**: Explain that private key bits cannot be exported, read into application memory, or saved to disk.
   - **Hardware Attestation Status**: Shows whether an X.509 chain validates hardware backing.
3. Tap **Sign with Hardware Key**:
   - The device signs a live challenge string using ECDSA inside the secure hardware.
   - Show that the public key verifies the signature instantly offline.

### Step 3: Offline Airplane Mode Hybrid Encryption (Time: 1:30 - 2:45)
1. **Enable Airplane Mode** on the device to prove 100% zero-network operation.
2. Navigate to the **Encrypt** tab.
3. Select a synthetic sample payload:
   - Choose `synthetic_resident_face.png` (simulated face image) or `offline_aadhaar_kyc.xml`.
4. Point out the recipient public key selection:
   - Select **UIDAI Offline Demo Recipient (RSA-2048)**.
   - Explain the crucial architectural distinction: *"The image is encrypted for the recipient's public key using fresh AES-256-GCM, while the device's hardware key signs the package digest to prove origin authenticity."*
5. Tap **Start Hybrid Encryption**:
   - Show elapsed time (typically ~2-5ms).
   - Review the generated package:
     - `nonce` (96-bit CSPRNG)
     - `wrappedAesKey` (RSA-OAEP with SHA-256)
     - `authenticationTag` (128-bit AES-GCM tag)
     - `deviceSignature` (Hardware origin signature)

### Step 4: Verification & Tamper Detection Lab (Time: 2:45 - 3:45)
1. Tap **Open in Verification & Tamper Lab** (or switch to the **Lab** tab).
2. Tap **Verify Integrity & Decrypt**:
   - The test recipient private key unwraps the AES session key.
   - AES-GCM verifies the 128-bit authentication tag and header AAD.
   - The device signature is verified.
   - The recovered payload SHA-256 hash matches the original digest **byte-for-byte**.
3. Now demonstrate **Adversary Tamper Detection**:
   - Tap **Tamper Ciphertext (Flip Bits)**.
   - Tap **Verify Integrity & Decrypt**.
   - **Observe Rejection**: The application displays an immediate cryptographic failure alert: *"Authenticated GCM tag validation failed: unable to authenticate data"*.
   - Tap **Tamper Device Signature** to show signature forgery detection.

### Step 5: Key Lifecycle & Rotation (Time: 3:45 - 4:30)
1. Switch to the **Lifecycle** tab.
2. Point out the **Key Rotation Timeline**:
   - Shows old key ID, new key ID, and rotation timestamps.
3. Tap **Revoke This Key Locally**:
   - Show that the key transitions to `LOCALLY REVOKED`.
   - Attempting to sign or encrypt with this key is immediately rejected by policy.
4. Show the **Sanitized Audit Log** in the Diagnostics tab, proving that zero private keys or raw images were ever logged.

### Step 6: Concluding Security & Architectural Summary (Time: 4:30 - 5:00)
1. Summarize:
   - Genuine hardware root of trust on Android (Keystore/StrongBox) and iOS (Secure Enclave).
   - Honest architectural boundaries: Secure Enclave uses EC P-256 for identity; RSA-OAEP wrapping executes in platform crypto.
   - 100% offline, airplane mode operational assurance.
   - Zero hardcoded production secrets, zero fake claims.
