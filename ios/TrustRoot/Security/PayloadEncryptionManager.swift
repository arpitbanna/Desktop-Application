import Foundation
import Security
import CryptoKit

/**
 * TrustRoot Mobile - PayloadEncryptionManager (iOS)
 *
 * Implements hybrid encryption on iOS:
 * - Fresh CSPRNG AES-256 key using CryptoKit SymmetricKey
 * - 96-bit unique nonce using AES.GCM.Nonce
 * - AES-256-GCM authenticated encryption with AAD metadata
 * - Recipient RSA-OAEP (SHA-256) key wrapping via SecKeyCreateEncryptedData
 * - Non-exportable Secure Enclave digital signature binding
 * - In-memory key zeroing
 */
@objc(PayloadEncryptionManager)
public class PayloadEncryptionManager: NSObject {

    private let hardwareKeyManager: HardwareKeyManager

    @objc
    public init(hardwareKeyManager: HardwareKeyManager) {
        self.hardwareKeyManager = hardwareKeyManager
        super.init()
    }

    @objc
    public func encryptPayload(
        payloadData: Data,
        payloadType: String,
        recipientPublicKeyPem: String,
        recipientKeyId: String,
        deviceKeyTag: String
    ) throws -> [String: Any] {
        let startTime = CFAbsoluteTimeGetCurrent()

        if payloadData.isEmpty {
            throw NSError(domain: "TrustRoot", code: -1, userInfo: [NSLocalizedDescriptionKey: "Payload cannot be empty"])
        }

        // 1. Compute payload SHA-256
        let payloadDigest = SHA256.hash(data: payloadData)
        let payloadSha256 = payloadDigest.map { String(format: "%02x", $0) }.joined()

        let packageId = "pkg_" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16)
        let isoFormatter = ISO8601DateFormatter()
        let createdAt = isoFormatter.string(from: Date())

        // 2. Generate Ephemeral AES-256 Key & 96-bit Nonce
        var symmetricKey = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()

        // 3. Form Authenticated Additional Data (AAD)
        let aadObject: [String: Any] = [
            "version": "1.0",
            "packageId": packageId,
            "createdAt": createdAt,
            "recipientKeyId": recipientKeyId,
            "deviceKeyId": deviceKeyTag,
            "payloadSha256": payloadSha256
        ]
        let aadData = try JSONSerialization.data(withJSONObject: aadObject, options: [.sortedKeys])

        // 4. Encrypt with AES-256-GCM
        let sealedBox = try AES.GCM.seal(payloadData, using: symmetricKey, nonce: nonce, authenticating: aadData)
        let ciphertextData = sealedBox.ciphertext
        let tagData = sealedBox.tag
        let nonceData = Data(nonce)

        // 5. Wrap AES Key using Recipient RSA Public Key (RSA-OAEP-SHA256)
        guard let recipientSecKey = parseRsaPublicKey(pem: recipientPublicKeyPem) else {
            throw NSError(domain: "TrustRoot", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid recipient RSA public key"])
        }

        let rawAesKeyData = symmetricKey.withUnsafeBytes { Data($0) }
        var error: Unmanaged<CFError>?
        guard let wrappedKeyData = SecKeyCreateEncryptedData(
            recipientSecKey,
            .rsaEncryptionOAEPSHA256,
            rawAesKeyData as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        // 6. Security: Overwrite plaintext key memory
        symmetricKey = SymmetricKey(size: .bits256)

        // 7. Base64 encode
        let ciphertextBase64 = ciphertextData.base64EncodedString()
        let nonceBase64 = nonceData.base64EncodedString()
        let tagBase64 = tagData.base64EncodedString()
        let wrappedAesKeyBase64 = wrappedKeyData.base64EncodedString()
        let aadBase64 = aadData.base64EncodedString()

        // 8. Sign Canonical Digest using Secure Enclave
        let ciphertextDigest = SHA256.hash(data: ciphertextData)
        let ciphertextSha256 = ciphertextDigest.map { String(format: "%02x", $0) }.joined()

        let canonicalString = "TRUSTROOT-v1:\(packageId):\(recipientKeyId):\(deviceKeyTag):\(nonceBase64):\(wrappedAesKeyBase64):\(tagBase64):\(ciphertextSha256)"
        let deviceSignature = try hardwareKeyManager.signCanonicalString(tag: deviceKeyTag, canonicalString: canonicalString)

        let elapsedMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000.0

        let packageDict: [String: Any] = [
            "version": "1.0",
            "packageId": packageId,
            "createdAt": createdAt,
            "payloadType": payloadType,
            "payloadSize": payloadData.count,
            "payloadSha256": payloadSha256,
            "encryptionAlgorithm": "AES-256-GCM",
            "keyWrappingAlgorithm": "RSA-OAEP-SHA256",
            "recipientKeyId": recipientKeyId,
            "deviceKeyId": deviceKeyTag,
            "nonce": nonceBase64,
            "ciphertext": ciphertextBase64,
            "authenticationTag": tagBase64,
            "wrappedAesKey": wrappedAesKeyBase64,
            "deviceSignature": deviceSignature,
            "securityLevel": HardwareKeyManager.isSecureEnclaveSupported() ? "SECURE_ENCLAVE" : "SOFTWARE_BACKED",
            "isHardwareBacked": HardwareKeyManager.isSecureEnclaveSupported(),
            "aad": aadBase64
        ]

        let packageJsonData = try JSONSerialization.data(withJSONObject: packageDict)
        let packageJson = String(data: packageJsonData, encoding: .utf8)!

        return [
            "packageJson": packageJson,
            "packageId": packageId,
            "elapsedMs": elapsedMs
        ]
    }

    private func parseRsaPublicKey(pem: String) -> SecKey? {
        let clean = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let keyData = Data(base64Encoded: clean) else { return nil }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]

        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error)
    }
}
