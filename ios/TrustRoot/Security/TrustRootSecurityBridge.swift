import Foundation
import React

/**
 * TrustRoot Mobile - React Native iOS Native Module Bridge
 */
@objc(TrustRootSecurityModule)
public class TrustRootSecurityBridge: NSObject {

    private let hardwareKeyManager = HardwareKeyManager()
    private lazy var encryptionManager = PayloadEncryptionManager(hardwareKeyManager: hardwareKeyManager)

    @objc
    public static func requiresMainQueueSetup() -> Bool {
        return false
    }

    @objc
    public func generateDeviceKey(
        _ alias: String,
        algorithm: String,
        preferStrongBox: Bool,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        do {
            let metadata = try hardwareKeyManager.generateDeviceKey(tag: alias, preferSecureEnclave: preferStrongBox)
            resolve(metadata)
        } catch {
            reject("KEY_GEN_FAILED", error.localizedDescription, error)
        }
    }

    @objc
    public func getKeyMetadata(
        _ alias: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        do {
            let metadata = try hardwareKeyManager.inspectKeyProperties(tag: alias)
            resolve(metadata)
        } catch {
            resolve(nil)
        }
    }

    @objc
    public func rotateDeviceKey(
        _ oldAlias: String,
        preferStrongBox: Bool,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        do {
            let metadata = try hardwareKeyManager.rotateKey(oldTag: oldAlias, preferSecureEnclave: preferStrongBox)
            resolve(metadata)
        } catch {
            reject("ROTATION_FAILED", error.localizedDescription, error)
        }
    }

    @objc
    public func getHardwareSecurityLevel(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let level = HardwareKeyManager.isSecureEnclaveSupported() ? "SECURE_ENCLAVE" : "SOFTWARE_BACKED"
        resolve(level)
    }

    @objc
    public func signPayload(
        _ alias: String,
        canonicalString: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        do {
            let signature = try hardwareKeyManager.signCanonicalString(tag: alias, canonicalString: canonicalString)
            resolve(signature)
        } catch {
            reject("SIGN_FAILED", error.localizedDescription, error)
        }
    }

    @objc
    public func encryptPayload(
        _ payloadBase64: String,
        payloadType: String,
        recipientPublicKeyPem: String,
        recipientKeyId: String,
        deviceKeyAlias: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let data = Data(base64Encoded: payloadBase64) else {
            reject("INVALID_PAYLOAD", "Payload base64 decoding failed", nil)
            return
        }

        do {
            let result = try encryptionManager.encryptPayload(
                payloadData: data,
                payloadType: payloadType,
                recipientPublicKeyPem: recipientPublicKeyPem,
                recipientKeyId: recipientKeyId,
                deviceKeyTag: deviceKeyAlias
            )
            resolve(result)
        } catch {
            reject("ENCRYPT_FAILED", error.localizedDescription, error)
        }
    }

    @objc
    public func deleteDeviceKey(
        _ alias: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let deleted = hardwareKeyManager.deleteKey(tag: alias)
        resolve(deleted)
    }

    @objc
    public func getDiagnostics(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let isSE = HardwareKeyManager.isSecureEnclaveSupported()
        let diagnostics: [String: Any] = [
            "platform": "ios",
            "osVersion": "iOS " + ProcessInfo.processInfo.operatingSystemVersionString,
            "deviceModel": "Apple Mobile Device",
            "strongBoxAvailable": false,
            "teeAvailable": false,
            "secureEnclaveAvailable": isSE,
            "keyAttestationSupported": false,
            "rsaOaepHardwareSupported": false,
            "detectedSecurityLevel": isSE ? "SECURE_ENCLAVE" : "SOFTWARE_BACKED",
            "offlineStatus": "OFFLINE_VERIFIED",
            "activeKeysCount": 1,
            "auditEventsCount": 10,
            "supportedDigests": ["SHA-256", "SHA-384", "SHA-512"],
            "supportedAlgorithms": ["EC_P256", "AES-256-GCM", "RSA-OAEP-SHA256"]
        ]
        resolve(diagnostics)
    }
}
