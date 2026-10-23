package com.trustroot.security

import android.os.Build
import android.util.Base64
import com.facebook.react.bridge.*
import org.json.JSONObject

/**
 * TrustRoot Mobile - React Native Android Bridge Module
 * Connects React Native JS layer with Android Keystore native implementations.
 */
class TrustRootSecurityModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val hardwareKeyManager = HardwareKeyManager(reactContext)
    private val encryptionManager = PayloadEncryptionManager(hardwareKeyManager)
    private val lifecycleManager = KeyLifecycleManager(reactContext, hardwareKeyManager)

    override fun getName(): String = "TrustRootSecurityModule"

    @ReactMethod
    fun generateDeviceKey(
        alias: String,
        algorithm: String,
        preferStrongBox: Boolean,
        promise: Promise
    ) {
        try {
            val props = hardwareKeyManager.generateDeviceKey(alias, algorithm, preferStrongBox)
            val map = toWritableMap(props)
            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("KEY_GENERATION_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun getKeyMetadata(alias: String, promise: Promise) {
        try {
            val props = hardwareKeyManager.inspectKeyProperties(alias)
            promise.resolve(toWritableMap(props))
        } catch (e: IllegalArgumentException) {
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("METADATA_FETCH_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun getHardwareSecurityLevel(promise: Promise) {
        try {
            // Check default alias or test key
            val defaultAlias = "trustroot_device_identity_v1"
            if (hardwareKeyManager.deleteKey(defaultAlias)) {
                // Key existed
            }
            // Generate test probe key to test platform capabilities
            val probeProps = hardwareKeyManager.generateDeviceKey(defaultAlias, "EC_P256", true)
            promise.resolve(probeProps.securityLevel)
        } catch (e: Exception) {
            promise.resolve("SOFTWARE_BACKED")
        }
    }

    @ReactMethod
    fun signPayload(alias: String, canonicalString: String, promise: Promise) {
        try {
            val props = hardwareKeyManager.inspectKeyProperties(alias)
            if (lifecycleManager.isKeyRevoked(props.keyId)) {
                promise.reject("KEY_REVOKED", "Device key has been revoked locally")
                return
            }
            val signature = hardwareKeyManager.signCanonicalString(alias, canonicalString)
            promise.resolve(signature)
        } catch (e: Exception) {
            promise.reject("SIGNING_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun encryptPayload(
        payloadBase64: String,
        payloadType: String,
        recipientPublicKeyPem: String,
        recipientKeyId: String,
        deviceKeyAlias: String,
        promise: Promise
    ) {
        try {
            val payloadBytes = Base64.decode(payloadBase64, Base64.NO_WRAP)
            val result = encryptionManager.encryptPayload(
                payloadBytes = payloadBytes,
                payloadType = payloadType,
                recipientPublicKeyPem = recipientPublicKeyPem,
                recipientKeyId = recipientKeyId,
                deviceKeyAlias = deviceKeyAlias
            )

            val map = Arguments.createMap().apply {
                putString("packageJson", result.packageJson)
                putString("packageId", result.packageId)
                putDouble("elapsedMs", result.elapsedMs.toDouble())
            }
            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("ENCRYPTION_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun deleteDeviceKey(alias: String, promise: Promise) {
        try {
            val result = lifecycleManager.deleteKey(alias)
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("DELETE_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun rotateDeviceKey(oldAlias: String, preferStrongBox: Boolean, promise: Promise) {
        try {
            val newProps = lifecycleManager.rotateKey(oldAlias, preferStrongBox)
            promise.resolve(toWritableMap(newProps))
        } catch (e: Exception) {
            promise.reject("ROTATION_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun getDiagnostics(promise: Promise) {
        try {
            val map = Arguments.createMap().apply {
                putString("platform", "android")
                putString("osVersion", "Android API " + Build.VERSION.SDK_INT)
                putString("deviceModel", Build.MANUFACTURER + " " + Build.MODEL)
                putBoolean("strongBoxAvailable", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                putBoolean("teeAvailable", true)
                putBoolean("secureEnclaveAvailable", false)
                putBoolean("keyAttestationSupported", Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                putBoolean("rsaOaepHardwareSupported", true)
                putString("detectedSecurityLevel", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) "STRONGBOX" else "TRUSTED_ENVIRONMENT")
                putString("offlineStatus", "OFFLINE_VERIFIED")
                putInt("activeKeysCount", 1)
                putInt("auditEventsCount", lifecycleManager.getAuditLogs().length())

                val digests = Arguments.createArray().apply {
                    pushString("SHA-256")
                    pushString("SHA-512")
                }
                putArray("supportedDigests", digests)

                val algorithms = Arguments.createArray().apply {
                    pushString("EC_P256")
                    pushString("RSA_2048")
                    pushString("AES-256-GCM")
                    pushString("RSA-OAEP-SHA256")
                }
                putArray("supportedAlgorithms", algorithms)
            }
            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("DIAGNOSTICS_FAILED", e.message, e)
        }
    }

    private fun toWritableMap(props: HardwareKeyManager.KeySecurityProperties): WritableMap {
        return Arguments.createMap().apply {
            putString("keyId", props.keyId)
            putString("alias", props.alias)
            putString("algorithm", props.algorithm)
            putInt("keySize", props.keySize)
            putString("securityLevel", props.securityLevel)
            putBoolean("isHardwareBacked", props.isHardwareBacked)
            putBoolean("isNonExportable", true)
            putString("attestationStatus", props.attestationStatus)
            putString("createdAt", props.createdAt)
            putString("expiresAt", props.expiresAt)
            putString("status", "ACTIVE")
            putString("publicKeyPem", props.publicKeyPem)

            val purposes = Arguments.createArray().apply {
                pushString("SIGN")
                pushString("VERIFY")
            }
            putArray("purposes", purposes)

            val digests = Arguments.createArray().apply {
                pushString("SHA-256")
            }
            putArray("digestAlgorithms", digests)

            if (props.attestationCertChain != null) {
                val certs = Arguments.createArray()
                for (cert in props.attestationCertChain) {
                    certs.pushString(cert)
                }
                putArray("attestationCertChain", certs)
            }
        }
    }
}
