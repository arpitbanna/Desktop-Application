package com.trustroot.security

import android.util.Base64
import org.json.JSONObject
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * TrustRoot Mobile - PayloadEncryptionManager (Android)
 *
 * Implements hardware-backed hybrid encryption:
 * - Fresh CSPRNG AES-256 session key
 * - 96-bit unique nonce for AES-GCM
 * - 128-bit authentication tag with AAD metadata
 * - RSA-OAEP (SHA-256 / MGF1-SHA256) recipient key wrapping
 * - Hardware device signature binding
 * - Secure in-memory wiping of ephemeral keys
 */
class PayloadEncryptionManager(private val hardwareKeyManager: HardwareKeyManager) {

    private val secureRandom = SecureRandom()

    data class EncryptedPackageResult(
        val packageJson: String,
        val packageId: String,
        val elapsedMs: Long
    )

    /**
     * Perform hybrid encryption on binary payload
     */
    fun encryptPayload(
        payloadBytes: ByteArray,
        payloadType: String,
        recipientPublicKeyPem: String,
        recipientKeyId: String,
        deviceKeyAlias: String
    ): EncryptedPackageResult {
        val startTime = System.currentTimeMillis()

        if (payloadBytes.isEmpty()) {
            throw IllegalArgumentException("Payload cannot be empty")
        }

        val deviceKeyProps = hardwareKeyManager.inspectKeyProperties(deviceKeyAlias)

        // 1. Calculate Payload SHA-256
        val payloadDigest = MessageDigest.getInstance("SHA-256").digest(payloadBytes)
        val payloadSha256 = payloadDigest.joinToString("") { "%02x".format(it) }

        val packageId = "pkg_" + UUID.randomUUID().toString().replace("-", "").take(16)
        val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val createdAt = isoFormat.format(Date())

        // 2. Generate Ephemeral AES-256 Key (32 bytes) & Nonce (12 bytes) via CSPRNG
        val aesKeyBytes = ByteArray(32)
        val nonceBytes = ByteArray(12)
        secureRandom.nextBytes(aesKeyBytes)
        secureRandom.nextBytes(nonceBytes)

        // 3. Form Authenticated Additional Data (AAD)
        val aadJson = JSONObject().apply {
            put("version", "1.0")
            put("packageId", packageId)
            put("createdAt", createdAt)
            put("recipientKeyId", recipientKeyId)
            put("deviceKeyId", deviceKeyProps.keyId)
            put("payloadSha256", payloadSha256)
        }
        val aadBytes = aadJson.toString().toByteArray(Charsets.UTF_8)

        // 4. Encrypt with AES-256-GCM
        val aesKeySpec = SecretKeySpec(aesKeyBytes, "AES")
        val gcmSpec = GCMParameterSpec(128, nonceBytes)
        val gcmCipher = Cipher.getInstance("AES/GCM/NoPadding")
        gcmCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, gcmSpec)
        gcmCipher.updateAAD(aadBytes)

        val ciphertextWithTag = gcmCipher.doFinal(payloadBytes)

        // Separate 128-bit (16-byte) authentication tag from ciphertext
        val tagLength = 16
        val ciphertextLength = ciphertextWithTag.size - tagLength
        val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextLength)
        val authTag = ciphertextWithTag.copyOfRange(ciphertextLength, ciphertextWithTag.size)

        // 5. Wrap AES Key with Recipient RSA-OAEP
        val recipientPublicKey = parsePublicKeyFromPem(recipientPublicKeyPem)
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaepSpec = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        )
        rsaCipher.init(Cipher.WRAP_MODE, recipientPublicKey, oaepSpec)
        val wrappedAesKey = rsaCipher.wrap(aesKeySpec)

        // 6. Security: Immediately wipe raw ephemeral AES key bytes from RAM
        Arrays.fill(aesKeyBytes, 0.toByte())

        // 7. Base64 encode components
        val ciphertextBase64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
        val nonceBase64 = Base64.encodeToString(nonceBytes, Base64.NO_WRAP)
        val authTagBase64 = Base64.encodeToString(authTag, Base64.NO_WRAP)
        val wrappedAesKeyBase64 = Base64.encodeToString(wrappedAesKey, Base64.NO_WRAP)
        val aadBase64 = Base64.encodeToString(aadBytes, Base64.NO_WRAP)

        // 8. Sign Canonical Digest using Hardware Device Identity Key
        val ciphertextDigest = MessageDigest.getInstance("SHA-256").digest(ciphertext)
        val ciphertextSha256 = ciphertextDigest.joinToString("") { "%02x".format(it) }

        val canonicalString = "TRUSTROOT-v1:$packageId:$recipientKeyId:${deviceKeyProps.keyId}:$nonceBase64:$wrappedAesKeyBase64:$authTagBase64:$ciphertextSha256"
        val deviceSignature = hardwareKeyManager.signCanonicalString(deviceKeyAlias, canonicalString)

        val elapsedMs = System.currentTimeMillis() - startTime

        // 9. Assemble Encrypted Package JSON
        val packageObject = JSONObject().apply {
            put("version", "1.0")
            put("packageId", packageId)
            put("createdAt", createdAt)
            put("payloadType", payloadType)
            put("payloadSize", payloadBytes.size)
            put("payloadSha256", payloadSha256)
            put("encryptionAlgorithm", "AES-256-GCM")
            put("keyWrappingAlgorithm", "RSA-OAEP-SHA256")
            put("recipientKeyId", recipientKeyId)
            put("deviceKeyId", deviceKeyProps.keyId)
            put("nonce", nonceBase64)
            put("ciphertext", ciphertextBase64)
            put("authenticationTag", authTagBase64)
            put("wrappedAesKey", wrappedAesKeyBase64)
            put("deviceSignature", deviceSignature)
            put("securityLevel", deviceKeyProps.securityLevel)
            put("isHardwareBacked", deviceKeyProps.isHardwareBacked)
            put("aad", aadBase64)
        }

        return EncryptedPackageResult(
            packageJson = packageObject.toString(),
            packageId = packageId,
            elapsedMs = elapsedMs
        )
    }

    private fun parsePublicKeyFromPem(pem: String): java.security.PublicKey {
        val cleanPem = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")
        val keyBytes = Base64.decode(cleanPem, Base64.DEFAULT)
        val spec = X509EncodedKeySpec(keyBytes)
        return KeyFactory.getInstance("RSA").generatePublic(spec)
    }
}
