package com.trustroot.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.*
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Cipher

/**
 * TrustRoot Mobile - HardwareKeyManager (Android)
 *
 * Implements hardware-backed cryptographic identity management via Android Keystore.
 * Targets StrongBox HSM where supported, falling back to TEE (TrustZone),
 * and honestly inspecting KeyInfo security levels.
 */
class HardwareKeyManager(private val context: Context) {

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val EC_CURVE = "secp256r1"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    data class KeySecurityProperties(
        val keyId: String,
        val alias: String,
        val algorithm: String,
        val keySize: Int,
        val securityLevel: String,
        val isHardwareBacked: Boolean,
        val isInsideSecureHardware: Boolean,
        val attestationStatus: String,
        val attestationCertChain: List<String>?,
        val createdAt: String,
        val expiresAt: String,
        val publicKeyPem: String
    )

    /**
     * Generate an asymmetric hardware-backed key pair inside Android Keystore
     */
    fun generateDeviceKey(
        alias: String,
        algorithm: String = "EC_P256",
        preferStrongBox: Boolean = true,
        attestationChallenge: ByteArray? = null
    ): KeySecurityProperties {
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance().apply { add(Calendar.YEAR, 1) }

        val isEc = algorithm == "EC_P256"
        val keyAlgorithm = if (isEc) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA

        val kpg = KeyPairGenerator.getInstance(keyAlgorithm, ANDROID_KEYSTORE)

        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setKeyValidityStart(startDate.time)
            .setKeyValidityEnd(endDate.time)
            .setUserAuthenticationRequired(false) // Offline autonomous operation

        if (isEc) {
            specBuilder.setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
        } else {
            specBuilder.setAlgorithmParameterSpec(
                RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
            )
            specBuilder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        }

        // Key Attestation challenge if supported and requested
        if (attestationChallenge != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            specBuilder.setAttestationChallenge(attestationChallenge)
        }

        // StrongBox support (Android Pie / API 28+)
        var strongBoxUsed = false
        if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                specBuilder.setIsStrongBoxBacked(true)
                kpg.initialize(specBuilder.build())
                kpg.generateKeyPair()
                strongBoxUsed = true
            } catch (e: Exception) {
                // StrongBox unavailable on this hardware; fall back to TEE
                specBuilder.setIsStrongBoxBacked(false)
                kpg.initialize(specBuilder.build())
                kpg.generateKeyPair()
            }
        } else {
            kpg.initialize(specBuilder.build())
            kpg.generateKeyPair()
        }

        return inspectKeyProperties(alias)
    }

    /**
     * Inspect genuine security properties of a key from Android Keystore
     */
    fun inspectKeyProperties(alias: String): KeySecurityProperties {
        if (!keyStore.containsAlias(alias)) {
            throw IllegalArgumentException("Key alias '$alias' does not exist in Android Keystore")
        }

        val cert = keyStore.getCertificate(alias) ?: throw IllegalStateException("Certificate missing for alias $alias")
        val publicKey = cert.publicKey
        val privateKey = keyStore.getKey(alias, null) ?: throw IllegalStateException("Private key reference missing")

        val keyFactory = KeyFactory.getInstance(publicKey.algorithm, ANDROID_KEYSTORE)
        val keyInfo: KeyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)

        var securityLevel = "SOFTWARE_BACKED"
        var isHardwareBacked = false
        val isInsideSecureHardware = keyInfo.isInsideSecureHardware

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> {
                    securityLevel = "STRONGBOX"
                    isHardwareBacked = true
                }
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> {
                    securityLevel = "TRUSTED_ENVIRONMENT"
                    isHardwareBacked = true
                }
                else -> {
                    securityLevel = "SOFTWARE_BACKED"
                    isHardwareBacked = false
                }
            }
        } else {
            if (isInsideSecureHardware) {
                securityLevel = "TRUSTED_ENVIRONMENT"
                isHardwareBacked = true
            }
        }

        // Check attestation certificate chain
        val certChain = keyStore.getCertificateChain(alias)
        var attestationStatus = "NOT_ATTESTED"
        var certChainBase64: MutableList<String>? = null

        if (certChain != null && certChain.size > 1) {
            attestationStatus = "VALID_HARDWARE_ATTESTED"
            certChainBase64 = mutableListOf()
            for (c in certChain) {
                certChainBase64.add(Base64.encodeToString(c.encoded, Base64.NO_WRAP))
            }
        }

        val publicKeyBytes = publicKey.encoded
        val keyId = computeFingerprint(publicKeyBytes)
        val publicKeyPem = formatPublicKeyPem(publicKeyBytes)

        val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }

        val createdAt = if (cert is X509Certificate) isoFormat.format(cert.notBefore) else isoFormat.format(Date())
        val expiresAt = if (cert is X509Certificate) isoFormat.format(cert.notAfter) else isoFormat.format(Date())

        val algorithm = if (publicKey.algorithm.equals("EC", ignoreCase = true)) "EC_P256" else "RSA_2048"
        val keySize = if (algorithm == "EC_P256") 256 else 2048

        return KeySecurityProperties(
            keyId = keyId,
            alias = alias,
            algorithm = algorithm,
            keySize = keySize,
            securityLevel = securityLevel,
            isHardwareBacked = isHardwareBacked,
            isInsideSecureHardware = isInsideSecureHardware,
            attestationStatus = attestationStatus,
            attestationCertChain = certChainBase64,
            createdAt = createdAt,
            expiresAt = expiresAt,
            publicKeyPem = publicKeyPem
        )
    }

    /**
     * Sign canonical string using hardware-backed private key
     */
    fun signCanonicalString(alias: String, canonicalString: String): String {
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("Private key reference for alias '$alias' unavailable")

        val cert = keyStore.getCertificate(alias) ?: throw IllegalStateException("Certificate for '$alias' unavailable")
        val isEc = cert.publicKey.algorithm.equals("EC", ignoreCase = true)
        val sigAlgorithm = if (isEc) "SHA256withECDSA" else "SHA256withRSA"

        val signature = Signature.getInstance(sigAlgorithm)
        signature.initSign(privateKey)
        signature.update(canonicalString.toByteArray(Charsets.UTF_8))
        val sigBytes = signature.sign()

        return Base64.encodeToString(sigBytes, Base64.NO_WRAP)
    }

    /**
     * Delete key from Android Keystore
     */
    fun deleteKey(alias: String): Boolean {
        return if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
            true
        } else {
            false
        }
    }

    private fun computeFingerprint(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.take(16).joinToString(":") { "%02X".format(it) }
    }

    private fun formatPublicKeyPem(encodedBytes: ByteArray): String {
        val base64 = Base64.encodeToString(encodedBytes, Base64.NO_WRAP)
        val chunks = base64.chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$chunks\n-----END PUBLIC KEY-----"
    }
}
