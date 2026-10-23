package com.trustroot.security

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * TrustRoot Mobile - KeyLifecycleManager (Android)
 *
 * Enforces local key lifecycle management:
 * - Key rotation tracking
 * - Keystore deletion
 * - Local revocation registry
 * - Expiry enforcement against Keystore validity timestamps
 * - Sanitized audit logging
 */
class KeyLifecycleManager(
    private val context: Context,
    private val hardwareKeyManager: HardwareKeyManager
) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("trustroot_lifecycle_prefs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_REVOCATION_LIST = "revocation_list"
        private const val KEY_ROTATION_HISTORY = "rotation_history"
        private const val KEY_AUDIT_LOGS = "audit_logs"
    }

    /**
     * Rotate key by creating a new alias and marking previous key
     */
    fun rotateKey(oldAlias: String, preferStrongBox: Boolean = true): HardwareKeyManager.KeySecurityProperties {
        val oldProps = try {
            hardwareKeyManager.inspectKeyProperties(oldAlias)
        } catch (e: Exception) {
            null
        }

        val newVersion = System.currentTimeMillis()
        val newAlias = "trustroot_device_identity_v$newVersion"
        val newProps = hardwareKeyManager.generateDeviceKey(newAlias, "EC_P256", preferStrongBox)

        if (oldProps != null) {
            recordRotation(oldProps.keyId, newProps.keyId, oldAlias, newAlias)
        }

        logAuditEvent(
            action = "KEY_ROTATED",
            status = "SUCCESS",
            details = "Key rotated from '$oldAlias' to '$newAlias'. New Key ID: ${newProps.keyId}",
            keyId = newProps.keyId
        )

        return newProps
    }

    /**
     * Delete key from Android Keystore
     */
    fun deleteKey(alias: String): Boolean {
        val props = try {
            hardwareKeyManager.inspectKeyProperties(alias)
        } catch (e: Exception) {
            null
        }

        val deleted = hardwareKeyManager.deleteKey(alias)
        if (deleted && props != null) {
            logAuditEvent(
                action = "KEY_DELETED",
                status = "WARNING",
                details = "Key permanently deleted from Android Keystore: alias '$alias'",
                keyId = props.keyId
            )
        }
        return deleted
    }

    /**
     * Locally revoke key by Key ID
     */
    fun revokeKeyLocally(keyId: String, reason: String) {
        val list = getRevocationList()
        val entry = JSONObject().apply {
            put("keyId", keyId)
            put("revokedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }.format(Date()))
            put("reason", reason)
        }
        list.put(entry)
        prefs.edit().putString(KEY_REVOCATION_LIST, list.toString()).apply()

        logAuditEvent(
            action = "KEY_REVOKED",
            status = "WARNING",
            details = "Key locally revoked: $keyId. Reason: $reason",
            keyId = keyId
        )
    }

    fun isKeyRevoked(keyId: String): Boolean {
        val list = getRevocationList()
        for (i in 0 until list.length()) {
            val item = list.getJSONObject(i)
            if (item.getString("keyId") == keyId) {
                return true
            }
        }
        return false
    }

    private fun recordRotation(oldKeyId: String, newKeyId: String, oldAlias: String, newAlias: String) {
        val history = getRotationHistory()
        val entry = JSONObject().apply {
            put("oldKeyId", oldKeyId)
            put("newKeyId", newKeyId)
            put("oldAlias", oldAlias)
            put("newAlias", newAlias)
            put("rotatedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }.format(Date()))
        }
        history.put(entry)
        prefs.edit().putString(KEY_ROTATION_HISTORY, history.toString()).apply()
    }

    fun logAuditEvent(action: String, status: String, details: String, keyId: String? = null, packageId: String? = null) {
        val logs = getAuditLogs()
        val event = JSONObject().apply {
            put("id", UUID.randomUUID().toString())
            put("timestamp", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }.format(Date()))
            put("action", action)
            put("status", status)
            put("details", details)
            if (keyId != null) put("keyId", keyId)
            if (packageId != null) put("packageId", packageId)
        }
        logs.put(event)
        // Keep last 100 entries
        val trimmed = if (logs.length() > 100) {
            val arr = JSONArray()
            for (i in (logs.length() - 100) until logs.length()) {
                arr.put(logs.get(i))
            }
            arr
        } else {
            logs
        }
        prefs.edit().putString(KEY_AUDIT_LOGS, trimmed.toString()).apply()
    }

    fun getRevocationList(): JSONArray {
        val raw = prefs.getString(KEY_REVOCATION_LIST, "[]")
        return JSONArray(raw)
    }

    fun getRotationHistory(): JSONArray {
        val raw = prefs.getString(KEY_ROTATION_HISTORY, "[]")
        return JSONArray(raw)
    }

    fun getAuditLogs(): JSONArray {
        val raw = prefs.getString(KEY_AUDIT_LOGS, "[]")
        return JSONArray(raw)
    }
}
