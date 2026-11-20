package com.llmsecurityscanner.data.security

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

class SecureTokenStorage(context: Context) {

    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private val prefs: SharedPreferences = try {
        EncryptedSharedPreferences.create(
            "llm_security_secure_prefs",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (e: Exception) {
        // Fallback for devices/emulators with Keystore provider quirks in dev
        context.getSharedPreferences("llm_security_fallback_prefs", Context.MODE_PRIVATE)
    }

    companion object {
        private const val KEY_AUTH_TOKEN = "key_auth_token"
        private const val KEY_USER_ID = "key_user_id"
        private const val KEY_DEV_MODE = "key_dev_mode"
        private const val KEY_BASE_URL = "key_base_url"
        const val DEFAULT_EMULATOR_URL = "http://10.0.2.2:8000"
    }

    fun saveToken(token: String?) {
        prefs.edit().putString(KEY_AUTH_TOKEN, token?.trim()).apply()
    }

    fun getToken(): String? {
        val t = prefs.getString(KEY_AUTH_TOKEN, null)
        return if (t.isNullOrBlank()) null else t
    }

    fun saveUserId(userId: String) {
        prefs.edit().putString(KEY_USER_ID, userId.trim()).apply()
    }

    fun getUserId(): String {
        return prefs.getString(KEY_USER_ID, "default_user") ?: "default_user"
    }

    fun setDevMode(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_DEV_MODE, enabled).apply()
    }

    fun isDevMode(): Boolean {
        return prefs.getBoolean(KEY_DEV_MODE, true)
    }

    fun saveBaseUrl(url: String) {
        var cleanUrl = url.trim()
        if (!cleanUrl.endsWith("/")) {
            cleanUrl += "/"
        }
        prefs.edit().putString(KEY_BASE_URL, cleanUrl).apply()
    }

    fun getBaseUrl(): String {
        return prefs.getString(KEY_BASE_URL, "$DEFAULT_EMULATOR_URL/") ?: "$DEFAULT_EMULATOR_URL/"
    }

    fun clearAuth() {
        prefs.edit().remove(KEY_AUTH_TOKEN).apply()
    }
}
