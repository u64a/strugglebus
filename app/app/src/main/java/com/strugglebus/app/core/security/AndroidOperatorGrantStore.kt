package com.strugglebus.app.core.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.strugglebus.app.core.OperatorGrantStore
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AndroidOperatorGrantStore(context: Context) : OperatorGrantStore {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    override fun hasGrant(): Boolean = runCatching {
        preferences.contains(CIPHERTEXT) &&
            preferences.contains(DEVICE_ID) &&
            loadPrivateKey() != null
    }.getOrDefault(false)

    override fun deviceId(): String? = preferences.getString(DEVICE_ID, null)

    override fun save(deviceId: String, grantSecret: String) {
        require(deviceId.isNotBlank()) { "Device ID is empty." }
        require(grantSecret.isNotBlank()) { "Write grant is empty." }
        clear()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, createKeyPair())
        val ciphertext = cipher.doFinal(grantSecret.toByteArray(Charsets.UTF_8))
        val chatCipher = Cipher.getInstance(CHAT_TRANSFORMATION)
        chatCipher.init(Cipher.ENCRYPT_MODE, createChatKey())
        val chatCiphertext = chatCipher.iv + chatCipher.doFinal(grantSecret.toByteArray(Charsets.UTF_8))
        check(
            preferences.edit()
                .putString(DEVICE_ID, deviceId)
                .putString(CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString(CHAT_CIPHERTEXT, Base64.encodeToString(chatCiphertext, Base64.NO_WRAP))
                .commit(),
        ) { "Unable to persist the protected write grant." }
    }

    override fun chatSecret(): String? = runCatching {
        val stored = Base64.decode(preferences.getString(CHAT_CIPHERTEXT, null) ?: return null, Base64.NO_WRAP)
        val key = keyStore().getKey(CHAT_KEY_ALIAS, null) as? SecretKey ?: return null
        Cipher.getInstance(CHAT_TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, stored, 0, GCM_IV_BYTES))
            doFinal(stored, GCM_IV_BYTES, stored.size - GCM_IV_BYTES).toString(Charsets.UTF_8)
        }
    }.getOrNull()

    override fun createDecryptionCipher(): Cipher {
        val privateKey = loadPrivateKey() ?: error("Operator access is not configured.")
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, privateKey)
        }
    }

    override fun decrypt(cipher: Cipher): String {
        val ciphertext = preferences.getString(CIPHERTEXT, null)
            ?: error("The protected write grant is unavailable.")
        return cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
            .toString(Charsets.UTF_8)
    }

    override fun clear() {
        preferences.edit().clear().commit()
        keyStore().run {
            if (containsAlias(KEY_ALIAS)) deleteEntry(KEY_ALIAS)
            if (containsAlias(CHAT_KEY_ALIAS)) deleteEntry(CHAT_KEY_ALIAS)
        }
    }

    /** Hardware-backed but usable without user authentication, so chat needs no prompt. */
    private fun createChatKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                CHAT_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return generator.generateKey()
    }

    private fun createKeyPair(): PublicKey {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(2048)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE,
        )
        generator.initialize(builder.build())
        return generator.generateKeyPair().public
    }

    private fun loadPrivateKey(): PrivateKey? = keyStore().getKey(KEY_ALIAS, null) as? PrivateKey

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "struggleapp.operator-grant.v1"
        const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        const val PREFERENCES = "protected_operator_grant"
        const val DEVICE_ID = "device_id"
        const val CIPHERTEXT = "ciphertext"
        const val CHAT_KEY_ALIAS = "struggleapp.operator-chat-grant.v1"
        const val CHAT_TRANSFORMATION = "AES/GCM/NoPadding"
        const val CHAT_CIPHERTEXT = "chat_ciphertext"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
    }
}
