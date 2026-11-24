package com.strugglebus.app.core.security

import android.content.Context
import com.strugglebus.app.core.ProfileStore
import java.io.File
import java.util.UUID

data class StoredMobileSession(
    val endpoint: String,
    val credential: String,
    val caDer: ByteArray,
    val lastAcceptedSequence: Long,
)

class AndroidProfileStore(
    context: Context,
    private val credentialStore: CredentialStore,
) : ProfileStore {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val caFile = File(context.noBackupFilesDir, CA_FILE)
    private val cursorLock = Any()

    override fun isEnrolled(): Boolean {
        if (!preferences.contains(ENDPOINT) || !caFile.isFile) return false
        return runCatching { credentialStore.load() != null }.getOrDefault(false)
    }

    override fun deviceInstanceId(): String {
        preferences.getString(DEVICE_INSTANCE_ID, null)?.let { return it }
        val id = UUID.randomUUID().toString()
        check(preferences.edit().putString(DEVICE_INSTANCE_ID, id).commit()) {
            "Unable to persist the device instance ID."
        }
        return id
    }

    override fun enrollmentRequestId(): String {
        preferences.getString(ENROLLMENT_REQUEST_ID, null)?.let { return it }
        val id = UUID.randomUUID().toString()
        check(preferences.edit().putString(ENROLLMENT_REQUEST_ID, id).commit()) {
            "Unable to persist the enrollment request ID."
        }
        return id
    }

    override fun saveEnrollment(endpoint: String, credential: String, caDer: ByteArray) {
        credentialStore.save(credential)
        try {
            caFile.writeBytes(caDer)
            check(
                preferences.edit()
                    .putString(ENDPOINT, endpoint)
                    .putLong(LAST_SEQUENCE, 0L)
                    .remove(ENROLLMENT_REQUEST_ID)
                    .commit(),
            ) { "Unable to persist the mobile profile." }
        } catch (failure: Throwable) {
            credentialStore.clear()
            caFile.delete()
            throw failure
        }
    }

    override fun loadSession(): StoredMobileSession {
        val endpoint = preferences.getString(ENDPOINT, null)
            ?: error("No enrolled mobile endpoint is stored.")
        val credential = credentialStore.load()
            ?: error("The mobile credential is unavailable.")
        check(caFile.isFile) { "The app-private CA certificate is unavailable." }
        return StoredMobileSession(
            endpoint = endpoint,
            credential = credential,
            caDer = caFile.readBytes(),
            lastAcceptedSequence = preferences.getLong(LAST_SEQUENCE, 0L),
        )
    }

    override fun updateLastAcceptedSequence(sequence: Long) {
        require(sequence >= 0) { "Sequence cannot be negative." }
        synchronized(cursorLock) {
            val current = preferences.getLong(LAST_SEQUENCE, 0L)
            if (sequence > current) {
                preferences.edit().putLong(LAST_SEQUENCE, sequence).apply()
            }
        }
    }

    override fun flushLastAcceptedSequence() {
        synchronized(cursorLock) {
            val sequence = preferences.getLong(LAST_SEQUENCE, 0L)
            check(preferences.edit().putLong(LAST_SEQUENCE, sequence).commit()) {
                "Unable to persist the stream cursor."
            }
        }
    }

    override fun clear() {
        credentialStore.clear()
        caFile.delete()
        preferences.edit().clear().commit()
    }

    private companion object {
        const val PREFERENCES = "mobile_profile"
        const val ENDPOINT = "endpoint"
        const val DEVICE_INSTANCE_ID = "device_instance_id"
        const val ENROLLMENT_REQUEST_ID = "enrollment_request_id"
        const val LAST_SEQUENCE = "last_sequence"
        const val CA_FILE = "mobile-monitor-ca.der"
    }
}
