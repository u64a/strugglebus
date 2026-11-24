package com.strugglebus.app

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.strugglebus.app.core.security.AndroidOperatorGrantStore
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OperatorGrantStoreTest {
    @Test
    fun grantIsEncryptedByAUserPresenceProtectedKeystoreKey() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = AndroidOperatorGrantStore(context)
        store.clear()

        store.save("dev_test", "grant_secret_that_must_not_be_stored_plaintext")

        assertTrue(store.hasGrant())
        assertTrue(store.deviceId() == "dev_test")
        val stored = context.getSharedPreferences(
            "protected_operator_grant",
            Context.MODE_PRIVATE,
        ).all.values.joinToString("|")
        assertFalse(stored.contains("grant_secret_that_must_not_be_stored_plaintext"))
        store.createDecryptionCipher()
        assertTrue(store.chatSecret() == "grant_secret_that_must_not_be_stored_plaintext")
        store.clear()
        assertFalse(store.hasGrant())
        assertTrue(store.chatSecret() == null)
    }
}
