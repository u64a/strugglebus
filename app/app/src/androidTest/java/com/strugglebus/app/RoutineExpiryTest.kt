package com.strugglebus.app

import android.os.SystemClock
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.strugglebus.app.activity.MobileMonitorRepository
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.network.MobileApiClient
import com.strugglebus.app.core.network.StreamEnd
import com.strugglebus.app.core.security.AndroidCredentialStore
import com.strugglebus.app.core.security.AndroidProfileStore
import com.strugglebus.app.enrollment.EnrollmentPayloadParser
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RoutineExpiryTest {
    @Test
    fun observesTheRealFiveMinuteRoutineClosure() = runBlocking {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue("Run explicitly with expiryProbe=true", arguments.getString("expiryProbe") == "true")
        val payload = decodeArgument(arguments.getString("enrollment"), "enrollment")
        val caPem = decodeArgument(arguments.getString("caPem"), "caPem")
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val profileStore = AndroidProfileStore(context, AndroidCredentialStore(context))
        profileStore.clear()
        val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
        val repository = MobileMonitorRepository(
            EnrollmentPayloadParser(moshi),
            profileStore,
            MobileApiClient(moshi),
        )
        repository.enroll(payload)
        val snapshot = repository.snapshot()

        val started = SystemClock.elapsedRealtime()
        val end = repository.stream(
            cursor = snapshot.latestSequence,
            channel = null,
            onOpen = {},
            onMessage = { error("No new message was expected during the expiry probe.") },
        )
        val elapsed = SystemClock.elapsedRealtime() - started

        assertEquals(StreamEnd.RoutineClosure, end)
        assertTrue("Stream closed too early after ${elapsed}ms", elapsed >= 295_000L)
        assertTrue("Stream exceeded the bounded expiry window: ${elapsed}ms", elapsed <= 330_000L)
        profileStore.clear()
    }

    private fun decodeArgument(value: String?, name: String): String {
        requireNotNull(value) { "Missing instrumentation argument: $name" }
        return Base64.decode(value, Base64.NO_WRAP).toString(Charsets.UTF_8)
    }
}
