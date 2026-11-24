package com.strugglebus.app

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
import com.strugglebus.app.core.security.CaCertificate
import com.strugglebus.app.enrollment.EnrollmentPayloadParser
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ProcessDeathResumeTest {
    @Test
    fun executesSelectedProcessDeathPhase() = runBlocking {
        val arguments = InstrumentationRegistry.getArguments()
        val phase = arguments.getString("resumePhase")
        assumeTrue("Run with resumePhase=seed or resume", phase in setOf("seed", "resume"))

        val payload = decodeArgument(arguments.getString("enrollment"), "enrollment")
        val caPem = decodeArgument(arguments.getString("caPem"), "caPem")
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
        val parser = EnrollmentPayloadParser(moshi)
        val parsedPayload = parser.parse(payload)
        val caDer = CaCertificate.parseAndVerify(caPem, parsedPayload.caSha256)
        val control = MockControlClient(caDer)
        val profileStore = AndroidProfileStore(context, AndroidCredentialStore(context))
        val repository = MobileMonitorRepository(parser, profileStore, MobileApiClient(moshi))
        val markers = context.getSharedPreferences(MARKER_STORE, 0)

        when (phase) {
            "seed" -> {
                profileStore.clear()
                repository.enroll(payload)
                val snapshot = repository.snapshot()
                assertEquals(2L, snapshot.latestSequence)
                control.addMessage(parsedPayload.endpoint, "status", "Queued before process death")
                val received = mutableListOf<Long>()
                val end = repository.stream(
                    cursor = repository.lastAcceptedSequence(),
                    channel = null,
                    onOpen = {},
                    onMessage = { received += it.sequence },
                )
                assertEquals(listOf(3L), received)
                assertEquals(StreamEnd.RoutineClosure, end)
                assertEquals(3L, repository.lastAcceptedSequence())
                markers.edit().putString(PROCESS_MARKER, PROCESS_INSTANCE).commit()
            }
            "resume" -> {
                assertTrue("Enrollment must survive process death.", repository.isEnrolled())
                assertEquals(3L, repository.lastAcceptedSequence())
                assertNotEquals(
                    "The resume phase must execute in a new instrumentation process.",
                    markers.getString(PROCESS_MARKER, null),
                    PROCESS_INSTANCE,
                )
                control.addMessage(parsedPayload.endpoint, "status", "Queued after process death")
                val received = mutableListOf<Long>()
                val end = repository.stream(
                    cursor = repository.lastAcceptedSequence(),
                    channel = null,
                    onOpen = {},
                    onMessage = { received += it.sequence },
                )
                assertEquals(listOf(4L), received)
                assertEquals(StreamEnd.RoutineClosure, end)
                assertEquals(4L, repository.lastAcceptedSequence())
                profileStore.clear()
                markers.edit().clear().commit()
            }
            else -> error("Unsupported process-death phase: $phase")
        }
        Unit
    }

    private fun decodeArgument(value: String?, name: String): String {
        requireNotNull(value) { "Missing instrumentation argument: $name" }
        return Base64.decode(value, Base64.NO_WRAP).toString(Charsets.UTF_8)
    }

    private companion object {
        val PROCESS_INSTANCE: String = UUID.randomUUID().toString()
        const val MARKER_STORE = "process_death_resume_test"
        const val PROCESS_MARKER = "seed_process_instance"
    }
}
