package com.strugglebus.app

import android.os.SystemClock
import android.util.Base64
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.strugglebus.app.activity.MobileMonitorRepository
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.network.EnrollmentStrandedException
import com.strugglebus.app.core.network.MobileApiClient
import com.strugglebus.app.core.network.StreamEnd
import com.strugglebus.app.core.security.AndroidCredentialStore
import com.strugglebus.app.core.security.AndroidProfileStore
import com.strugglebus.app.core.security.CaCertificate
import com.strugglebus.app.enrollment.EnrollmentPayloadParser
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MobilePocIntegrationTest {
    @Test
    fun enrollsWithPinnedCaStoresCredentialAndStreams() = runBlocking {
        val arguments = InstrumentationRegistry.getArguments()
        val payload = decodeArgument(arguments.getString("enrollment"), "enrollment")
        val caPem = decodeArgument(arguments.getString("caPem"), "caPem")
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val credentialStore = AndroidCredentialStore(context)
        val profileStore = AndroidProfileStore(context, credentialStore)
        profileStore.clear()
        val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
        val payloadParser = EnrollmentPayloadParser(moshi)
        val parsedPayload = payloadParser.parse(payload)
        val caDer = CaCertificate.parseAndVerify(caPem, parsedPayload.caSha256)
        val control = MockControlClient(caDer)
        val repository = MobileMonitorRepository(
            payloadParser,
            profileStore,
            MobileApiClient(moshi),
        )

        repository.enroll(payload)
        assertTrue(repository.isEnrolled())

        // Redemption is single-use and unreplayable: the server keeps only a hash of the
        // secret, so a repeat attempt must surface as terminal, never as a silent retry.
        val replay = runCatching {
            repository.enroll(payload)
        }.exceptionOrNull()
        assertTrue(
            "Expected a stranded enrollment, got $replay",
            replay is EnrollmentStrandedException,
        )
        assertTrue(repository.isEnrolled())

        assertEquals(BusStatus.READY, repository.status())
        val snapshot = repository.snapshot()
        assertTrue(snapshot.messages.isNotEmpty())

        val received = mutableListOf<Long>()
        val end = repository.stream(
            cursor = 0,
            channel = null,
            onOpen = {},
            onMessage = { received += it.sequence },
        )
        assertEquals(StreamEnd.RoutineClosure, end)
        assertEquals(snapshot.messages.map { it.sequence }, received)
        assertEquals(received.maxOrNull(), repository.lastAcceptedSequence())

        assertFourthConcurrentStreamIsRateLimited(repository)
        assertLiveReadsDuringFreezeAndRepositoryRecreation(
            repository = repository,
            control = control,
            endpoint = parsedPayload.endpoint,
            context = context,
            moshi = moshi,
        )
        assertBackgroundResume(
            control = control,
            endpoint = parsedPayload.endpoint,
            profileStore = profileStore,
        )
        repository.clearEnrollment()
    }

    private suspend fun assertLiveReadsDuringFreezeAndRepositoryRecreation(
        repository: MobileMonitorRepository,
        control: MockControlClient,
        endpoint: String,
        context: android.content.Context,
        moshi: Moshi,
    ) {
        control.addMessage(endpoint, "status", "Accepted before deterministic denial")
        control.addMessage(endpoint, "status", "Must remain behind denial")
        control.setState(endpoint, """{"freeze_after_sequence":3}""")

        val received = mutableListOf<Long>()
        val end = repository.stream(
            cursor = 2,
            channel = null,
            onOpen = {},
            onMessage = { received += it.sequence },
        )
        assertEquals(listOf(3L, 4L), received)
        assertEquals(StreamEnd.RoutineClosure, end)
        assertEquals(BusStatus.FROZEN, repository.status())
        assertTrue(repository.snapshot().latestSequence >= 0L)
        assertEquals(4L, repository.lastAcceptedSequence())

        // Recreate every repository dependency from durable Android storage. This models
        // process recreation without retaining an in-memory cursor or credential object.
        val recreatedStore = AndroidProfileStore(context, AndroidCredentialStore(context))
        val recreated = MobileMonitorRepository(
            EnrollmentPayloadParser(moshi),
            recreatedStore,
            MobileApiClient(moshi),
        )
        assertEquals(4L, recreated.lastAcceptedSequence())

        control.setState(
            endpoint,
            """{"frozen":false,"freeze_after_sequence":null}""",
        )
        val resumed = mutableListOf<Long>()
        val resumedEnd = recreated.stream(
            cursor = recreated.lastAcceptedSequence(),
            channel = null,
            onOpen = {},
            onMessage = { resumed += it.sequence },
        )
        assertTrue(resumed.isEmpty())
        assertEquals(StreamEnd.RoutineClosure, resumedEnd)
        assertEquals(4L, recreated.lastAcceptedSequence())
    }

    private fun assertBackgroundResume(
        control: MockControlClient,
        endpoint: String,
        profileStore: AndroidProfileStore,
    ) {
        control.addMessage(endpoint, "status", "Visible before backgrounding")
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            awaitSequence(profileStore, 5L)
            awaitActiveStreams(control, endpoint, 1)

            scenario.moveToState(Lifecycle.State.CREATED)
            awaitActiveStreams(control, endpoint, 0)
            control.addMessage(endpoint, "status", "Queued while backgrounded")
            SystemClock.sleep(750)
            assertEquals(
                "The backgrounded activity must not keep consuming the SSE stream.",
                5L,
                profileStore.loadSession().lastAcceptedSequence,
            )

            scenario.moveToState(Lifecycle.State.RESUMED)
            awaitSequence(profileStore, 6L)
        }
    }

    private fun awaitActiveStreams(
        control: MockControlClient,
        endpoint: String,
        expected: Int,
    ) {
        repeat(50) {
            if (control.activeStreams(endpoint) == expected) return
            SystemClock.sleep(100)
        }
        assertEquals(expected, control.activeStreams(endpoint))
    }

    private fun awaitSequence(profileStore: AndroidProfileStore, expected: Long) {
        repeat(50) {
            if (profileStore.loadSession().lastAcceptedSequence == expected) return
            SystemClock.sleep(100)
        }
        assertEquals(expected, profileStore.loadSession().lastAcceptedSequence)
    }

    private suspend fun assertFourthConcurrentStreamIsRateLimited(
        repository: MobileMonitorRepository,
    ) = coroutineScope {
        val opened = Channel<Unit>(capacity = 3)
        val streams = List(3) {
            async {
                repository.stream(
                    cursor = repository.lastAcceptedSequence(),
                    channel = null,
                    onOpen = { opened.trySend(Unit) },
                    onMessage = {},
                )
            }
        }
        repeat(3) { opened.receive() }

        val fourth = repository.stream(
            cursor = repository.lastAcceptedSequence(),
            channel = null,
            onOpen = { error("The rejected fourth stream must not open.") },
            onMessage = {},
        )
        assertTrue(
            "Expected fourth stream to be rate limited, got $fourth",
            fourth is StreamEnd.RateLimited && fourth.retryAfterMillis >= 0,
        )
        streams.forEach { assertEquals(StreamEnd.RoutineClosure, it.await()) }
    }

    private fun decodeArgument(value: String?, name: String): String {
        requireNotNull(value) { "Missing instrumentation argument: $name" }
        return Base64.decode(value, Base64.NO_WRAP).toString(Charsets.UTF_8)
    }
}
