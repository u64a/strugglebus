package com.strugglebus.app.ui

import com.strugglebus.app.activity.HumansPoster
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.HumanChannel
import com.strugglebus.app.core.model.HumanMessageKind
import com.strugglebus.app.core.network.ApiException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class HumansViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun sendPostsImmediatelyAndEmitsMessage() = runTest(dispatcher) {
        val poster = FakePoster()
        val viewModel = HumansViewModel(poster)

        viewModel.updateDraft("  Deploy looks good  ")
        viewModel.send()
        assertEquals("", viewModel.uiState.value.draft)
        assertEquals(OutgoingStatus.SENDING, viewModel.uiState.value.outbox.single().status)
        runCurrent()

        assertEquals("Deploy looks good", poster.calls.single().body)
        assertTrue(viewModel.uiState.value.outbox.isEmpty())
        assertEquals(99L, viewModel.posted.first().sequence)
    }

    @Test
    fun retryReusesTheSameRequestId() = runTest(dispatcher) {
        val poster = FakePoster(failures = mutableListOf(IllegalStateException("timeout")))
        val viewModel = HumansViewModel(poster)

        viewModel.updateDraft("hello")
        viewModel.send()
        runCurrent()
        val failed = viewModel.uiState.value.outbox.single()
        assertEquals(OutgoingStatus.FAILED, failed.status)
        assertEquals("timeout", failed.error)
        assertTrue(failed.retryable)

        viewModel.retry(failed.requestId)
        runCurrent()

        assertEquals(2, poster.calls.size)
        assertEquals(1, poster.calls.map { it.requestId }.distinct().size)
        assertTrue(viewModel.uiState.value.outbox.isEmpty())
    }

    @Test
    fun messagelessFailureNamesTheExceptionType() = runTest(dispatcher) {
        val poster = FakePoster(failures = mutableListOf(IllegalStateException()))
        val viewModel = HumansViewModel(poster)

        viewModel.updateDraft("hello")
        viewModel.send()
        runCurrent()

        assertEquals(
            "Unable to reach StruggleBus (IllegalStateException).",
            viewModel.uiState.value.outbox.single().error,
        )
    }

    @Test
    fun conflictIsNotRetryable() = runTest(dispatcher) {
        val poster = FakePoster(failures = mutableListOf(ApiException("conflict", 409)))
        val viewModel = HumansViewModel(poster)

        viewModel.updateDraft("hello")
        viewModel.send()
        runCurrent()

        assertFalse(viewModel.uiState.value.outbox.single().retryable)
    }

    @Test
    fun rejectedGrantIsClearedAndBlocksFurtherPosts() = runTest(dispatcher) {
        val poster = FakePoster(failures = mutableListOf(ApiException("bad grant", 401)))
        val viewModel = HumansViewModel(poster)

        viewModel.updateDraft("hello")
        viewModel.send()
        runCurrent()

        assertTrue(poster.cleared)
        assertFalse(viewModel.uiState.value.grantConfigured)
        viewModel.updateDraft("again")
        viewModel.send()
        runCurrent()
        assertEquals(1, poster.calls.size)
    }

    @Test
    fun replyingToAQuestionDefaultsToAnswer() {
        val viewModel = HumansViewModel(FakePoster())

        viewModel.replyTo(
            BusMessage(7, "m7", HumanChannel.NAME, "a", "agent-a", "Which branch?", "question", null, "2026-10-05T00:00:00Z"),
        )

        assertEquals(7L, viewModel.uiState.value.replyTo?.sequence)
        assertEquals(HumanMessageKind.ANSWER, viewModel.uiState.value.kind)
    }

    private data class Call(val requestId: String, val body: String, val kind: HumanMessageKind, val replyTo: Long?)

    private class FakePoster(
        private val failures: MutableList<Throwable> = mutableListOf(),
    ) : HumansPoster {
        val calls = mutableListOf<Call>()
        var cleared = false
        private var grant = true

        override fun canPost() = grant
        override suspend fun post(
            requestId: String,
            body: String,
            kind: HumanMessageKind,
            replyTo: Long?,
        ): BusMessage {
            calls += Call(requestId, body, kind, replyTo)
            failures.removeFirstOrNull()?.let { throw it }
            return BusMessage(99, "m99", HumanChannel.NAME, "h", HumanChannel.OPERATOR_AUTHOR, body, kind.wireName, replyTo, "2026-10-05T00:00:00Z")
        }
        override fun clearGrant() {
            cleared = true
            grant = false
        }
    }
}