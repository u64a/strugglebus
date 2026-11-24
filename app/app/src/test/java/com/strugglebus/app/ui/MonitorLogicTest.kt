package com.strugglebus.app.ui

import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.network.ReconnectDecision
import com.strugglebus.app.core.network.StreamEnd
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MonitorLogicTest {
    @Test
    fun channelSelectionNeverNarrowsTheGlobalStream() {
        assertNull(MonitorLogic.streamChannel())
    }

    @Test
    fun removedChannelResetsSelection() {
        val channels = listOf(BusChannel("1", "help", "Help"))

        assertEquals("help", MonitorLogic.normalizeChannelSelection("help", channels))
        assertNull(MonitorLogic.normalizeChannelSelection("status", channels))
    }

    @Test
    fun messagesAreDeduplicatedSortedAndCapped() {
        val result = MonitorLogic.mergeMessages(
            current = listOf(message(3), message(2), message(1)),
            incoming = message(2, body = "replacement"),
            limit = 2,
        )

        assertEquals(listOf(3L, 2L), result.map(BusMessage::sequence))
        assertEquals("replacement", result.last().body)
    }

    @Test
    fun retryBackoffOnlyResetsAfterMessage() {
        val state = MonitorRetryState()

        val first = state.decide(StreamEnd.RetryableFailure("offline")) as ReconnectDecision.Retry
        val second = state.decide(StreamEnd.RetryableFailure("offline")) as ReconnectDecision.Retry
        assertEquals(2_000L, first.delayMillis)
        assertEquals(4_000L, second.delayMillis)
        assertEquals(2, state.consecutiveFailures)

        state.onMessage()
        assertEquals(0, state.consecutiveFailures)
        val reset = state.decide(StreamEnd.RetryableFailure("offline")) as ReconnectDecision.Retry
        assertEquals(2_000L, reset.delayMillis)
    }

    @Test
    fun quietClosuresDoNotIncreaseFailureCount() {
        val state = MonitorRetryState()
        val decision = state.decide(StreamEnd.RoutineClosure) as ReconnectDecision.Retry

        assertTrue(decision.quiet)
        assertEquals(0, state.consecutiveFailures)
    }

    private fun message(sequence: Long, body: String = "message-$sequence") = BusMessage(
        sequence = sequence,
        id = "m$sequence",
        channel = "help",
        agentId = "agent",
        agentName = "Agent",
        body = body,
        kind = "status",
        replyTo = null,
        createdAt = "2030-01-01T00:00:00Z",
    )
}
