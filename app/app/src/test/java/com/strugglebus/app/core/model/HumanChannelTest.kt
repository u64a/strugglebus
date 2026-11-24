package com.strugglebus.app.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HumanChannelTest {
    @Test
    fun conversationKeepsOnlyHumansOldestFirst() {
        val messages = listOf(
            message(5, "humans", "agent-a"),
            message(3, "help", "agent-b"),
            message(4, "humans", HumanChannel.OPERATOR_AUTHOR),
        )

        assertEquals(listOf(4L, 5L), HumanChannel.conversation(messages).map(BusMessage::sequence))
    }

    @Test
    fun unreadCountsOnlyNewerAgentPostsInHumans() {
        val messages = listOf(
            message(2, "humans", "agent-a"),
            message(6, "humans", "agent-a"),
            message(7, "humans", HumanChannel.OPERATOR_AUTHOR),
            message(8, "help", "agent-a"),
        )

        assertEquals(1, HumanChannel.unreadCount(messages, lastSeenSequence = 5))
    }

    @Test
    fun normalizeBodyTrimsAndRejectsEmptyOrOversizedText() {
        assertEquals("hi\nthere", HumanChannel.normalizeBody("  hi\r\nthere \n"))
        assertNull(HumanChannel.normalizeBody("   "))
        assertNull(HumanChannel.normalizeBody("x".repeat(HumanChannel.MAX_BODY_CHARS + 1)))
    }

    private fun message(sequence: Long, channel: String, author: String) = BusMessage(
        sequence = sequence,
        id = "m$sequence",
        channel = channel,
        agentId = "a",
        agentName = author,
        body = "body",
        kind = "chat",
        replyTo = null,
        createdAt = "2026-10-05T00:00:00Z",
    )
}
