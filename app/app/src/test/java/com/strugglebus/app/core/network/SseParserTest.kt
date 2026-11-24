package com.strugglebus.app.core.network

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class SseParserTest {
    private val protocol = SseProtocol(
        Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
    )

    @Test
    fun parsesFragmentedMessageWithEscapedAndNonAsciiTextAndLargeLongSequence() {
        val sequence = Long.MAX_VALUE
        val wire = """
            id: $sequence
            event: message
            data: {"seq":$sequence,"id":"m","channel":"announce","agent_id":"a","agent_name":"agent","body":"escaped \u263a and café","kind":"status","reply_to":null,"created_at":"2030-01-01T00:00:00Z"}

        """.trimIndent() + "\n\n"
        val frames = mutableListOf<SseFrame>()
        val parser = SseParser(frames::add)
        wire.toByteArray(Charsets.UTF_8).forEach { parser.feed(byteArrayOf(it)) }

        val decoded = protocol.decode(frames.single(), "announce") as DecodedSseEvent.Message
        assertEquals(sequence, decoded.message.sequence)
        assertEquals("escaped ☺ and café", decoded.message.body)
    }

    @Test
    fun acceptsMessageNearOneMebibyteBodyLimit() {
        val body = "x".repeat(1_048_576)
        val wire = """id: 7
event: message
data: {"seq":7,"id":"m","channel":"announce","agent_id":"a","agent_name":"agent","body":"$body","kind":"status","reply_to":null,"created_at":"2030-01-01T00:00:00.000000Z"}

"""
        val frames = mutableListOf<SseFrame>()
        SseParser(frames::add).feed(wire.toByteArray())

        val decoded = protocol.decode(frames.single(), "announce") as DecodedSseEvent.Message
        assertEquals(body.length, decoded.message.body.length)
    }

    @Test
    fun ignoresHeartbeatComments() {
        val frames = mutableListOf<SseFrame>()
        SseParser(frames::add).feed(": heartbeat\n\n".toByteArray())

        assertEquals(emptyList<SseFrame>(), frames)
    }

    @Test
    fun parsesTerminalWithoutIdAndRejectsTerminalWithId() {
        val frames = mutableListOf<SseFrame>()
        SseParser(frames::add).feed(
            "event: credential_inactive\ndata: {\"detail\":\"inactive\"}\n\n".toByteArray(),
        )
        assertNull(frames.single().id)
        val decoded = protocol.decode(frames.single(), null) as DecodedSseEvent.Terminal
        assertEquals("credential_inactive", decoded.name)

        assertThrows(ProtocolException::class.java) {
            protocol.decode(frames.single().copy(id = "1"), null)
        }
    }

    @Test
    fun rejectsMessageOutsideRequestedChannel() {
        val frame = SseFrame(
            id = "1",
            event = "message",
            data = """{"seq":1,"id":"m","channel":"status","agent_id":"a","agent_name":"agent","body":"x","kind":"status","reply_to":null,"created_at":"2030-01-01T00:00:00Z"}""",
        )

        assertThrows(ProtocolException::class.java) {
            protocol.decode(frame, "announce")
        }
    }
}
