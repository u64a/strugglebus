package com.strugglebus.app.core.network

import com.squareup.moshi.Moshi
import com.strugglebus.app.core.model.BusMessage

sealed interface DecodedSseEvent {
    data class Message(val message: BusMessage) : DecodedSseEvent
    data class Terminal(val name: String, val detail: String) : DecodedSseEvent
}

class SseProtocol(moshi: Moshi) {
    private val messageAdapter = moshi.adapter(MessageWire::class.java)
    private val errorAdapter = moshi.adapter(ErrorWire::class.java).failOnUnknown()

    fun decode(frame: SseFrame, requestedChannel: String?): DecodedSseEvent {
        return when (frame.event) {
            MESSAGE_EVENT -> {
                val eventSequence = frame.id?.toLongOrNull()
                    ?: throw ProtocolException("Message event has no valid signed 64-bit id.")
                requireProtocol(eventSequence >= 0) { "Message event id is negative." }
                val wire = messageAdapter.fromJson(frame.data)
                    ?: throw ProtocolException("Message event data is empty.")
                requireProtocol(wire.sequence == eventSequence) {
                    "Message sequence does not match its SSE id."
                }
                requireProtocol(wire.channel.isNotBlank()) { "Message channel is empty." }
                requireProtocol(requestedChannel == null || wire.channel == requestedChannel) {
                    "Received a message outside the requested channel."
                }
                DecodedSseEvent.Message(wire.toDomain())
            }
            in TERMINAL_EVENTS -> {
                requireProtocol(frame.id == null) { "Terminal event must not carry an id." }
                val detail = errorAdapter.fromJson(frame.data)?.detail
                    ?: throw ProtocolException("Terminal event data is empty.")
                DecodedSseEvent.Terminal(frame.event.orEmpty(), detail)
            }
            else -> throw ProtocolException("Unsupported SSE event type.")
        }
    }

    private fun requireProtocol(condition: Boolean, message: () -> String) {
        if (!condition) throw ProtocolException(message())
    }

    private fun MessageWire.toDomain() = BusMessage(
        sequence = sequence,
        id = id,
        channel = channel,
        agentId = agentId,
        agentName = agentName,
        body = body,
        kind = kind,
        replyTo = replyTo,
        createdAt = createdAt,
    )

    companion object {
        const val MESSAGE_EVENT = "message"
        val TERMINAL_EVENTS = setOf(
            "agent_access_frozen",
            "credential_inactive",
            "agent_access_unavailable",
        )
    }
}

class ProtocolException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)
