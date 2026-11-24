package com.strugglebus.app.core.network

import java.io.ByteArrayOutputStream

data class SseFrame(
    val id: String?,
    val event: String?,
    val data: String,
)

class SseParser(
    private val onFrame: (SseFrame) -> Unit,
) {
    private val line = ByteArrayOutputStream()
    private var id: String? = null
    private var event: String? = null
    private val data = mutableListOf<String>()

    fun feed(bytes: ByteArray, length: Int = bytes.size) {
        require(length in 0..bytes.size)
        for (index in 0 until length) {
            val value = bytes[index]
            if (value == NEWLINE) {
                consumeLine()
            } else {
                if (line.size() >= MAX_LINE_BYTES) {
                    throw ProtocolException("SSE line exceeds the 8 MiB safety limit.")
                }
                line.write(value.toInt())
            }
        }
    }

    fun finish() {
        if (line.size() > 0) {
            consumeLine()
        }
        if (data.isNotEmpty()) {
            dispatch()
        }
    }

    private fun consumeLine() {
        var bytes = line.toByteArray()
        line.reset()
        if (bytes.lastOrNull() == CARRIAGE_RETURN) {
            bytes = bytes.copyOf(bytes.size - 1)
        }
        val value = bytes.toString(Charsets.UTF_8)
        if (value.isEmpty()) {
            dispatch()
            return
        }
        if (value.startsWith(":")) return

        val separator = value.indexOf(':')
        val field = if (separator < 0) value else value.substring(0, separator)
        val fieldValue = if (separator < 0) {
            ""
        } else {
            value.substring(separator + 1).removePrefix(" ")
        }
        when (field) {
            "id" -> if (!fieldValue.contains('\u0000')) id = fieldValue
            "event" -> event = fieldValue
            "data" -> data += fieldValue
        }
    }

    private fun dispatch() {
        if (data.isNotEmpty()) {
            onFrame(SseFrame(id = id, event = event, data = data.joinToString("\n")))
        }
        id = null
        event = null
        data.clear()
    }

    private companion object {
        // The API permits a 1 MiB body; JSON escaping can expand its encoded SSE data line.
        const val MAX_LINE_BYTES = 8 * 1_024 * 1_024
        const val NEWLINE: Byte = 10
        const val CARRIAGE_RETURN: Byte = 13
    }
}
