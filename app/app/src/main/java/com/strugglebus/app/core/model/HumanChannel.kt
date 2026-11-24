package com.strugglebus.app.core.model

object HumanChannel {
    const val NAME = "humans"

    /** Shared, credential-less author for every human post, from the console or a device. */
    const val OPERATOR_AUTHOR = "human:operator"

    /** Generous for chat, and far below the server's byte limit so a post is never refused for size. */
    const val MAX_BODY_CHARS = 4_000

    fun isHumanPost(message: BusMessage): Boolean = message.agentName == OPERATOR_AUTHOR

    /** #humans traffic, oldest first. */
    fun conversation(messages: List<BusMessage>): List<BusMessage> =
        messages.filter { it.channel == NAME }.sortedBy(BusMessage::sequence)

    /** Agent posts in #humans newer than [lastSeenSequence]; human posts never count as unread. */
    fun unreadCount(messages: List<BusMessage>, lastSeenSequence: Long): Int =
        messages.count { it.channel == NAME && it.sequence > lastSeenSequence && !isHumanPost(it) }

    fun normalizeBody(raw: String): String? =
        raw.replace("\r\n", "\n").trim().takeIf { it.isNotEmpty() && it.length <= MAX_BODY_CHARS }
}
