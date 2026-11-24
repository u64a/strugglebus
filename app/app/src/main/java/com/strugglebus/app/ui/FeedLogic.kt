package com.strugglebus.app.ui

import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.HumanChannel
import com.strugglebus.app.core.model.HumanMessageKind
import java.time.Duration
import java.time.Instant

enum class AgentPresence { ACTIVE, IDLE, OFFLINE }

/** What the operator is looking for: free text plus optional agent and channel. */
data class FeedQuery(val text: String = "", val agent: String? = null, val channel: String? = null) {
    val isEmpty: Boolean get() = text.isEmpty() && agent == null && channel == null
}

enum class SegmentKind { PLAIN, HIT, MENTION }

data class TextSegment(val text: String, val kind: SegmentKind)

data class MentionToken(val start: Int, val prefix: String)

data class MentionOption(val insert: String, val meta: String, val presence: AgentPresence?, val isGroup: Boolean)

/** Pure rules for searching, presence and @mentions, matching the Windows app. No UI types. */
object FeedLogic {
    const val EVERYONE_TOKEN = "everyone"
    const val MAX_MENTIONS_PER_MESSAGE = 32
    val ACTIVE_WINDOW: Duration = Duration.ofMinutes(5)
    val IDLE_WINDOW: Duration = Duration.ofHours(1)

    // Mirrors the server's mention pattern (strugglebus service.py): a name must contain a hyphen.
    private val MENTION = Regex(
        "(?<![A-Za-z0-9._%+-])@([a-z0-9]+(?:-[a-z0-9]+)+)(?![A-Za-z0-9-]|\\.[A-Za-z0-9])",
        RegexOption.IGNORE_CASE,
    )
    private val EVERYONE = Regex("(?<![A-Za-z0-9._%+-])@everyone(?![A-Za-z0-9-])", RegexOption.IGNORE_CASE)

    /** Splits "from:name in:#channel some words" into its parts. Unknown text stays as text. */
    fun parseQuery(raw: String?): FeedQuery {
        var agent: String? = null
        var channel: String? = null
        val words = mutableListOf<String>()
        for (token in raw.orEmpty().split(' ').filter(String::isNotEmpty)) {
            when {
                token.startsWith("from:", ignoreCase = true) && token.length > 5 ->
                    agent = token.substring(5).trimStart('@').ifEmpty { null }
                token.startsWith("in:", ignoreCase = true) && token.length > 3 ->
                    channel = token.substring(3).trimStart('#').ifEmpty { null }
                else -> words += token
            }
        }
        return FeedQuery(words.joinToString(" "), agent, channel)
    }

    /** Replaces the from: part of a typed query, keeping everything else. */
    fun withAgent(raw: String, agent: String?): String {
        val kept = raw.split(' ').filter { it.isNotEmpty() && !it.startsWith("from:", ignoreCase = true) }
        return (if (agent == null) kept else listOf("from:$agent") + kept).joinToString(" ")
    }

    fun matches(message: BusMessage, query: FeedQuery): Boolean {
        if (query.channel != null && !message.channel.equals(query.channel, ignoreCase = true)) return false
        if (query.agent != null && !message.agentName.equals(query.agent, ignoreCase = true)) return false
        return query.text.isEmpty() ||
            message.body.contains(query.text, ignoreCase = true) ||
            message.agentName.contains(query.text, ignoreCase = true)
    }

    fun lastSeen(agent: BusAgent): Instant? = runCatching { Instant.parse(agent.lastSeenAt) }.getOrNull()

    fun presence(lastSeen: Instant?, now: Instant): AgentPresence {
        if (lastSeen == null) return AgentPresence.OFFLINE
        val age = Duration.between(lastSeen, now)
        return when {
            age <= ACTIVE_WINDOW -> AgentPresence.ACTIVE
            age <= IDLE_WINDOW -> AgentPresence.IDLE
            else -> AgentPresence.OFFLINE
        }
    }

    fun presenceLabel(lastSeen: Instant?, now: Instant): String {
        if (lastSeen == null) return "never seen"
        val age = Duration.between(lastSeen, now)
        return when {
            age < Duration.ofMinutes(1) -> "active now"
            age <= ACTIVE_WINDOW -> "active ${age.toMinutes()}m ago"
            age <= IDLE_WINDOW -> "idle ${age.toMinutes()}m"
            age < Duration.ofDays(1) -> "seen ${age.toHours()}h ago"
            else -> "seen ${age.toDays()}d ago"
        }
    }

    /** Agents for the monitor strip: most recently seen first, then by name. */
    fun sortAgents(agents: List<BusAgent>): List<BusAgent> =
        agents.sortedWith(
            compareByDescending<BusAgent> { lastSeen(it) ?: Instant.MIN }.thenBy { it.name.lowercase() },
        )

    /** Breaks text into plain runs, @mentions and search hits, in order. */
    fun segment(text: String, highlight: String?): List<TextSegment> {
        val segments = mutableListOf<TextSegment>()
        var position = 0
        for (mention in MENTION.findAll(text)) {
            addWithHits(segments, text.substring(position, mention.range.first), highlight)
            segments += TextSegment(mention.value, SegmentKind.MENTION)
            position = mention.range.last + 1
        }
        addWithHits(segments, text.substring(position), highlight)
        return segments
    }

    private fun addWithHits(segments: MutableList<TextSegment>, text: String, highlight: String?) {
        if (text.isEmpty()) return
        if (highlight.isNullOrEmpty()) {
            segments += TextSegment(text, SegmentKind.PLAIN)
            return
        }
        var position = 0
        while (position < text.length) {
            val hit = text.indexOf(highlight, position, ignoreCase = true)
            if (hit < 0) break
            if (hit > position) segments += TextSegment(text.substring(position, hit), SegmentKind.PLAIN)
            segments += TextSegment(text.substring(hit, hit + highlight.length), SegmentKind.HIT)
            position = hit + highlight.length
        }
        if (position < text.length) segments += TextSegment(text.substring(position), SegmentKind.PLAIN)
    }

    fun isMentionable(agentName: String): Boolean = MENTION.matches("@$agentName")

    /** The "@prefix" being typed at the caret, if the caret sits inside one. */
    fun activeMentionToken(text: String, caret: Int): MentionToken? {
        if (caret < 0 || caret > text.length) return null
        var start = caret
        while (start > 0 && (text[start - 1].isAsciiLetterOrDigit() || text[start - 1] == '-')) start--
        if (start == 0 || text[start - 1] != '@') return null
        val at = start - 1
        if (at > 0 && !text[at - 1].isWhitespace() && text[at - 1] !in "([,") return null
        return MentionToken(at, text.substring(start, caret))
    }

    private fun Char.isAsciiLetterOrDigit(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

    /** Agents the bus will accept as a mention, best match first, then the @everyone group. */
    fun mentionOptions(agents: List<BusAgent>, prefix: String, now: Instant, limit: Int = 8): List<MentionOption> {
        val mentionable = agents.filter { isMentionable(it.name) }
        val options = mentionable
            .filter { it.name.contains(prefix, ignoreCase = true) }
            .sortedWith(
                compareBy<BusAgent> { if (it.name.startsWith(prefix, ignoreCase = true)) 0 else 1 }
                    .thenBy { presence(lastSeen(it), now) }
                    .thenBy { it.name.lowercase() },
            )
            .take(limit)
            .map { MentionOption(it.name, presenceLabel(lastSeen(it), now), presence(lastSeen(it), now), false) }
            .toMutableList()
        if (EVERYONE_TOKEN.startsWith(prefix, ignoreCase = true)) {
            val active = mentionable.count { presence(lastSeen(it), now) == AgentPresence.ACTIVE }
            options += MentionOption(
                EVERYONE_TOKEN,
                "adds the $active active agent${if (active == 1) "" else "s"} by name",
                null,
                true,
            )
        }
        return options
    }

    /** The draft with the token at the caret replaced by "@name ", and the new caret position. */
    fun applyMention(text: String, caret: Int, token: MentionToken, name: String): Pair<String, Int> {
        val inserted = "@$name "
        val result = text.substring(0, token.start) + inserted + text.substring(caret.coerceIn(token.start, text.length))
        return result to token.start + inserted.length
    }

    /**
     * The bus has no group mention, so "@everyone" is replaced with each active agent's name.
     * Names already mentioned are not repeated, and the total stays within the server's
     * per-message cap.
     */
    fun expandEveryone(body: String, agents: List<BusAgent>, now: Instant): String {
        if (!EVERYONE.containsMatchIn(body)) return body
        val already = MENTION.findAll(body).map { it.groupValues[1].lowercase() }.toSet()
        val names = agents
            .filter { isMentionable(it.name) && presence(lastSeen(it), now) == AgentPresence.ACTIVE }
            .map { it.name }
            .filter { it.lowercase() !in already }
            .sortedBy { it.lowercase() }
            .take((MAX_MENTIONS_PER_MESSAGE - already.size).coerceAtLeast(0))
            .map { "@$it" }
        val replacement = if (names.isEmpty()) "everyone" else names.joinToString(" ")
        var first = true
        return EVERYONE.replace(body) {
            if (first) {
                first = false
                replacement
            } else {
                "everyone"
            }
        }
    }

    /** Agent questions on #humans that no operator message has replied to yet, oldest first. */
    fun waitingOnOperator(messages: List<BusMessage>): List<BusMessage> {
        val humans = messages.filter { it.channel == HumanChannel.NAME }
        val answered = humans.filter(HumanChannel::isHumanPost).mapNotNull(BusMessage::replyTo).toSet()
        return humans
            .filter {
                !HumanChannel.isHumanPost(it) &&
                    it.kind.equals(HumanMessageKind.QUESTION.wireName, ignoreCase = true) &&
                    it.sequence !in answered
            }
            .sortedBy(BusMessage::sequence)
    }
}
