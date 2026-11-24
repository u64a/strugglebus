package com.strugglebus.app.ui

import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.ui.theme.Themes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Duration
import java.time.Instant

class FeedLogicTest {
    private val now: Instant = Instant.parse("2026-11-15T12:00:00Z")

    private fun agent(name: String, seenAgo: Duration?) = BusAgent(
        id = "id-$name",
        name = name,
        description = "",
        host = "",
        state = "registered",
        presence = "",
        lastSeenAt = seenAgo?.let { now.minus(it).toString() }.orEmpty(),
    )

    private fun message(
        sequence: Long,
        body: String,
        agent: String = "prox-manager",
        channel: String = "status",
        kind: String = "chat",
        replyTo: Long? = null,
    ) = BusMessage(sequence, "m$sequence", channel, "a", agent, body, kind, replyTo, now.toString())

    @Test
    fun parsesAgentChannelAndWords() {
        assertEquals(FeedQuery("disk full", "prox-manager", "status"), FeedLogic.parseQuery("from:@prox-manager disk in:#status  full"))
        assertEquals(FeedQuery("from: in:"), FeedLogic.parseQuery("from: in:"))
        assertTrue(FeedLogic.parseQuery("   ").isEmpty)
    }

    @Test
    fun withAgentReplacesOnlyTheFromPart() {
        assertEquals("from:bus-dev disk", FeedLogic.withAgent("from:prox-manager disk", "bus-dev"))
        assertEquals("disk", FeedLogic.withAgent("from:prox-manager disk", null))
        assertEquals("from:bus-dev", FeedLogic.withAgent("", "bus-dev"))
    }

    @Test
    fun matchesTextAgentAndChannelWithoutCase() {
        val m = message(1, "Disk is FULL on node 3")
        assertTrue(FeedLogic.matches(m, FeedQuery("full")))
        assertTrue(FeedLogic.matches(m, FeedQuery("prox")))
        assertTrue(FeedLogic.matches(m, FeedQuery("", "PROX-MANAGER", "Status")))
        assertFalse(FeedLogic.matches(m, FeedQuery("full", "bus-dev")))
        assertFalse(FeedLogic.matches(m, FeedQuery("", null, "humans")))
    }

    @Test
    fun presenceUsesFiveMinuteAndOneHourWindows() {
        assertEquals(AgentPresence.ACTIVE, FeedLogic.presence(now.minusSeconds(299), now))
        assertEquals(AgentPresence.IDLE, FeedLogic.presence(now.minusSeconds(301), now))
        assertEquals(AgentPresence.OFFLINE, FeedLogic.presence(now.minusSeconds(3601), now))
        assertEquals(AgentPresence.OFFLINE, FeedLogic.presence(null, now))
        assertEquals("active now", FeedLogic.presenceLabel(now.minusSeconds(20), now))
        assertEquals("idle 30m", FeedLogic.presenceLabel(now.minusSeconds(1800), now))
        assertEquals("seen 3h ago", FeedLogic.presenceLabel(now.minus(Duration.ofHours(3)), now))
        assertEquals("never seen", FeedLogic.presenceLabel(null, now))
    }

    @Test
    fun segmentsMentionsAndHits() {
        val parts = FeedLogic.segment("ask @prox-manager about the disk, not a@b-c.com", "DISK")
        assertEquals(
            listOf(
                TextSegment("ask ", SegmentKind.PLAIN),
                TextSegment("@prox-manager", SegmentKind.MENTION),
                TextSegment(" about the ", SegmentKind.PLAIN),
                TextSegment("disk", SegmentKind.HIT),
                TextSegment(", not a@b-c.com", SegmentKind.PLAIN),
            ),
            parts,
        )
        assertEquals(listOf(TextSegment("plain", SegmentKind.PLAIN)), FeedLogic.segment("plain", ""))
    }

    @Test
    fun onlyHyphenatedNamesAreMentionable() {
        assertTrue(FeedLogic.isMentionable("prox-manager"))
        assertFalse(FeedLogic.isMentionable("solo"))
        assertFalse(FeedLogic.isMentionable("bad name"))
    }

    @Test
    fun findsTheMentionBeingTyped() {
        assertEquals(MentionToken(4, "pro"), FeedLogic.activeMentionToken("hey @pro", 8))
        assertEquals(MentionToken(0, ""), FeedLogic.activeMentionToken("@", 1))
        assertNull(FeedLogic.activeMentionToken("mail@pro", 8))
        assertNull(FeedLogic.activeMentionToken("hey there", 9))
    }

    @Test
    fun offersMatchingAgentsThenEveryone() {
        val agents = listOf(
            agent("prox-manager", Duration.ofMinutes(1)),
            agent("u64-security", Duration.ofMinutes(2)),
            agent("old-prox", Duration.ofDays(2)),
            agent("solo", Duration.ofMinutes(1)),
        )
        val options = FeedLogic.mentionOptions(agents, "pro", now)
        assertEquals(listOf("prox-manager", "old-prox"), options.map { it.insert })
        val all = FeedLogic.mentionOptions(agents, "e", now)
        assertEquals("everyone", all.last().insert)
        assertTrue(all.last().isGroup)
        assertEquals("adds the 2 active agents by name", all.last().meta)
    }

    @Test
    fun appliesAMentionAtTheCaret() {
        val token = FeedLogic.activeMentionToken("hey @pro there", 8)!!
        assertEquals("hey @prox-manager  there" to 18, FeedLogic.applyMention("hey @pro there", 8, token, "prox-manager"))
    }

    @Test
    fun expandsEveryoneToActiveAgentsOnce() {
        val agents = listOf(
            agent("prox-manager", Duration.ofMinutes(1)),
            agent("u64-security", Duration.ofMinutes(2)),
            agent("idle-one", Duration.ofMinutes(30)),
        )
        assertEquals(
            "@prox-manager @u64-security: reboot at 5, everyone ok?",
            FeedLogic.expandEveryone("@everyone: reboot at 5, @everyone ok?", agents, now),
        )
        assertEquals(
            "@prox-manager and @u64-security",
            FeedLogic.expandEveryone("@prox-manager and @everyone", agents, now),
        )
        assertEquals("everyone hello", FeedLogic.expandEveryone("@everyone hello", emptyList(), now))
        assertEquals("no group here", FeedLogic.expandEveryone("no group here", agents, now))
    }

    @Test
    fun listsUnansweredAgentQuestions() {
        val messages = listOf(
            message(1, "can I reboot?", channel = "humans", kind = "question"),
            message(2, "which disk?", agent = "u64-security", channel = "humans", kind = "question"),
            message(3, "yes", agent = "human:operator", channel = "humans", kind = "answer", replyTo = 1),
            message(4, "question elsewhere", channel = "status", kind = "question"),
            message(5, "my own question", agent = "human:operator", channel = "humans", kind = "question"),
        )
        assertEquals(listOf(2L), FeedLogic.waitingOnOperator(messages).map(BusMessage::sequence))
    }

    @Test
    fun monitorShowsFilteredLiveMessagesPlusLoadedHistory() {
        val state = BusMonitorUiState(
            messages = listOf(message(5, "new disk alert"), message(4, "hello", agent = "bus-dev")),
            history = listOf(message(2, "old disk alert"), message(5, "new disk alert")),
            query = "from:prox-manager disk",
        )
        assertEquals(listOf(5L, 2L), MonitorLogic.visibleMessages(state).map(BusMessage::sequence))
        assertEquals("prox-manager", MonitorLogic.historyFilter(state)?.agent)
        assertNull(MonitorLogic.historyFilter(BusMonitorUiState(query = "disk")))
        val searching = state.copy(searchResults = listOf(message(9, "from the bus")))
        assertEquals(listOf(9L), MonitorLogic.visibleMessages(searching).map(BusMessage::sequence))
        assertNull(MonitorLogic.historyFilter(searching))
        assertEquals("humans", MonitorLogic.effectiveQuery(state.copy(selectedChannel = "humans")).channel)
    }

    @Test
    fun everyPaletteIsReadable() {
        assertEquals(19, Themes.all.size)
        assertEquals(Themes.all.size, Themes.all.map { it.id }.toSet().size)
        for (palette in Themes.all) {
            val colors = Themes.derive(palette)
            for (text in listOf(colors.muted, colors.soft, colors.accentText, colors.okText, colors.badText)) {
                assertTrue("${palette.id} text contrast", Themes.contrast(text, colors.bg) >= 4.5)
            }
            assertTrue("${palette.id} on accent", Themes.contrast(colors.onAccent, colors.accent) >= 4.5)
        }
        assertEquals("retro-82", Themes.find("no-such-theme", light = false).id)
        assertEquals("catppuccin-latte", Themes.find("tokyo-night", light = true).id)
    }
}
