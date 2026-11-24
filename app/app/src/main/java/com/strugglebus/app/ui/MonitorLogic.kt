package com.strugglebus.app.ui

import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.network.ReconnectDecision
import com.strugglebus.app.core.network.ReconnectPolicy
import com.strugglebus.app.core.network.StreamEnd

class MonitorRetryState {
    var consecutiveFailures: Int = 0
        private set

    fun onMessage() {
        consecutiveFailures = 0
    }

    fun decide(end: StreamEnd): ReconnectDecision =
        ReconnectPolicy.decide(end, consecutiveFailures).also { decision ->
            if (decision is ReconnectDecision.Retry && !decision.quiet) {
                consecutiveFailures += 1
            }
        }
}

object MonitorLogic {
    /** The typed query with the channel chip applied; the chip wins over a typed in: filter. */
    fun effectiveQuery(state: BusMonitorUiState): FeedQuery {
        val typed = FeedLogic.parseQuery(state.query)
        return if (state.selectedChannel == null) typed else typed.copy(channel = state.selectedChannel)
    }

    /** What the feed shows: bus search results when present, otherwise the filtered live window plus loaded history. */
    fun visibleMessages(state: BusMonitorUiState): List<BusMessage> {
        state.searchResults?.let { return it }
        val query = effectiveQuery(state)
        return (state.messages + state.history)
            .distinctBy(BusMessage::sequence)
            .filter { FeedLogic.matches(it, query) }
            .sortedByDescending(BusMessage::sequence)
    }

    /** Older pages can only be fetched for one agent and/or channel; null when neither is chosen. */
    fun historyFilter(state: BusMonitorUiState): FeedQuery? {
        if (state.searchResults != null) return null
        val query = effectiveQuery(state)
        return query.takeIf { it.agent != null || it.channel != null }
    }

    fun streamChannel(): String? = null

    fun normalizeChannelSelection(
        selectedChannel: String?,
        channels: List<BusChannel>,
    ): String? = selectedChannel?.takeIf { selected -> channels.any { it.name == selected } }

    fun mergeMessages(
        current: List<BusMessage>,
        incoming: BusMessage,
        limit: Int,
    ): List<BusMessage> = (listOf(incoming) + current)
        .distinctBy(BusMessage::sequence)
        .sortedByDescending(BusMessage::sequence)
        .take(limit)
}
