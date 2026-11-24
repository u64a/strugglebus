package com.strugglebus.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strugglebus.app.activity.MonitorRepository
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.network.ApiException
import com.strugglebus.app.core.network.EnrollmentStrandedException
import com.strugglebus.app.core.network.ReconnectDecision
import com.strugglebus.app.core.network.TerminalState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class ConnectionState {
    NOT_ENROLLED,
    ENROLLING,
    ENROLLMENT_STRANDED,
    LOADING_SNAPSHOT,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    FROZEN,
    REVOKED,
    STOPPED,
}

data class BusMonitorUiState(
    val connectionState: ConnectionState = ConnectionState.NOT_ENROLLED,
    val isFrozen: Boolean = false,
    val channels: List<BusChannel> = emptyList(),
    val selectedChannel: String? = null,
    val messages: List<BusMessage> = emptyList(),
    val detail: String? = null,
    val agents: List<BusAgent> = emptyList(),
    /** What the operator typed in the filter box, for example "from:prox-manager disk". */
    val query: String = "",
    /** Older messages fetched on request; kept apart from the live window so it is never trimmed. */
    val history: List<BusMessage> = emptyList(),
    /** Whole-bus search results, newest first, or null when the live feed is showing. */
    val searchResults: List<BusMessage>? = null,
    val historyBusy: Boolean = false,
    val historyNote: String? = null,
)

private sealed interface MonitorCommand {
    data class Start(val fetchSnapshot: Boolean) : MonitorCommand
    data class Enroll(val rawPayload: String) : MonitorCommand
    data object Pause : MonitorCommand
    data object RemoveEnrollment : MonitorCommand
}

class BusMonitorViewModel(
    private val repository: MonitorRepository,
) : ViewModel() {
    private val _uiState = MutableStateFlow(
        BusMonitorUiState(
            connectionState = if (repository.isEnrolled()) {
                ConnectionState.LOADING_SNAPSHOT
            } else {
                ConnectionState.NOT_ENROLLED
            },
        ),
    )
    val uiState: StateFlow<BusMonitorUiState> = _uiState.asStateFlow()
    private val commands = Channel<MonitorCommand>(Channel.UNLIMITED)
    private var hasLoadedSnapshot = false

    init {
        viewModelScope.launch {
            var activeJob: Job? = null
            for (command in commands) {
                activeJob?.cancelAndJoin()
                activeJob = when (command) {
                    is MonitorCommand.Start -> launch {
                        runMonitorSafely(command.fetchSnapshot)
                    }
                    is MonitorCommand.Enroll -> launch {
                        enrollAndMonitor(command.rawPayload)
                    }
                    MonitorCommand.Pause -> {
                        _uiState.update {
                            it.copy(
                                connectionState = ConnectionState.STOPPED,
                                detail = "Monitoring paused while the app is in the background.",
                            )
                        }
                        null
                    }
                    MonitorCommand.RemoveEnrollment -> {
                        try {
                            repository.clearEnrollment()
                            hasLoadedSnapshot = false
                            _uiState.value = BusMonitorUiState()
                        } catch (failure: Throwable) {
                            _uiState.update {
                                it.copy(
                                    connectionState = ConnectionState.STOPPED,
                                    detail = failure.safeMessage(),
                                )
                            }
                        }
                        null
                    }
                }
            }
        }
    }

    fun onForeground() {
        if (repository.isEnrolled()) {
            commands.trySend(MonitorCommand.Start(fetchSnapshot = !hasLoadedSnapshot))
        }
    }

    fun onBackground() {
        commands.trySend(MonitorCommand.Pause)
    }

    fun enroll(rawPayload: String) {
        commands.trySend(MonitorCommand.Enroll(rawPayload))
    }

    fun selectChannel(channel: String?) {
        if (_uiState.value.selectedChannel == channel) return
        _uiState.update { it.copy(selectedChannel = channel, detail = null) }
    }

    fun setQuery(raw: String) {
        if (raw.length > MAX_QUERY_CHARS) return
        _uiState.update { it.copy(query = raw, searchResults = null, historyNote = null) }
    }

    /** Filters the feed to one agent, or clears that filter when the same agent is picked again. */
    fun toggleAgentFilter(agentName: String) {
        _uiState.update { state ->
            val current = FeedLogic.parseQuery(state.query).agent
            val next = if (current.equals(agentName, ignoreCase = true)) null else agentName
            state.copy(query = FeedLogic.withAgent(state.query, next), searchResults = null, historyNote = null)
        }
    }

    fun clearSearch() {
        _uiState.update { it.copy(searchResults = null, historyNote = null) }
    }

    /** Searches the whole board for the typed words, not just the messages held on this phone. */
    fun searchBus() {
        val text = FeedLogic.parseQuery(_uiState.value.query).text
        if (text.isBlank() || _uiState.value.historyBusy) return
        runHistory { state ->
            val hits = repository.search(text, SEARCH_LIMIT)
            state.copy(
                searchResults = hits,
                historyNote = if (hits.isEmpty()) "Nothing on the bus matches those words." else null,
            )
        }
    }

    /** Fetches the page of messages before the oldest one shown for the current agent or channel. */
    fun loadOlder() {
        val state = _uiState.value
        val filter = MonitorLogic.historyFilter(state) ?: return
        if (state.historyBusy) return
        val before = MonitorLogic.visibleMessages(state).minOfOrNull(BusMessage::sequence)
        runHistory { current ->
            val older = repository.history(filter.channel, filter.agent, before, HISTORY_PAGE)
            current.copy(
                history = (current.history + older).distinctBy(BusMessage::sequence),
                historyNote = if (older.isEmpty()) "No older messages." else null,
            )
        }
    }

    private fun runHistory(block: suspend (BusMonitorUiState) -> BusMonitorUiState) {
        _uiState.update { it.copy(historyBusy = true, historyNote = null) }
        viewModelScope.launch {
            try {
                val result = block(_uiState.value)
                _uiState.update {
                    it.copy(
                        history = result.history,
                        searchResults = result.searchResults,
                        historyNote = result.historyNote,
                        historyBusy = false,
                    )
                }
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Throwable) {
                val unsupported = failure is UnsupportedOperationException ||
                    (failure as? ApiException)?.statusCode in setOf(404, 405, 422)
                _uiState.update {
                    it.copy(
                        historyBusy = false,
                        historyNote = if (unsupported) {
                            "This bus cannot search or page history yet. It needs StruggleBus 0.2.62 or later."
                        } else {
                            failure.safeMessage()
                        },
                    )
                }
            }
        }
    }

    fun recover() {
        commands.trySend(MonitorCommand.Start(fetchSnapshot = true))
    }

    fun removeEnrollment() {
        commands.trySend(MonitorCommand.RemoveEnrollment)
    }

    /** Shows an accepted post immediately; the stream's later copy is de-duplicated by sequence. */
    fun acceptPostedMessage(message: BusMessage) {
        _uiState.update { state ->
            state.copy(
                messages = MonitorLogic.mergeMessages(
                    current = state.messages,
                    incoming = message,
                    limit = MAX_MESSAGES,
                ),
            )
        }
    }

    private suspend fun enrollAndMonitor(rawPayload: String) {
        _uiState.value = BusMonitorUiState(connectionState = ConnectionState.ENROLLING)
        try {
            repository.enroll(rawPayload = rawPayload)
            runMonitorSafely(fetchSnapshot = true)
        } catch (failure: CancellationException) {
            throw failure
        } catch (failure: EnrollmentStrandedException) {
            repository.clearEnrollment()
            _uiState.value = BusMonitorUiState(
                connectionState = ConnectionState.ENROLLMENT_STRANDED,
                detail = failure.safeMessage(),
            )
        } catch (failure: Throwable) {
            _uiState.value = BusMonitorUiState(
                connectionState = ConnectionState.NOT_ENROLLED,
                detail = failure.safeMessage(),
            )
        }
    }

    private suspend fun runMonitorSafely(fetchSnapshot: Boolean) {
        try {
            runMonitor(fetchSnapshot)
        } catch (failure: CancellationException) {
            throw failure
        } catch (failure: Throwable) {
            _uiState.update {
                it.copy(
                    connectionState = ConnectionState.STOPPED,
                    detail = failure.safeMessage(),
                )
            }
        }
    }

    private suspend fun runMonitor(fetchSnapshot: Boolean) {
        var cursor = repository.lastAcceptedSequence()
        if (fetchSnapshot) {
            _uiState.update {
                it.copy(connectionState = ConnectionState.LOADING_SNAPSHOT, detail = null)
            }
            val status = repository.status()
            _uiState.update { it.copy(isFrozen = status == BusStatus.FROZEN) }
            val snapshot = repository.snapshot()
            hasLoadedSnapshot = true
            cursor = snapshot.latestSequence
            _uiState.update {
                it.copy(
                    connectionState = ConnectionState.CONNECTING,
                    channels = snapshot.channels,
                    agents = snapshot.agents,
                    selectedChannel = MonitorLogic.normalizeChannelSelection(
                        it.selectedChannel,
                        snapshot.channels,
                    ),
                    messages = snapshot.messages.sortedByDescending(BusMessage::sequence),
                    detail = null,
                )
            }
        } else {
            _uiState.update {
                it.copy(connectionState = ConnectionState.CONNECTING, detail = null)
            }
        }

        val channelRefreshJob = CoroutineScope(currentCoroutineContext()).launch {
            while (currentCoroutineContext().isActive) {
                delay(CHANNEL_REFRESH_MILLIS)
                try {
                    val channels = repository.channels()
                    _uiState.update { state ->
                        state.copy(
                            channels = channels,
                            selectedChannel = MonitorLogic.normalizeChannelSelection(
                                state.selectedChannel,
                                channels,
                            ),
                        )
                    }
                } catch (failure: CancellationException) {
                    throw failure
                } catch (_: Throwable) {
                    // The live stream remains authoritative while channel metadata is unavailable.
                }
                try {
                    val agents = repository.agents()
                    _uiState.update { it.copy(agents = agents) }
                } catch (failure: CancellationException) {
                    throw failure
                } catch (_: Throwable) {
                    // Presence simply goes stale until the next refresh succeeds.
                }
            }
        }
        val statusRefreshJob = CoroutineScope(currentCoroutineContext()).launch {
            while (currentCoroutineContext().isActive) {
                delay(STATUS_REFRESH_MILLIS)
                try {
                    val status = repository.status()
                    _uiState.update { it.copy(isFrozen = status == BusStatus.FROZEN) }
                } catch (failure: CancellationException) {
                    throw failure
                } catch (_: Throwable) {
                    // Keep the last known containment state during a transient polling failure.
                }
            }
        }
        val retryState = MonitorRetryState()
        try {
            while (currentCoroutineContext().isActive) {
                val end = repository.stream(
                    cursor = cursor,
                    channel = MonitorLogic.streamChannel(),
                    onOpen = {
                        _uiState.update {
                            it.copy(connectionState = ConnectionState.CONNECTED, detail = null)
                        }
                    },
                    onMessage = { message ->
                        retryState.onMessage()
                        cursor = maxOf(cursor, message.sequence)
                        _uiState.update { state ->
                            state.copy(
                                messages = MonitorLogic.mergeMessages(
                                    current = state.messages,
                                    incoming = message,
                                    limit = MAX_MESSAGES,
                                ),
                            )
                        }
                    },
                )
                when (val decision = retryState.decide(end)) {
                    is ReconnectDecision.Retry -> {
                        _uiState.update {
                            it.copy(
                                connectionState = ConnectionState.RECONNECTING,
                                detail = if (decision.quiet) {
                                    null
                                } else {
                                    "Connection interrupted; retrying."
                                },
                            )
                        }
                        delay(decision.delayMillis)
                    }
                    is ReconnectDecision.Stop -> {
                        if (decision.state == TerminalState.FROZEN) {
                            _uiState.update { it.copy(isFrozen = true) }
                            delay(FROZEN_STATUS_POLL_MILLIS)
                            continue
                        }
                        _uiState.update {
                            it.copy(
                                connectionState = when (decision.state) {
                                    TerminalState.FROZEN -> ConnectionState.FROZEN
                                    TerminalState.REVOKED -> ConnectionState.REVOKED
                                    TerminalState.STOPPED -> ConnectionState.STOPPED
                                },
                                isFrozen = decision.state == TerminalState.FROZEN || it.isFrozen,
                                detail = decision.detail,
                            )
                        }
                        return
                    }
                }
            }
        } finally {
            withContext(NonCancellable) {
                channelRefreshJob.cancelAndJoin()
                statusRefreshJob.cancelAndJoin()
                runCatching { repository.flushCursor() }
            }
        }
    }

    private fun Throwable.safeMessage(): String =
        message?.takeIf(String::isNotBlank) ?: "Unable to connect to StruggleBus."

    private companion object {
        const val MAX_MESSAGES = 200
        const val MAX_QUERY_CHARS = 200
        const val SEARCH_LIMIT = 50
        const val HISTORY_PAGE = 100
        const val CHANNEL_REFRESH_MILLIS = 15_000L
        const val STATUS_REFRESH_MILLIS = 5_000L
        const val FROZEN_STATUS_POLL_MILLIS = 5_000L
    }
}
