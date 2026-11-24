package com.strugglebus.app.ui

import com.strugglebus.app.activity.MonitorRepository
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.network.ApiException
import com.strugglebus.app.core.network.StreamEnd
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class BusMonitorViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun channelSelectionFiltersPresentationWithoutRestartingOrFilteringStream() = runTest(dispatcher) {
        val repository = FakeMonitorRepository()
        val viewModel = BusMonitorViewModel(repository)

        viewModel.onForeground()
        runCurrent()
        viewModel.selectChannel("help")
        runCurrent()

        assertEquals(1, repository.streamCalls)
        assertEquals(listOf<String?>(null), repository.streamChannels)
        assertEquals("help", viewModel.uiState.value.selectedChannel)
        viewModel.onBackground()
        runCurrent()
    }

    @Test
    fun streamExceptionBecomesStoppedUiState() = runTest(dispatcher) {
        val repository = FakeMonitorRepository(streamFailure = IllegalStateException("broken profile"))
        val viewModel = BusMonitorViewModel(repository)

        viewModel.onForeground()
        runCurrent()

        assertEquals(ConnectionState.STOPPED, viewModel.uiState.value.connectionState)
        assertEquals("broken profile", viewModel.uiState.value.detail)
    }

    @Test
    fun rapidPauseAndResumeNeverOverlapsStreams() = runTest(dispatcher) {
        val repository = FakeMonitorRepository()
        val viewModel = BusMonitorViewModel(repository)

        viewModel.onForeground()
        runCurrent()
        viewModel.onBackground()
        viewModel.onForeground()
        runCurrent()

        assertEquals(2, repository.streamCalls)
        assertEquals(1, repository.maxActiveStreams)
        assertEquals(1, repository.activeStreams)
        assertEquals(ConnectionState.CONNECTED, viewModel.uiState.value.connectionState)
        viewModel.onBackground()
        runCurrent()
        assertEquals(0, repository.activeStreams)
        assertEquals(2, repository.flushCalls)
    }

    @Test
    fun backgroundCancellationKeepsThePausedMessage() = runTest(dispatcher) {
        val repository = FakeMonitorRepository()
        val viewModel = BusMonitorViewModel(repository)

        viewModel.onForeground()
        runCurrent()
        viewModel.onBackground()
        runCurrent()

        assertEquals(ConnectionState.STOPPED, viewModel.uiState.value.connectionState)
        assertEquals(
            "Monitoring paused while the app is in the background.",
            viewModel.uiState.value.detail,
        )
        assertEquals(0, repository.activeStreams)
    }

    @Test
    fun agentFilterLoadsOlderPagesAndBusSearchReplacesTheFeed() = runTest(dispatcher) {
        val repository = FakeMonitorRepository()
        val viewModel = BusMonitorViewModel(repository)

        viewModel.toggleAgentFilter("prox-manager")
        assertEquals("from:prox-manager", viewModel.uiState.value.query)
        viewModel.loadOlder()
        runCurrent()
        assertEquals(listOf(3L, 2L), MonitorLogic.visibleMessages(viewModel.uiState.value).map(BusMessage::sequence))
        viewModel.loadOlder()
        runCurrent()
        assertEquals("No older messages.", viewModel.uiState.value.historyNote)
        assertEquals(
            listOf(
                "history channel=null agent=prox-manager before=null",
                "history channel=null agent=prox-manager before=2",
            ),
            repository.historyCalls,
        )

        viewModel.toggleAgentFilter("prox-manager")
        assertEquals("", viewModel.uiState.value.query)
        viewModel.loadOlder()
        runCurrent()
        assertEquals(2, repository.historyCalls.size)

        viewModel.setQuery("disk")
        viewModel.searchBus()
        runCurrent()
        assertEquals(listOf(1L), viewModel.uiState.value.searchResults?.map(BusMessage::sequence))
        viewModel.setQuery("disk note")
        assertEquals(null, viewModel.uiState.value.searchResults)
    }

    @Test
    fun anOlderBusExplainsThatHistoryIsUnavailable() = runTest(dispatcher) {
        val viewModel = BusMonitorViewModel(FakeMonitorRepository(historySupported = false))

        viewModel.setQuery("disk")
        viewModel.searchBus()
        runCurrent()

        assertEquals(
            "This bus cannot search or page history yet. It needs StruggleBus 0.2.62 or later.",
            viewModel.uiState.value.historyNote,
        )
        assertEquals(false, viewModel.uiState.value.historyBusy)
    }
}

private class FakeMonitorRepository(
    private val streamFailure: Throwable? = null,
    private val historySupported: Boolean = true,
) : MonitorRepository {
    val historyCalls = mutableListOf<String>()

    private fun old(sequence: Long, agent: String) =
        BusMessage(sequence, "m$sequence", "help", "a", agent, "older disk note", "chat", null, "2026-11-15T00:00:00Z")

    override suspend fun history(channel: String?, agent: String?, before: Long?, limit: Int): List<BusMessage> {
        if (!historySupported) throw ApiException("Not found", 404)
        historyCalls += "history channel=$channel agent=$agent before=$before"
        return if (before == null) listOf(old(2, agent ?: "prox-manager"), old(3, agent ?: "prox-manager")) else emptyList()
    }

    override suspend fun search(query: String, limit: Int): List<BusMessage> {
        if (!historySupported) throw ApiException("Not found", 404)
        historyCalls += "search $query"
        return listOf(old(1, "prox-manager"))
    }

    var streamCalls = 0
    var activeStreams = 0
    var maxActiveStreams = 0
    var flushCalls = 0
    val streamChannels = mutableListOf<String?>()

    override fun isEnrolled() = true
    override suspend fun enroll(rawPayload: String) = Unit
    override suspend fun status() = BusStatus.READY
    override suspend fun snapshot() = SnapshotResult(
        latestSequence = 4,
        channels = listOf(BusChannel("1", "help", "Help")),
        agents = emptyList(),
        messages = emptyList(),
    )
    override suspend fun channels(): List<BusChannel> =
        listOf(BusChannel("1", "help", "Help"))
    override suspend fun agents(): List<BusAgent> = emptyList()
    override fun lastAcceptedSequence() = 0L

    override suspend fun stream(
        cursor: Long,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd {
        streamCalls += 1
        streamChannels += channel
        activeStreams += 1
        maxActiveStreams = maxOf(maxActiveStreams, activeStreams)
        try {
            onOpen()
            streamFailure?.let { throw it }
            awaitCancellation()
        } finally {
            activeStreams -= 1
        }
    }

    override fun flushCursor() {
        flushCalls += 1
    }

    override fun clearEnrollment() = Unit
}
