package com.strugglebus.app.activity

import com.strugglebus.app.core.EnrollmentParser
import com.strugglebus.app.core.MobileService
import com.strugglebus.app.core.OperatorGrantStore
import com.strugglebus.app.core.ProfileStore
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.EnrollmentPayload
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.network.StreamEnd
import com.strugglebus.app.core.security.CaCertificate

interface MonitorRepository {
    fun isEnrolled(): Boolean
    suspend fun enroll(rawPayload: String)
    suspend fun status(): BusStatus
    suspend fun snapshot(): SnapshotResult
    suspend fun channels(): List<BusChannel>
    suspend fun agents(): List<BusAgent>
    suspend fun history(channel: String?, agent: String?, before: Long?, limit: Int): List<BusMessage> =
        throw UnsupportedOperationException("History is not available.")
    suspend fun search(query: String, limit: Int): List<BusMessage> =
        throw UnsupportedOperationException("Search is not available.")
    fun lastAcceptedSequence(): Long
    suspend fun stream(
        cursor: Long,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd
    fun flushCursor()
    fun clearEnrollment()
}

class MobileMonitorRepository(
    private val payloadParser: EnrollmentParser,
    private val profileStore: ProfileStore,
    private val apiClient: MobileService,
    private val operatorGrantStore: OperatorGrantStore? = null,
) : MonitorRepository {
    override fun isEnrolled(): Boolean = profileStore.isEnrolled()

    override suspend fun enroll(rawPayload: String) {
        val payload: EnrollmentPayload = payloadParser.parse(rawPayload)
        val caDer = CaCertificate.parseAndVerify(payload.caDer, payload.caSha256)
        val result = apiClient.redeem(
            payload = payload,
            requestId = profileStore.enrollmentRequestId(),
        )
        operatorGrantStore?.clear()
        profileStore.saveEnrollment(payload.endpoint, result.credential, caDer)
    }

    override suspend fun status(): BusStatus = apiClient.status(profileStore.loadSession())

    override suspend fun snapshot(): SnapshotResult {
        val result = apiClient.snapshot(profileStore.loadSession())
        profileStore.updateLastAcceptedSequence(result.latestSequence)
        return result
    }

    override suspend fun channels(): List<BusChannel> =
        apiClient.channels(profileStore.loadSession())

    override suspend fun agents(): List<BusAgent> = apiClient.agents(profileStore.loadSession())

    override suspend fun history(channel: String?, agent: String?, before: Long?, limit: Int): List<BusMessage> =
        apiClient.history(profileStore.loadSession(), channel, agent, before, limit)

    override suspend fun search(query: String, limit: Int): List<BusMessage> =
        apiClient.search(profileStore.loadSession(), query, limit)

    override fun lastAcceptedSequence(): Long = profileStore.loadSession().lastAcceptedSequence

    override suspend fun stream(
        cursor: Long,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd = apiClient.stream(
        session = profileStore.loadSession(),
        cursor = cursor,
        channel = channel,
        onOpen = onOpen,
        onMessage = { message ->
            profileStore.updateLastAcceptedSequence(message.sequence)
            onMessage(message)
        },
    )

    override fun flushCursor() = profileStore.flushLastAcceptedSequence()

    override fun clearEnrollment() {
        operatorGrantStore?.clear()
        profileStore.clear()
    }
}
