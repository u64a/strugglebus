package com.strugglebus.app.core

import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.EnrollmentPayload
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.network.EnrollmentResult
import com.strugglebus.app.core.network.StreamEnd
import com.strugglebus.app.core.security.StoredMobileSession

interface EnrollmentParser {
    fun parse(rawPayload: String): EnrollmentPayload
}

interface ProfileStore {
    fun isEnrolled(): Boolean
    fun deviceInstanceId(): String
    /**
     * A stable correlator for the enrollment attempt. It is an audit aid, and it is correct
     * for the credential operations that are genuinely idempotent. It does NOT make
     * enrollment redemption retry-safe: the server verifies the one-time token before it
     * ever consults a request ID, and retains only a hash of the issued secret.
     */
    fun enrollmentRequestId(): String
    fun saveEnrollment(endpoint: String, credential: String, caDer: ByteArray)
    fun loadSession(): StoredMobileSession
    fun updateLastAcceptedSequence(sequence: Long)
    fun flushLastAcceptedSequence()
    fun clear()
}

interface MobileService {
    suspend fun redeem(
        payload: EnrollmentPayload,
        requestId: String,
    ): EnrollmentResult

    suspend fun status(session: StoredMobileSession): BusStatus

    suspend fun snapshot(session: StoredMobileSession): SnapshotResult

    suspend fun channels(session: StoredMobileSession): List<BusChannel>

    suspend fun agents(session: StoredMobileSession): List<BusAgent>

    /**
     * Older messages for one channel and/or agent, oldest first. [before] is an exclusive
     * sequence bound. Needs StruggleBus 0.2.62 or later.
     */
    suspend fun history(
        session: StoredMobileSession,
        channel: String?,
        agent: String?,
        before: Long?,
        limit: Int,
    ): List<BusMessage> = throw UnsupportedOperationException("History is not available.")

    /** Full-text search across the whole board, newest first. Needs StruggleBus 0.2.62 or later. */
    suspend fun search(
        session: StoredMobileSession,
        query: String,
        limit: Int,
    ): List<BusMessage> = throw UnsupportedOperationException("Search is not available.")

    suspend fun stream(
        session: StoredMobileSession,
        cursor: Long,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd
}
