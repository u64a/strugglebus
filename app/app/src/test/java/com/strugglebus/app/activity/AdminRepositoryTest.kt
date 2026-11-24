package com.strugglebus.app.activity

import com.strugglebus.app.core.EnrollmentParser
import com.strugglebus.app.core.MobileService
import com.strugglebus.app.core.MobileWriteService
import com.strugglebus.app.core.OperatorGrantStore
import com.strugglebus.app.core.ProfileStore
import com.strugglebus.app.core.model.ActionConfirmation
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.EnrollmentPayload
import com.strugglebus.app.core.model.HumanMessageKind
import com.strugglebus.app.core.model.OperatorAction
import com.strugglebus.app.core.model.OperatorActionResult
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.model.WriteGrantResult
import com.strugglebus.app.core.network.EnrollmentResult
import com.strugglebus.app.core.network.StreamEnd
import com.strugglebus.app.core.security.StoredMobileSession
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher

class AdminRepositoryTest {
    private val profileStore = FakeProfileStore()
    private val monitorService = FakeMonitorService()
    private val monitorRepository = MobileMonitorRepository(
        payloadParser = object : EnrollmentParser {
            override fun parse(rawPayload: String): EnrollmentPayload = error("unused")
        },
        profileStore = profileStore,
        apiClient = monitorService,
    )
    private val writeService = FakeWriteService()
    private val grantStore = FakeGrantStore()
    private val repository = AdminRepository(
        profileStore = profileStore,
        monitorRepository = monitorRepository,
        writeService = writeService,
        grantStore = grantStore,
    )

    @Test
    fun establishGrantStoresReturnedSecretWithoutExposingItFromRepository() = runBlocking {
        repository.establishGrant("correct horse battery staple")

        assertTrue(repository.hasGrant())
        assertEquals("dev_test", repository.currentDeviceId())
        assertEquals("grant_test", grantStore.secret)
        assertEquals("correct horse battery staple", writeService.password)
    }

    @Test
    fun performActionRedeclaresConfirmationBindingAndHumanReason() = runBlocking {
        repository.establishGrant("correct horse battery staple")
        val confirmation = repository.requestConfirmation(
            OperatorAction.BLOCK_AGENT,
            "agent_test",
        )

        val result = repository.performAction(
            confirmation = confirmation,
            authenticatedCipher = Cipher.getInstance("AES/GCM/NoPadding"),
            reason = "Agent is behaving unexpectedly",
        )

        assertTrue(result.applied)
        assertEquals(OperatorAction.BLOCK_AGENT, writeService.performedAction)
        assertEquals("agent_test", writeService.performedTarget)
        assertEquals("grant_test", writeService.performedGrant)
        assertEquals("Agent is behaving unexpectedly", writeService.performedReason)
    }
}

private class FakeWriteService : MobileWriteService {
    var password: String? = null
    var performedAction: OperatorAction? = null
    var performedTarget: String? = null
    var performedGrant: String? = null
    var performedReason: String? = null

    override suspend fun establishGrant(
        session: StoredMobileSession,
        requestId: String,
        operatorPassword: String,
        reason: String,
    ): WriteGrantResult {
        password = operatorPassword
        return WriteGrantResult("dev_test", "grant_test")
    }

    override suspend fun requestConfirmation(
        session: StoredMobileSession,
        requestId: String,
        action: OperatorAction,
        targetId: String,
    ) = ActionConfirmation(
        id = "confirmation_test",
        action = action,
        targetKind = "agent",
        targetId = targetId,
        targetLabel = "test-agent",
        expiresAt = "2026-09-10T00:00:00Z",
        effect = "Block test-agent.",
    )

    override suspend fun performAction(
        session: StoredMobileSession,
        requestId: String,
        confirmation: ActionConfirmation,
        grantSecret: String,
        reason: String,
    ): OperatorActionResult {
        performedAction = confirmation.action
        performedTarget = confirmation.targetId
        performedGrant = grantSecret
        performedReason = reason
        return OperatorActionResult(
            confirmation.action,
            confirmation.targetId,
            confirmation.targetLabel,
            true,
            "Applied",
        )
    }

    override suspend fun postHumanMessage(
        session: StoredMobileSession,
        requestId: String,
        body: String,
        kind: HumanMessageKind,
        replyTo: Long?,
        grantSecret: String,
    ): BusMessage = error("unused")
}

private class FakeGrantStore : OperatorGrantStore {
    var id: String? = null
    var secret: String? = null
    override fun hasGrant() = id != null && secret != null
    override fun deviceId() = id
    override fun save(deviceId: String, grantSecret: String) {
        id = deviceId
        secret = grantSecret
    }
    override fun createDecryptionCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    override fun decrypt(cipher: Cipher): String = requireNotNull(secret)
    override fun chatSecret(): String? = secret
    override fun clear() {
        id = null
        secret = null
    }
}

private class FakeProfileStore : ProfileStore {
    private val session = StoredMobileSession(
        endpoint = "https://example.invalid",
        credential = "credential",
        caDer = byteArrayOf(1),
        lastAcceptedSequence = 0,
    )
    override fun isEnrolled() = true
    override fun deviceInstanceId() = "instance"
    override fun enrollmentRequestId() = "enrollment"
    override fun saveEnrollment(endpoint: String, credential: String, caDer: ByteArray) = Unit
    override fun loadSession() = session
    override fun updateLastAcceptedSequence(sequence: Long) = Unit
    override fun flushLastAcceptedSequence() = Unit
    override fun clear() = Unit
}

private class FakeMonitorService : MobileService {
    override suspend fun redeem(payload: EnrollmentPayload, requestId: String): EnrollmentResult =
        error("unused")
    override suspend fun status(session: StoredMobileSession) = BusStatus.READY
    override suspend fun snapshot(session: StoredMobileSession): SnapshotResult = error("unused")
    override suspend fun channels(session: StoredMobileSession): List<BusChannel> = emptyList()
    override suspend fun agents(session: StoredMobileSession): List<BusAgent> = emptyList()
    override suspend fun stream(
        session: StoredMobileSession,
        cursor: Long,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd = error("unused")
}
