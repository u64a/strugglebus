package com.strugglebus.app.activity

import com.strugglebus.app.core.MobileWriteService
import com.strugglebus.app.core.OperatorGrantStore
import com.strugglebus.app.core.ProfileStore
import com.strugglebus.app.core.model.ActionConfirmation
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.EnrollmentOutcome
import com.strugglebus.app.core.model.EnrollmentRequest
import com.strugglebus.app.core.model.OperatorAction
import com.strugglebus.app.core.model.OperatorActionResult
import java.util.UUID
import javax.crypto.Cipher

class AdminRepository(
    private val profileStore: ProfileStore,
    private val monitorRepository: MobileMonitorRepository,
    private val writeService: MobileWriteService,
    private val grantStore: OperatorGrantStore,
) {
    fun hasGrant(): Boolean = grantStore.hasGrant()

    fun currentDeviceId(): String? = grantStore.deviceId()

    suspend fun status(): BusStatus = monitorRepository.status()

    suspend fun agents(): List<BusAgent> = monitorRepository.agents()

    suspend fun establishGrant(operatorPassword: String) {
        // A lost response may still have replaced the server-side grant. Remove any stale
        // local copy first so the UI never presents an unusable grant as configured.
        grantStore.clear()
        val result = writeService.establishGrant(
            session = profileStore.loadSession(),
            requestId = UUID.randomUUID().toString(),
            operatorPassword = operatorPassword,
            reason = "Establish protected Android operator access",
        )
        grantStore.save(result.deviceId, result.grantSecret)
    }

    suspend fun requestConfirmation(
        action: OperatorAction,
        targetId: String,
    ): ActionConfirmation = writeService.requestConfirmation(
        session = profileStore.loadSession(),
        requestId = UUID.randomUUID().toString(),
        action = action,
        targetId = targetId,
    )

    fun createGrantDecryptionCipher(): Cipher = grantStore.createDecryptionCipher()

    suspend fun performAction(
        confirmation: ActionConfirmation,
        authenticatedCipher: Cipher,
        reason: String,
    ): OperatorActionResult {
        val grantSecret = grantStore.decrypt(authenticatedCipher)
        return writeService.performAction(
            session = profileStore.loadSession(),
            requestId = UUID.randomUUID().toString(),
            confirmation = confirmation,
            grantSecret = grantSecret,
            reason = reason,
        )
    }

    /** Enrolls an agent, service principal or device; the grant is unlocked by the biometric prompt. */
    suspend fun createEnrollment(
        request: EnrollmentRequest,
        authenticatedCipher: Cipher,
    ): EnrollmentOutcome {
        val grantSecret = grantStore.decrypt(authenticatedCipher)
        return writeService.createEnrollment(
            session = profileStore.loadSession(),
            requestId = UUID.randomUUID().toString(),
            request = request,
            grantSecret = grantSecret,
        )
    }

    fun clearGrant() = grantStore.clear()
}
