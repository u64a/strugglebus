package com.strugglebus.app.core

import com.strugglebus.app.core.model.ActionConfirmation
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.EnrollmentOutcome
import com.strugglebus.app.core.model.EnrollmentRequest
import com.strugglebus.app.core.model.HumanMessageKind
import com.strugglebus.app.core.model.OperatorAction
import com.strugglebus.app.core.model.OperatorActionResult
import com.strugglebus.app.core.model.WriteGrantResult
import com.strugglebus.app.core.security.StoredMobileSession
import javax.crypto.Cipher

interface MobileWriteService {
    suspend fun establishGrant(
        session: StoredMobileSession,
        requestId: String,
        operatorPassword: String,
        reason: String,
    ): WriteGrantResult

    suspend fun requestConfirmation(
        session: StoredMobileSession,
        requestId: String,
        action: OperatorAction,
        targetId: String,
    ): ActionConfirmation

    suspend fun performAction(
        session: StoredMobileSession,
        requestId: String,
        confirmation: ActionConfirmation,
        grantSecret: String,
        reason: String,
    ): OperatorActionResult

    /**
     * Posts to #humans as the shared human operator. [requestId] must be a canonical
     * lowercase UUID and must be reused unchanged when retrying the same post, so a
     * response lost in transit can never produce a duplicate message.
     */
    suspend fun postHumanMessage(
        session: StoredMobileSession,
        requestId: String,
        body: String,
        kind: HumanMessageKind,
        replyTo: Long?,
        grantSecret: String,
    ): BusMessage

    /**
     * Enrolls an agent, a service principal or another device with this device's operator
     * grant. The returned secret is shown once by the bus. Needs StruggleBus 0.2.62 or later.
     */
    suspend fun createEnrollment(
        session: StoredMobileSession,
        requestId: String,
        request: EnrollmentRequest,
        grantSecret: String,
    ): EnrollmentOutcome = throw UnsupportedOperationException("Enrollment is not available.")
}

interface OperatorGrantStore {
    fun hasGrant(): Boolean
    fun deviceId(): String?
    fun save(deviceId: String, grantSecret: String)
    fun createDecryptionCipher(): Cipher
    fun decrypt(cipher: Cipher): String
    /**
     * Grant copy for #humans chat that is readable without a biometric prompt. Null when the
     * grant was set up before chat support, in which case it must be set up again.
     */
    fun chatSecret(): String?
    fun clear()
}
