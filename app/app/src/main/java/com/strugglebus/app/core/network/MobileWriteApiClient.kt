package com.strugglebus.app.core.network

import com.squareup.moshi.Moshi
import com.strugglebus.app.core.MobileWriteService
import com.strugglebus.app.core.model.ActionConfirmation
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.EnrollmentKind
import com.strugglebus.app.core.model.EnrollmentOutcome
import com.strugglebus.app.core.model.EnrollmentRequest
import com.strugglebus.app.core.model.HumanChannel
import com.strugglebus.app.core.model.HumanMessageKind
import com.strugglebus.app.core.model.OperatorAction
import com.strugglebus.app.core.model.OperatorActionResult
import com.strugglebus.app.core.model.WriteGrantResult
import com.strugglebus.app.core.security.StoredMobileSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.HttpUrl.Companion.toHttpUrl

class MobileWriteApiClient(
    moshi: Moshi,
    private val clientProvider: PinnedHttpClientProvider = PinnedHttpClientProvider(),
) : MobileWriteService {
    private val grantRequestAdapter = moshi.adapter(GrantRequestWire::class.java)
    private val grantResponseAdapter = moshi.adapter(GrantResponseWire::class.java).failOnUnknown()
    private val confirmationRequestAdapter = moshi.adapter(ConfirmationRequestWire::class.java)
    private val confirmationResponseAdapter = moshi.adapter(ConfirmationResponseWire::class.java).failOnUnknown()
    private val actionRequestAdapter = moshi.adapter(ActionRequestWire::class.java)
    private val actionResponseAdapter = moshi.adapter(ActionResponseWire::class.java).failOnUnknown()
    private val humanPostRequestAdapter = moshi.adapter(HumanPostRequestWire::class.java)
    // Lenient on purpose: the post has already been accepted when this parses, so a new
    // server field must not turn a successful post into an apparent failure.
    private val messageAdapter = moshi.adapter(MessageWire::class.java)
    private val errorAdapter = moshi.adapter(ErrorWire::class.java)
    // Lenient for the same reason: the enrollment exists once the bus answers, and its secret
    // is shown only once.
    private val agentEnrollmentRequestAdapter = moshi.adapter(AgentEnrollmentRequestWire::class.java)
    private val agentEnrollmentResponseAdapter = moshi.adapter(AgentEnrollmentResponseWire::class.java)
    private val servicePrincipalRequestAdapter = moshi.adapter(ServicePrincipalRequestWire::class.java)
    private val servicePrincipalResponseAdapter = moshi.adapter(ServicePrincipalResponseWire::class.java)
    private val deviceEnrollmentRequestAdapter = moshi.adapter(DeviceEnrollmentRequestWire::class.java)
    private val deviceEnrollmentResponseAdapter = moshi.adapter(DeviceEnrollmentResponseWire::class.java)

    override suspend fun establishGrant(
        session: StoredMobileSession,
        requestId: String,
        operatorPassword: String,
        reason: String,
    ): WriteGrantResult = withContext(Dispatchers.IO) {
        val wire = post(
            session = session,
            path = "api/mobile/grants",
            json = grantRequestAdapter.toJson(
                GrantRequestWire(requestId, operatorPassword, reason),
            ),
            expectedStatus = 201,
            parser = grantResponseAdapter::fromJson,
        )
        require(wire.deviceId.isNotBlank() && wire.grantSecret.isNotBlank()) {
            "Grant response was incomplete."
        }
        WriteGrantResult(wire.deviceId, wire.grantSecret)
    }

    override suspend fun requestConfirmation(
        session: StoredMobileSession,
        requestId: String,
        action: OperatorAction,
        targetId: String,
    ): ActionConfirmation = withContext(Dispatchers.IO) {
        val wire = post(
            session = session,
            path = "api/mobile/confirmations",
            json = confirmationRequestAdapter.toJson(
                ConfirmationRequestWire(requestId, action.wireName, targetId),
            ),
            expectedStatus = 201,
            parser = confirmationResponseAdapter::fromJson,
        )
        require(wire.action == action.wireName && wire.targetId == targetId) {
            "Confirmation binding did not match the requested action."
        }
        ActionConfirmation(
            id = wire.confirmationId,
            action = action,
            targetKind = wire.targetKind,
            targetId = wire.targetId,
            targetLabel = wire.targetLabel,
            expiresAt = wire.expiresAt,
            effect = wire.effect,
        )
    }

    override suspend fun performAction(
        session: StoredMobileSession,
        requestId: String,
        confirmation: ActionConfirmation,
        grantSecret: String,
        reason: String,
    ): OperatorActionResult = withContext(Dispatchers.IO) {
        val wire = post(
            session = session,
            path = "api/mobile/actions",
            json = actionRequestAdapter.toJson(
                ActionRequestWire(
                    requestId = requestId,
                    confirmationId = confirmation.id,
                    action = confirmation.action.wireName,
                    targetId = confirmation.targetId,
                    grantSecret = grantSecret,
                    reason = reason,
                ),
            ),
            expectedStatus = 200,
            parser = actionResponseAdapter::fromJson,
        )
        require(wire.action == confirmation.action.wireName && wire.targetId == confirmation.targetId) {
            "Action response did not match the confirmed action."
        }
        OperatorActionResult(
            action = confirmation.action,
            targetId = wire.targetId,
            targetLabel = wire.targetLabel,
            applied = wire.applied,
            detail = wire.detail,
        )
    }

    override suspend fun postHumanMessage(
        session: StoredMobileSession,
        requestId: String,
        body: String,
        kind: HumanMessageKind,
        replyTo: Long?,
        grantSecret: String,
    ): BusMessage = withContext(Dispatchers.IO) {
        val wire = post(
            session = session,
            path = HUMAN_POST_PATH,
            json = humanPostRequestJson(requestId, body, kind, replyTo, grantSecret),
            expectedStatus = 201,
            parser = messageAdapter::fromJson,
        )
        require(wire.channel == HumanChannel.NAME) {
            "The server placed the post outside #${HumanChannel.NAME}."
        }
        BusMessage(
            sequence = wire.sequence,
            id = wire.id,
            channel = wire.channel,
            agentId = wire.agentId,
            agentName = wire.agentName,
            body = wire.body,
            kind = wire.kind,
            replyTo = wire.replyTo,
            createdAt = wire.createdAt,
        )
    }

    override suspend fun createEnrollment(
        session: StoredMobileSession,
        requestId: String,
        request: EnrollmentRequest,
        grantSecret: String,
    ): EnrollmentOutcome = withContext(Dispatchers.IO) {
        when (request.kind) {
            EnrollmentKind.AGENT -> {
                val wire = post(
                    session = session,
                    path = "api/mobile/enrollments/agents",
                    json = agentEnrollmentRequestAdapter.toJson(
                        AgentEnrollmentRequestWire(requestId, request.name, request.extra, request.reason, grantSecret),
                    ),
                    expectedStatus = 201,
                    parser = agentEnrollmentResponseAdapter::fromJson,
                )
                EnrollmentOutcome(
                    title = "Onboarding package for ${wire.agentName}",
                    detail = "Single use. Expires ${wire.expiresAt}. Hand it to the agent privately.",
                    secret = wire.packageText,
                )
            }
            EnrollmentKind.SERVICE_PRINCIPAL -> {
                val wire = post(
                    session = session,
                    path = "api/mobile/enrollments/service-principals",
                    json = servicePrincipalRequestAdapter.toJson(
                        ServicePrincipalRequestWire(requestId, request.name, request.extra, request.reason, grantSecret),
                    ),
                    expectedStatus = 201,
                    alsoAccept = 200,
                    parser = servicePrincipalResponseAdapter::fromJson,
                )
                EnrollmentOutcome(
                    title = "Service principal ${wire.name}",
                    detail = if (wire.credentialSecret == null) {
                        "The bus had already created this one and will not show its secret again. " +
                            "Rotate it from the console if you need a new secret."
                    } else {
                        "It can create short-lived worker agents named ${wire.agentNamePrefix}-*. " +
                            "This credential is shown once."
                    },
                    secret = wire.credentialSecret,
                )
            }
            EnrollmentKind.DEVICE -> {
                val wire = post(
                    session = session,
                    path = "api/mobile/enrollments/devices",
                    json = deviceEnrollmentRequestAdapter.toJson(
                        DeviceEnrollmentRequestWire(requestId, request.name, request.reason, grantSecret),
                    ),
                    expectedStatus = 201,
                    parser = deviceEnrollmentResponseAdapter::fromJson,
                )
                EnrollmentOutcome(
                    title = "Enrollment for ${wire.deviceLabel}",
                    detail = "Single use. Expires ${wire.expiresAt}. Paste it into the app on the new device.",
                    secret = wire.payload,
                )
            }
        }
    }

    internal fun humanPostRequestJson(
        requestId: String,
        body: String,
        kind: HumanMessageKind,
        replyTo: Long?,
        grantSecret: String,
    ): String = humanPostRequestAdapter.toJson(
        HumanPostRequestWire(
            requestId = requestId,
            body = body,
            kind = kind.wireName,
            replyTo = replyTo,
            grantSecret = grantSecret,
        ),
    )

    private fun <T> post(
        session: StoredMobileSession,
        path: String,
        json: String,
        expectedStatus: Int,
        alsoAccept: Int? = null,
        parser: (String) -> T?,
    ): T {
        val request = Request.Builder()
            .url(session.endpoint.toHttpUrl().newBuilder().addPathSegments(path).build())
            .header("Authorization", "Bearer ${session.credential}")
            .header("Accept", JSON_MEDIA_TYPE)
            .post(json.toRequestBody(JSON_MEDIA_TYPE.toMediaType()))
            .build()
        return clientProvider.client(session.caDer, stream = false).newCall(request).execute().use { response ->
            if (response.code != expectedStatus && response.code != alsoAccept) {
                throw ApiException(errorDetail(response), response.code)
            }
            val raw = response.body?.string() ?: error("Response has no body.")
            parser(raw) ?: error("Response body is empty.")
        }
    }

    private fun errorDetail(response: Response): String {
        val raw = response.body?.string().orEmpty()
        return runCatching { errorAdapter.fromJson(raw)?.detail }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: "Request failed with HTTP ${response.code}."
    }

    private companion object {
        const val JSON_MEDIA_TYPE = "application/json"
        const val HUMAN_POST_PATH = "api/mobile/humans/messages"
    }
}
