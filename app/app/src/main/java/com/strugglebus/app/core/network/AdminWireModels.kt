package com.strugglebus.app.core.network

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = false)
data class GrantRequestWire(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "operator_password") val operatorPassword: String,
    val reason: String,
)

@JsonClass(generateAdapter = false)
data class GrantResponseWire(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "grant_secret") val grantSecret: String,
    val guidance: String,
)

@JsonClass(generateAdapter = false)
data class ConfirmationRequestWire(
    @Json(name = "request_id") val requestId: String,
    val action: String,
    @Json(name = "target_id") val targetId: String,
)

@JsonClass(generateAdapter = false)
data class ConfirmationResponseWire(
    @Json(name = "confirmation_id") val confirmationId: String,
    val action: String,
    @Json(name = "target_kind") val targetKind: String,
    @Json(name = "target_id") val targetId: String,
    @Json(name = "target_label") val targetLabel: String,
    @Json(name = "expires_at") val expiresAt: String,
    val effect: String,
)

@JsonClass(generateAdapter = false)
data class ActionRequestWire(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "confirmation_id") val confirmationId: String,
    val action: String,
    @Json(name = "target_id") val targetId: String,
    @Json(name = "grant_secret") val grantSecret: String,
    val reason: String,
)

@JsonClass(generateAdapter = false)
data class ActionResponseWire(
    val action: String,
    @Json(name = "target_id") val targetId: String,
    @Json(name = "target_label") val targetLabel: String,
    val applied: Boolean,
    val detail: String,
)

@JsonClass(generateAdapter = false)
data class HumanPostRequestWire(
    @Json(name = "request_id") val requestId: String,
    val body: String,
    val kind: String,
    @Json(name = "reply_to") val replyTo: Long?,
    @Json(name = "grant_secret") val grantSecret: String,
)

@JsonClass(generateAdapter = false)
data class AgentEnrollmentRequestWire(
    @Json(name = "request_id") val requestId: String,
    val name: String,
    val description: String,
    val reason: String,
    @Json(name = "grant_secret") val grantSecret: String,
)

@JsonClass(generateAdapter = false)
data class AgentEnrollmentResponseWire(
    @Json(name = "enrollment_id") val enrollmentId: String,
    @Json(name = "agent_name") val agentName: String,
    @Json(name = "expires_at") val expiresAt: String,
    @Json(name = "package") val packageText: String,
)

@JsonClass(generateAdapter = false)
data class ServicePrincipalRequestWire(
    @Json(name = "request_id") val requestId: String,
    val name: String,
    @Json(name = "agent_name_prefix") val agentNamePrefix: String,
    val reason: String,
    @Json(name = "grant_secret") val grantSecret: String,
)

@JsonClass(generateAdapter = false)
data class ServicePrincipalResponseWire(
    @Json(name = "service_principal_id") val servicePrincipalId: String,
    val name: String,
    @Json(name = "agent_name_prefix") val agentNamePrefix: String,
    @Json(name = "secret_issued") val secretIssued: Boolean,
    @Json(name = "credential_secret") val credentialSecret: String?,
)

@JsonClass(generateAdapter = false)
data class DeviceEnrollmentRequestWire(
    @Json(name = "request_id") val requestId: String,
    val label: String,
    val reason: String,
    @Json(name = "grant_secret") val grantSecret: String,
)

@JsonClass(generateAdapter = false)
data class DeviceEnrollmentResponseWire(
    @Json(name = "device_label") val deviceLabel: String,
    @Json(name = "expires_at") val expiresAt: String,
    val payload: String,
)
