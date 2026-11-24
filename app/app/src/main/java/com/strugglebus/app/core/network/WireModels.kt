package com.strugglebus.app.core.network

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = false)
data class EnrollmentRequestWire(
    @Json(name = "request_id") val requestId: String,
)

@JsonClass(generateAdapter = false)
data class EnrollmentResponseWire(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "device_label") val deviceLabel: String,
    @Json(name = "credential_id") val credentialId: String,
    @Json(name = "credential_secret") val credentialSecret: String,
    val guidance: String,
)

@JsonClass(generateAdapter = false)
data class DeviceWire(
    val id: String,
    val label: String,
    val status: String,
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = false)
data class ErrorWire(val detail: String)

@JsonClass(generateAdapter = false)
data class StatusWire(
    @Json(name = "api_version") val apiVersion: Int,
    @Json(name = "server_time") val serverTime: String,
    val state: String,
)

@JsonClass(generateAdapter = false)
data class SnapshotWire(
    @Json(name = "api_version") val apiVersion: Int,
    @Json(name = "server_time") val serverTime: String,
    @Json(name = "latest_seq") val latestSequence: Long? = null,
    val health: HealthWire? = null,
    val channels: List<ChannelWire>? = null,
    val agents: List<AgentWire>? = null,
    val messages: List<MessageWire>? = null,
)

@JsonClass(generateAdapter = false)
data class HealthWire(val status: String)

@JsonClass(generateAdapter = false)
data class ChannelWire(
    val id: String,
    val name: String,
    val purpose: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "created_by") val createdBy: String?,
)

@JsonClass(generateAdapter = false)
data class AgentWire(
    val id: String,
    val name: String,
    val description: String,
    val host: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "last_seen_at") val lastSeenAt: String?,
    @Json(name = "credential_epoch") val credentialEpoch: Int,
)

@JsonClass(generateAdapter = false)
data class MessageWire(
    @Json(name = "seq") val sequence: Long,
    val id: String,
    val channel: String,
    @Json(name = "agent_id") val agentId: String,
    @Json(name = "agent_name") val agentName: String,
    val body: String,
    val kind: String,
    @Json(name = "reply_to") val replyTo: Long?,
    val metadata: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,
)
