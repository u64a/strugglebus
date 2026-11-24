package com.strugglebus.app.core.model

import java.time.Instant

data class EnrollmentPayload(
    val endpoint: String,
    val enrollmentToken: String,
    val caDer: ByteArray,
    val caSha256: String,
    val deviceLabel: String,
    val expiresAt: Instant,
)

data class MobileDevice(
    val id: String,
    val label: String,
    val status: String,
    val createdAt: String,
)

data class BusChannel(
    val id: String,
    val name: String,
    val purpose: String,
)

data class BusAgent(
    val id: String,
    val name: String,
    val description: String,
    val host: String,
    val state: String,
    val presence: String,
    val lastSeenAt: String,
)

data class BusMessage(
    val sequence: Long,
    val id: String,
    val channel: String,
    val agentId: String,
    val agentName: String,
    val body: String,
    val kind: String,
    val replyTo: Long?,
    val createdAt: String,
)

enum class BusStatus {
    READY,
    FROZEN,
}

data class SnapshotResult(
    val latestSequence: Long,
    val channels: List<BusChannel>,
    val agents: List<BusAgent>,
    val messages: List<BusMessage>,
)
