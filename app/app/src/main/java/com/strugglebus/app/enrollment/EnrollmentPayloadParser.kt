package com.strugglebus.app.enrollment

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.strugglebus.app.core.EnrollmentParser
import com.strugglebus.app.core.model.EnrollmentPayload
import java.net.URI
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64

class EnrollmentPayloadParser(
    moshi: Moshi,
    private val clock: Clock = Clock.systemUTC(),
) : EnrollmentParser {
    private val adapter = moshi.adapter(EnrollmentPayloadWire::class.java).failOnUnknown()

    override fun parse(rawPayload: String): EnrollmentPayload {
        require(rawPayload.isNotBlank()) { "Enrollment payload is required." }
        val wire = adapter.fromJson(rawPayload)
            ?: throw IllegalArgumentException("Enrollment payload is empty.")
        require(wire.version == SUPPORTED_VERSION) { "Unsupported enrollment payload version." }
        require(
            wire.enrollmentToken.startsWith("sbme1_") &&
                wire.enrollmentToken == wire.enrollmentToken.trim(),
        ) { "Enrollment token is malformed." }
        require(wire.deviceLabel.isNotBlank() && wire.deviceLabel == wire.deviceLabel.trim()) {
            "Device label is malformed."
        }
        require(CA_FINGERPRINT.matches(wire.caSha256)) {
            "CA SHA-256 must be 64 lowercase hexadecimal characters."
        }
        val caDer = runCatching { Base64.getDecoder().decode(wire.caDer) }
            .getOrElse { throw IllegalArgumentException("CA DER is not valid base64.", it) }
        require(caDer.isNotEmpty()) { "CA DER is empty." }
        val actualSha = java.security.MessageDigest.getInstance("SHA-256").digest(caDer)
            .joinToString("") { "%02x".format(it) }
        require(actualSha == wire.caSha256) { "CA DER does not match ca_sha256." }

        val endpoint = validateEndpoint(wire.endpoint)
        val expiresAt = runCatching { Instant.parse(wire.expiresAt) }
            .getOrElse { throw IllegalArgumentException("Enrollment expiry is not valid UTC RFC 3339.", it) }
        val remaining = Duration.between(clock.instant(), expiresAt)
        require(!remaining.isNegative && !remaining.isZero) { "Enrollment payload has expired." }
        require(remaining <= MAX_TTL) { "Enrollment expiry exceeds the five-minute monitor limit." }

        return EnrollmentPayload(
            endpoint = endpoint,
            enrollmentToken = wire.enrollmentToken,
            caDer = caDer,
            caSha256 = wire.caSha256,
            deviceLabel = wire.deviceLabel,
            expiresAt = expiresAt,
        )
    }

    private fun validateEndpoint(rawEndpoint: String): String {
        require(rawEndpoint == rawEndpoint.trim()) { "Endpoint is malformed." }
        val uri = runCatching { URI(rawEndpoint) }
            .getOrElse { throw IllegalArgumentException("Endpoint is not a valid HTTPS URL.", it) }
        require(uri.scheme.equals("https", ignoreCase = true)) { "Endpoint must use HTTPS." }
        require(!uri.host.isNullOrBlank() && uri.userInfo == null) { "Endpoint authority is invalid." }
        require(uri.query == null && uri.fragment == null) { "Endpoint must not contain a query or fragment." }
        require(uri.path.isNullOrEmpty() || uri.path == "/") { "Endpoint must not contain a path." }
        return rawEndpoint.removeSuffix("/")
    }

    private companion object {
        const val SUPPORTED_VERSION = 1
        val MAX_TTL: Duration = Duration.ofMinutes(5)
        val CA_FINGERPRINT = Regex("[0-9a-f]{64}")
    }
}

@JsonClass(generateAdapter = false)
private data class EnrollmentPayloadWire(
    val version: Int,
    @Json(name = "base_url") val endpoint: String,
    @Json(name = "ca_der") val caDer: String,
    @Json(name = "ca_sha256") val caSha256: String,
    @Json(name = "device_label") val deviceLabel: String,
    val enrollment: String,
    @Json(name = "expires_at") val expiresAt: String,
) {
    val enrollmentToken: String get() = enrollment
}
