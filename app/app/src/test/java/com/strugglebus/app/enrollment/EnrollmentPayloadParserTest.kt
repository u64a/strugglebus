package com.strugglebus.app.enrollment

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class EnrollmentPayloadParserTest {
    private val now = Instant.parse("2030-01-01T00:00:00Z")
    private val parser = EnrollmentPayloadParser(
        Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
        Clock.fixed(now, ZoneOffset.UTC),
    )

    @Test
    fun parsesValidPayload() {
        val payload = parser.parse(validPayload())

        assertEquals("https://10.0.2.2:8443", payload.endpoint)
        assertEquals("sbme1_token", payload.enrollmentToken)
        assertEquals("operator-phone", payload.deviceLabel)
        assertEquals(now.plusSeconds(300), payload.expiresAt)
    }

    @Test
    fun rejectsUnknownFieldsAndNonHttpsEndpoints() {
        assertThrows(Exception::class.java) {
            parser.parse(validPayload().replace("\"version\":1", "\"version\":1,\"extra\":true"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            parser.parse(validPayload().replace("https://", "http://"))
        }
    }

    @Test
    fun rejectsExpiredOversizedAndUppercaseFingerprintPayloads() {
        assertThrows(IllegalArgumentException::class.java) {
            parser.parse(validPayload("2029-12-31T23:59:59Z"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            parser.parse(validPayload("2030-01-01T00:05:01Z"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            val hash = "ca".sha256()
            parser.parse(validPayload().replace("ca_sha256\":\"$hash", "ca_sha256\":\"${hash.uppercase()}"))
        }
    }

    private fun validPayload(expiresAt: String = "2030-01-01T00:05:00Z") =
        """{"version":1,"base_url":"https://10.0.2.2:8443","ca_der":"Y2E=","ca_sha256":"${"ca".sha256()}","device_label":"operator-phone","enrollment":"sbme1_token","expires_at":"$expiresAt"}"""

    private fun String.sha256(): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(toByteArray())
        .joinToString("") { "%02x".format(it) }
}
