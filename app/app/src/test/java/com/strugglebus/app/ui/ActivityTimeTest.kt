package com.strugglebus.app.ui

import java.time.Instant
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Test

class ActivityTimeTest {
    private val now = Instant.parse("2026-09-08T00:00:00Z")

    @Test
    fun `recent activity is immediately recognisable`() {
        assertEquals("JUST NOW", formatActivityTime("2026-09-07T23:59:31Z", now))
        assertEquals("8M AGO", formatActivityTime("2026-09-07T23:52:00Z", now))
        assertEquals("3H AGO", formatActivityTime("2026-09-07T21:00:00Z", now))
        assertEquals("2D AGO", formatActivityTime("2026-09-06T00:00:00Z", now))
    }

    @Test
    fun `small clock skew still reads as current activity`() {
        assertEquals("JUST NOW", formatActivityTime("2026-09-08T00:01:30Z", now))
    }

    @Test
    fun `older activity uses a compact local timestamp`() {
        assertEquals(
            "29 AUG · 00:00",
            formatActivityTime("2026-08-29T00:00:00Z", now, ZoneOffset.UTC),
        )
    }

    @Test
    fun `unknown timestamp remains visible rather than disappearing`() {
        assertEquals("unknown", formatActivityTime("unknown", now))
    }
}
