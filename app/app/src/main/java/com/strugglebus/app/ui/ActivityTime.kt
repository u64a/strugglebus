package com.strugglebus.app.ui

import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val FALLBACK_TIME_FORMAT = DateTimeFormatter.ofPattern("dd MMM · HH:mm")

fun formatActivityTime(
    createdAt: String,
    now: Instant = Instant.now(),
    zoneId: ZoneId = ZoneId.systemDefault(),
): String {
    val created = runCatching { Instant.parse(createdAt) }.getOrNull() ?: return createdAt
    val elapsed = Duration.between(created, now)
    if (elapsed.isNegative) {
        return if (elapsed.seconds >= -120) {
            "JUST NOW"
        } else {
            created.atZone(zoneId).format(FALLBACK_TIME_FORMAT).uppercase()
        }
    }

    return when {
        elapsed.seconds < 60 -> "JUST NOW"
        elapsed.toMinutes() < 60 -> "${elapsed.toMinutes()}M AGO"
        elapsed.toHours() < 24 -> "${elapsed.toHours()}H AGO"
        elapsed.toDays() < 7 -> "${elapsed.toDays()}D AGO"
        else -> created.atZone(zoneId).format(FALLBACK_TIME_FORMAT).uppercase()
    }
}
