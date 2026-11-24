package com.strugglebus.app.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class ReconnectPolicyTest {
    @Test
    fun routineClosureReconnectsQuietly() {
        val decision = ReconnectPolicy.decide(StreamEnd.RoutineClosure, 4) as ReconnectDecision.Retry

        assertTrue(decision.quiet)
        assertEquals(1_000L, decision.delayMillis)
    }

    @Test
    fun rateLimitHonorsRetryAfter() {
        val decision = ReconnectPolicy.decide(
            StreamEnd.RateLimited(7_000L),
            0,
        ) as ReconnectDecision.Retry

        assertEquals(7_000L, decision.delayMillis)
        assertTrue(decision.quiet)
    }

    @Test
    fun networkFailuresBackOffAndTerminalStatesStop() {
        val retry = ReconnectPolicy.decide(
            StreamEnd.RetryableFailure("offline"),
            3,
        ) as ReconnectDecision.Retry
        assertEquals(16_000L, retry.delayMillis)
        assertFalse(retry.quiet)

        val frozen = ReconnectPolicy.decide(
            StreamEnd.Terminal("agent_access_frozen", "frozen"),
            0,
        ) as ReconnectDecision.Stop
        assertEquals(TerminalState.FROZEN, frozen.state)

        val revoked = ReconnectPolicy.decide(
            StreamEnd.Terminal("credential_inactive", "inactive"),
            0,
        ) as ReconnectDecision.Stop
        assertEquals(TerminalState.REVOKED, revoked.state)
    }

    @Test
    fun parsesRetryAfterSecondsAndHttpDate() {
        val clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC)

        assertEquals(7_000L, MobileApiClient.retryAfterMillis("7", clock))
        assertEquals(
            5_000L,
            MobileApiClient.retryAfterMillis("Tue, 1 Jan 2030 00:00:05 GMT", clock),
        )
    }
}
