package com.strugglebus.app.core.network

sealed interface StreamEnd {
    data object RoutineClosure : StreamEnd
    data class RateLimited(val retryAfterMillis: Long) : StreamEnd
    data class Terminal(val event: String, val detail: String) : StreamEnd
    data class Unauthorized(val detail: String) : StreamEnd
    data class RetryableFailure(val detail: String) : StreamEnd
    data class ProtocolFailure(val detail: String) : StreamEnd
}

sealed interface ReconnectDecision {
    data class Retry(val delayMillis: Long, val quiet: Boolean) : ReconnectDecision
    data class Stop(val state: TerminalState, val detail: String) : ReconnectDecision
}

enum class TerminalState {
    FROZEN,
    REVOKED,
    STOPPED,
}

object ReconnectPolicy {
    fun decide(end: StreamEnd, consecutiveFailures: Int): ReconnectDecision = when (end) {
        StreamEnd.RoutineClosure -> ReconnectDecision.Retry(
            delayMillis = ROUTINE_RECONNECT_MILLIS,
            quiet = true,
        )
        is StreamEnd.RateLimited -> ReconnectDecision.Retry(
            delayMillis = end.retryAfterMillis.coerceAtLeast(0L),
            quiet = true,
        )
        is StreamEnd.RetryableFailure -> ReconnectDecision.Retry(
            delayMillis = exponentialDelay(consecutiveFailures),
            quiet = false,
        )
        is StreamEnd.Unauthorized -> ReconnectDecision.Stop(TerminalState.REVOKED, end.detail)
        is StreamEnd.ProtocolFailure -> ReconnectDecision.Stop(TerminalState.STOPPED, end.detail)
        is StreamEnd.Terminal -> when (end.event) {
            "agent_access_frozen" -> ReconnectDecision.Stop(TerminalState.FROZEN, end.detail)
            "credential_inactive" -> ReconnectDecision.Stop(TerminalState.REVOKED, end.detail)
            "agent_access_unavailable" -> ReconnectDecision.Retry(
                delayMillis = exponentialDelay(consecutiveFailures),
                quiet = false,
            )
            else -> ReconnectDecision.Stop(TerminalState.STOPPED, end.detail)
        }
    }

    private fun exponentialDelay(consecutiveFailures: Int): Long {
        val exponent = consecutiveFailures.coerceIn(0, 4)
        return (BASE_FAILURE_DELAY_MILLIS shl exponent).coerceAtMost(MAX_FAILURE_DELAY_MILLIS)
    }

    private const val ROUTINE_RECONNECT_MILLIS = 1_000L
    private const val BASE_FAILURE_DELAY_MILLIS = 2_000L
    private const val MAX_FAILURE_DELAY_MILLIS = 30_000L
}
