package com.strugglebus.app.core.network

import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.strugglebus.app.core.MobileService
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusChannel
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.EnrollmentPayload
import com.strugglebus.app.core.model.MobileDevice
import com.strugglebus.app.core.model.SnapshotResult
import com.strugglebus.app.core.security.StoredMobileSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.job
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.time.Clock
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.lang.reflect.Type

data class EnrollmentResult(
    val device: MobileDevice,
    val credential: String,
)

class MobileApiClient(
    moshi: Moshi,
    private val clock: Clock = Clock.systemUTC(),
    private val clientProvider: PinnedHttpClientProvider = PinnedHttpClientProvider(),
) : MobileService {
    private val enrollmentRequestAdapter = moshi.adapter(EnrollmentRequestWire::class.java)
    private val enrollmentResponseAdapter = moshi.adapter(EnrollmentResponseWire::class.java).failOnUnknown()
    private val statusAdapter = moshi.adapter(StatusWire::class.java).failOnUnknown()
    // The server includes extensible message metadata; the monitor does not need to model it.
    private val messageListAdapter = moshi.adapter<List<MessageWire>>(
        Types.newParameterizedType(List::class.java, MessageWire::class.java),
    )
    private val channelListAdapter = moshi.adapter<List<ChannelWire>>(
        Types.newParameterizedType(List::class.java, ChannelWire::class.java),
    ).failOnUnknown()
    private val agentListAdapter = moshi.adapter<List<AgentWire>>(
        Types.newParameterizedType(List::class.java, AgentWire::class.java),
    ).failOnUnknown()
    private val errorAdapter = moshi.adapter(ErrorWire::class.java).failOnUnknown()
    private val sseProtocol = SseProtocol(moshi)

    override suspend fun redeem(
        payload: EnrollmentPayload,
        requestId: String,
    ): EnrollmentResult = withContext(Dispatchers.IO) {
        val body = enrollmentRequestAdapter.toJson(EnrollmentRequestWire(requestId = requestId))
        val request = Request.Builder()
            .url(url(payload.endpoint, "api/mobile/enrollments/redeem"))
            .header("Authorization", "Bearer ${payload.enrollmentToken}")
            .header("Accept", JSON_MEDIA_TYPE)
            .post(body.toRequestBody(JSON_MEDIA_TYPE.toMediaType()))
            .build()
        val call = clientProvider.client(payload.caDer, stream = false).newCall(request)
        val response = try {
            call.execute()
        } catch (failure: IOException) {
            // The request may have been received and the credential issued before the
            // connection dropped. Enrollment redemption is single-use and the server
            // retains only a one-way hash, so this can never be safely retried.
            throw EnrollmentStrandedException(
                "The connection dropped while enrolling. Enrollment may have succeeded, " +
                    "but the credential was lost. Ask the operator to recover this device; " +
                    "re-enrolling the same name will be refused.",
                failure,
            )
        }
        response.use { completed ->
            when (completed.code) {
                201 -> Unit
                200 -> throw ApiException(
                    "Enrollment redemption returned a replay response, which cannot carry a credential.",
                    200,
                )
                401, 409 -> throw EnrollmentStrandedException(
                    "The enrollment token has already been used. If a previous attempt reached " +
                        "the server, that device exists without a stored credential and the " +
                        "operator must run recovery.",
                    null,
                )
                else -> throw ApiException(errorDetail(completed), completed.code)
            }
            val wire = parseBody(completed, enrollmentResponseAdapter::fromJson)
            require(wire.credentialSecret.isNotBlank()) { "Enrollment returned an empty credential." }
            EnrollmentResult(
                device = MobileDevice(
                    id = wire.deviceId,
                    label = wire.deviceLabel,
                    status = "active",
                    createdAt = "",
                ),
                credential = wire.credentialSecret,
            )
        }
    }

    override suspend fun status(session: StoredMobileSession): BusStatus = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url(session.endpoint, "api/mobile/status"))
            .header("Authorization", "Bearer ${session.credential}")
            .header("Accept", JSON_MEDIA_TYPE)
            .build()
        clientProvider.client(session.caDer, stream = false).newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw ApiException(errorDetail(response), response.code)
            val wire = parseBody(response, statusAdapter::fromJson)
            require(wire.apiVersion == 1) { "Unsupported mobile API version." }
            when (wire.state) {
                "available" -> BusStatus.READY
                "frozen" -> BusStatus.FROZEN
                else -> error("Unsupported bus status.")
            }
        }
    }

    override suspend fun snapshot(
        session: StoredMobileSession,
    ): SnapshotResult = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(
                url(session.endpoint, "api/mobile/snapshot")
                    .newBuilder()
                    .addQueryParameter("limit", SNAPSHOT_LIMIT.toString())
                    .build(),
            )
            .header("Authorization", "Bearer ${session.credential}")
            .header("Accept", JSON_MEDIA_TYPE)
            .build()
        val messages = clientProvider.client(session.caDer, stream = false)
            .newCall(request)
            .execute()
            .use { response ->
                if (!response.isSuccessful) throw ApiException(errorDetail(response), response.code)
                parseBody(response, messageListAdapter::fromJson).map { it.toDomain() }
            }
        require(messages.all { it.sequence >= 0 }) { "Message sequence is negative." }
        require(messages.zipWithNext().all { (left, right) -> left.sequence < right.sequence }) {
            "Snapshot messages are not in ascending sequence order."
        }
        val channels = getJson(session, "api/mobile/channels", channelListAdapter)
        val agents = getJson(session, "api/mobile/agents", agentListAdapter)
        SnapshotResult(
            latestSequence = messages.maxOfOrNull { it.sequence } ?: 0L,
            channels = channels.map { BusChannel(it.id, it.name, it.purpose) },
            agents = agents.map {
                BusAgent(
                    id = it.id,
                    name = it.name,
                    description = it.description,
                    host = it.host,
                    state = "registered",
                    presence = if (it.lastSeenAt == null) "never-seen" else "seen",
                    lastSeenAt = it.lastSeenAt.orEmpty(),
                )
            },
            messages = messages,
        )
    }

    override suspend fun channels(
        session: StoredMobileSession,
    ): List<BusChannel> = withContext(Dispatchers.IO) {
        getJson(session, "api/mobile/channels", channelListAdapter)
            .map { BusChannel(it.id, it.name, it.purpose) }
    }

    override suspend fun agents(
        session: StoredMobileSession,
    ): List<BusAgent> = withContext(Dispatchers.IO) {
        getJson(session, "api/mobile/agents", agentListAdapter).map {
            BusAgent(
                id = it.id,
                name = it.name,
                description = it.description,
                host = it.host,
                state = "registered",
                presence = if (it.lastSeenAt == null) "never-seen" else "seen",
                lastSeenAt = it.lastSeenAt.orEmpty(),
            )
        }
    }

    override suspend fun history(
        session: StoredMobileSession,
        channel: String?,
        agent: String?,
        before: Long?,
        limit: Int,
    ): List<BusMessage> = withContext(Dispatchers.IO) {
        require(!channel.isNullOrBlank() || !agent.isNullOrBlank()) { "History needs a channel or an agent." }
        val historyUrl = url(session.endpoint, "api/mobile/snapshot")
            .newBuilder()
            .addQueryParameter("limit", limit.toString())
            .apply {
                if (!channel.isNullOrBlank()) addQueryParameter("channel", channel)
                if (!agent.isNullOrBlank()) addQueryParameter("agent", agent)
                if (before != null) addQueryParameter("before", before.toString())
            }
            .build()
        getJson(session, historyUrl, messageListAdapter).map { it.toDomain() }.sortedBy(BusMessage::sequence)
    }

    override suspend fun search(
        session: StoredMobileSession,
        query: String,
        limit: Int,
    ): List<BusMessage> = withContext(Dispatchers.IO) {
        val searchUrl = url(session.endpoint, "api/mobile/search")
            .newBuilder()
            .addQueryParameter("query", query)
            .addQueryParameter("limit", limit.toString())
            .build()
        getJson(session, searchUrl, messageListAdapter).map { it.toDomain() }
    }

    override suspend fun stream(
        session: StoredMobileSession,
        cursor: Long,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd = withContext(Dispatchers.IO) {
        val streamUrl = url(session.endpoint, "api/mobile/stream")
            .newBuilder()
            .addQueryParameter("since", cursor.toString())
            .apply {
                if (channel != null) addQueryParameter("channel", channel)
            }
            .build()
        val request = Request.Builder()
            .url(streamUrl)
            .header("Accept", "text/event-stream")
            .header("Authorization", "Bearer ${session.credential}")
            .header("Last-Event-ID", cursor.toString())
            .build()
        val call = clientProvider.client(session.caDer, stream = true).newCall(request)
        val cancellation = coroutineContext.job.invokeOnCompletion { call.cancel() }
        try {
            call.execute().use { response ->
                when {
                    response.code == 401 -> StreamEnd.Unauthorized(errorDetail(response))
                    response.code == 429 -> StreamEnd.RateLimited(
                        retryAfterMillis(response.header("Retry-After"), clock),
                    )
                    !response.isSuccessful -> StreamEnd.RetryableFailure(errorDetail(response))
                    !response.header("Content-Type").orEmpty().startsWith("text/event-stream") ->
                        StreamEnd.ProtocolFailure("Stream response is not text/event-stream.")
                    else -> readStream(response, channel, onOpen, onMessage)
                }
            }
        } catch (failure: ProtocolException) {
            StreamEnd.ProtocolFailure(failure.message ?: "Malformed SSE stream.")
        } catch (failure: IOException) {
            coroutineContext.ensureActive()
            StreamEnd.RetryableFailure("Connection interrupted.")
        } finally {
            cancellation.dispose()
        }
    }

    private fun readStream(
        response: Response,
        channel: String?,
        onOpen: () -> Unit,
        onMessage: (BusMessage) -> Unit,
    ): StreamEnd {
        val body = response.body ?: return StreamEnd.ProtocolFailure("Stream response has no body.")
        var terminal: StreamEnd.Terminal? = null
        val parser = SseParser { frame ->
            when (val event = sseProtocol.decode(frame, channel)) {
                is DecodedSseEvent.Message -> onMessage(event.message)
                is DecodedSseEvent.Terminal -> terminal = StreamEnd.Terminal(event.name, event.detail)
            }
        }
        onOpen()
        val input = body.byteStream()
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        while (terminal == null) {
            val count = input.read(buffer)
            if (count < 0) break
            parser.feed(buffer, count)
        }
        parser.finish()
        return terminal ?: StreamEnd.RoutineClosure
    }

    private fun <T> getJson(
        session: StoredMobileSession,
        path: String,
        adapter: JsonAdapter<T>,
    ): T = getJson(session, url(session.endpoint, path), adapter)

    private fun <T> getJson(
        session: StoredMobileSession,
        target: okhttp3.HttpUrl,
        adapter: JsonAdapter<T>,
    ): T {
        val request = Request.Builder()
            .url(target)
            .header("Authorization", "Bearer ${session.credential}")
            .header("Accept", JSON_MEDIA_TYPE)
            .build()
        return clientProvider.client(session.caDer, stream = false).newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw ApiException(errorDetail(response), response.code)
            parseBody(response, adapter::fromJson)
        }
    }

    private fun url(endpoint: String, path: String) =
        endpoint.toHttpUrl().newBuilder().addPathSegments(path).build()

    private fun errorDetail(response: Response): String {
        val raw = response.body?.string().orEmpty()
        return runCatching { errorAdapter.fromJson(raw)?.detail }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: "Request failed with HTTP ${response.code}."
    }

    private fun <T> parseBody(response: Response, parser: (String) -> T?): T {
        val raw = response.body?.string() ?: error("Response has no body.")
        return parser(raw) ?: error("Response body is empty.")
    }

    private fun MessageWire.toDomain() = BusMessage(
        sequence = sequence,
        id = id,
        channel = channel,
        agentId = agentId,
        agentName = agentName,
        body = body,
        kind = kind,
        replyTo = replyTo,
        createdAt = createdAt,
    )

    companion object {
        const val SNAPSHOT_LIMIT = 100
        const val JSON_MEDIA_TYPE = "application/json"
        const val STREAM_BUFFER_BYTES = 4_096

        fun retryAfterMillis(value: String?, clock: Clock): Long {
            if (value.isNullOrBlank()) return 1_000L
            value.toLongOrNull()?.let { seconds ->
                return seconds.coerceAtLeast(0L).coerceAtMost(3_600L) * 1_000L
            }
            return runCatching {
                val retryAt = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME)
                    .toInstant()
                (retryAt.toEpochMilli() - clock.millis()).coerceAtLeast(0L)
            }.getOrDefault(1_000L)
        }
    }
}

class ApiException(message: String, val statusCode: Int) : IllegalStateException(message)

/**
 * Enrollment could not be completed and must not be retried. The one-time token may already
 * have been consumed, so only the operator's local recovery path can restore this device.
 */
class EnrollmentStrandedException(
    message: String,
    cause: Throwable?,
) : IllegalStateException(message, cause)
