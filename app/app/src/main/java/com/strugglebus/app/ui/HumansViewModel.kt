package com.strugglebus.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strugglebus.app.activity.HumansPoster
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.HumanChannel
import com.strugglebus.app.core.model.HumanMessageKind
import com.strugglebus.app.core.network.ApiException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import java.util.UUID

enum class OutgoingStatus { SENDING, FAILED }

data class ReplyTarget(val sequence: Long, val author: String, val preview: String)

data class OutgoingPost(
    /** Fixed for the life of the post so every retry is idempotent on the server. */
    val requestId: String,
    val body: String,
    val kind: HumanMessageKind,
    val replyTo: ReplyTarget?,
    val status: OutgoingStatus,
    val error: String? = null,
    val retryable: Boolean = true,
)

data class HumansUiState(
    val grantConfigured: Boolean = false,
    val draft: String = "",
    val kind: HumanMessageKind = HumanMessageKind.CHAT,
    val replyTo: ReplyTarget? = null,
    val outbox: List<OutgoingPost> = emptyList(),
    val error: String? = null,
)

class HumansViewModel(
    private val poster: HumansPoster,
) : ViewModel() {
    private val _uiState = MutableStateFlow(HumansUiState(grantConfigured = poster.canPost()))
    val uiState: StateFlow<HumansUiState> = _uiState.asStateFlow()
    private val postedMessages = Channel<BusMessage>(Channel.UNLIMITED)

    /** Accepted posts, so the feed can show them before the live stream delivers them. */
    val posted: Flow<BusMessage> = postedMessages.receiveAsFlow()

    fun refreshGrant() {
        _uiState.update { it.copy(grantConfigured = poster.canPost()) }
    }

    fun updateDraft(text: String) {
        if (text.length > HumanChannel.MAX_BODY_CHARS) return
        _uiState.update { it.copy(draft = text, error = null) }
    }

    fun selectKind(kind: HumanMessageKind) {
        _uiState.update { it.copy(kind = kind) }
    }

    fun replyTo(message: BusMessage) {
        if (message.channel != HumanChannel.NAME) return
        _uiState.update {
            it.copy(
                replyTo = ReplyTarget(
                    sequence = message.sequence,
                    author = message.agentName,
                    preview = MessagePreview.summarise(message.body).preview,
                ),
                kind = if (message.kind == HumanMessageKind.QUESTION.wireName) {
                    HumanMessageKind.ANSWER
                } else {
                    it.kind
                },
            )
        }
    }

    fun cancelReply() {
        _uiState.update { it.copy(replyTo = null) }
    }

    /** [agents] is the current roster, used to turn "@everyone" into the active agents' names. */
    fun send(agents: List<BusAgent> = emptyList(), now: Instant = Instant.now()) {
        val state = _uiState.value
        if (!state.grantConfigured) {
            _uiState.update { it.copy(error = GRANT_MISSING) }
            return
        }
        val body = HumanChannel.normalizeBody(FeedLogic.expandEveryone(state.draft, agents, now)) ?: run {
            _uiState.update {
                it.copy(
                    error = if (state.draft.isBlank()) "Write a message first."
                    else "That message is too long once @everyone is expanded.",
                )
            }
            return
        }
        val post = OutgoingPost(
            requestId = UUID.randomUUID().toString(),
            body = body,
            kind = state.kind,
            replyTo = state.replyTo,
            status = OutgoingStatus.SENDING,
        )
        _uiState.update {
            it.copy(
                draft = "",
                kind = HumanMessageKind.CHAT,
                replyTo = null,
                outbox = it.outbox + post,
                error = null,
            )
        }
        deliver(post)
    }

    fun retry(requestId: String) {
        val state = _uiState.value
        val post = state.outbox.firstOrNull { it.requestId == requestId } ?: return
        if (!post.retryable || post.status != OutgoingStatus.FAILED) return
        if (!state.grantConfigured) {
            _uiState.update { it.copy(error = GRANT_MISSING) }
            return
        }
        updatePost(requestId) { it.copy(status = OutgoingStatus.SENDING, error = null) }
        _uiState.update { it.copy(error = null) }
        deliver(post)
    }

    fun discard(requestId: String) {
        _uiState.update { state ->
            state.copy(outbox = state.outbox.filterNot {
                it.requestId == requestId && it.status == OutgoingStatus.FAILED
            })
        }
    }

    private fun deliver(post: OutgoingPost) {
        val requestId = post.requestId
        viewModelScope.launch {
            try {
                val message = poster.post(
                    requestId = post.requestId,
                    body = post.body,
                    kind = post.kind,
                    replyTo = post.replyTo?.sequence,
                )
                _uiState.update { state ->
                    state.copy(outbox = state.outbox.filterNot { it.requestId == requestId })
                }
                postedMessages.trySend(message)
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Throwable) {
                handleFailure(requestId, failure)
            }
        }
    }

    private fun handleFailure(requestId: String, failure: Throwable) {
        val status = (failure as? ApiException)?.statusCode
        if (status == 401) {
            poster.clearGrant()
            _uiState.update { it.copy(grantConfigured = false) }
        }
        val (detail, retryable) = when (status) {
            401 -> GRANT_REJECTED to true
            409 -> "The server already holds a different post with this ID. Discard it and write it again." to false
            413 -> "The message is too long for the server." to false
            400 -> (failure.message?.takeIf(String::isNotBlank) ?: "The server refused this post.") to false
            else -> (failure.message?.takeIf(String::isNotBlank)
                ?.let { if (it == failure.cause?.toString()) null else it }
                ?: "Unable to reach StruggleBus (${failure::class.java.simpleName}).") to true
        }
        updatePost(requestId) {
            it.copy(status = OutgoingStatus.FAILED, error = detail, retryable = retryable)
        }
    }

    private fun updatePost(requestId: String, transform: (OutgoingPost) -> OutgoingPost) {
        _uiState.update { state ->
            state.copy(outbox = state.outbox.map { if (it.requestId == requestId) transform(it) else it })
        }
    }

    private companion object {
        const val GRANT_MISSING =
            "Set up operator access on the ADMIN page before posting to #humans. " +
                "If you set it up before this update, set it up once more to enable chat."
        const val GRANT_REJECTED =
            "Operator access was revoked or replaced. Set it up again on the ADMIN page, then retry."
    }
}
