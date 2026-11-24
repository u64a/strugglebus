package com.strugglebus.app.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.HumanChannel
import com.strugglebus.app.core.model.HumanMessageKind
import com.strugglebus.app.ui.theme.RetroAmber
import com.strugglebus.app.ui.theme.RetroCream
import com.strugglebus.app.ui.theme.RetroRed
import com.strugglebus.app.ui.theme.RetroTeal
import com.strugglebus.app.ui.theme.RetroTealMuted
import java.time.Instant

@Composable
fun HumansScreen(
    viewModel: HumansViewModel,
    messages: List<BusMessage>,
    agents: List<BusAgent> = emptyList(),
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val conversation = remember(messages) { HumanChannel.conversation(messages).asReversed() }
    val waiting = remember(messages) { FeedLogic.waitingOnOperator(messages) }

    LaunchedEffect(Unit) { viewModel.refreshGrant() }

    Column(modifier = modifier.fillMaxSize().imePadding()) {
        if (!state.grantConfigured) {
            HumansNotice(
                "Read-only. Set up operator access on the ADMIN page to post to #humans " +
                    "(once more if you set it up before chat was added).",
                error = false,
            )
        }
        state.error?.let { HumansNotice(it, error = true) }
        if (waiting.isNotEmpty()) {
            WaitingStrip(waiting = waiting, onReply = viewModel::replyTo)
        }
        LazyColumn(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            reverseLayout = true,
            contentPadding = PaddingValues(vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(state.outbox.asReversed(), key = { "out-${it.requestId}" }) { post ->
                OutgoingBubble(
                    post = post,
                    onRetry = { viewModel.retry(post.requestId) },
                    onDiscard = { viewModel.discard(post.requestId) },
                )
            }
            items(conversation, key = { "msg-${it.sequence}" }) { message ->
                ConversationBubble(message = message, onReply = { viewModel.replyTo(message) })
            }
            if (conversation.isEmpty() && state.outbox.isEmpty()) {
                item {
                    Text(
                        "NO #HUMANS CONVERSATION YET",
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.labelMedium,
                        color = RetroTealMuted,
                    )
                }
            }
        }
        Composer(
            state = state,
            agents = agents,
            onDraftChange = viewModel::updateDraft,
            onKindSelected = viewModel::selectKind,
            onCancelReply = viewModel::cancelReply,
            onSend = { viewModel.send(agents) },
        )
    }
}

/** Agent questions nobody has answered yet, so they are not lost in a busy channel. */
@Composable
private fun WaitingStrip(waiting: List<BusMessage>, onReply: (BusMessage) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp)
            .border(1.dp, MaterialTheme.colorScheme.primary, MaterialTheme.shapes.medium)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            "WAITING ON YOU (${waiting.size})",
            style = MaterialTheme.typography.labelMedium,
            color = RetroAmber,
        )
        waiting.take(3).forEach { question ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "${question.agentName}: ${MessagePreview.summarise(question.body).preview}",
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroCream,
                )
                BubbleAction("ANSWER", RetroAmber) { onReply(question) }
            }
        }
        if (waiting.size > 3) {
            Text(
                "and ${waiting.size - 3} more",
                style = MaterialTheme.typography.bodySmall,
                color = RetroTealMuted,
            )
        }
    }
}

@Composable
private fun ConversationBubble(message: BusMessage, onReply: () -> Unit) {
    val mine = HumanChannel.isHumanPost(message)
    val question = message.kind == HumanMessageKind.QUESTION.wireName && !mine
    Bubble(
        mine = mine,
        borderColor = if (question) RetroAmber else MaterialTheme.colorScheme.outlineVariant,
        author = if (mine) "YOU" else message.agentName,
        tag = message.kind.uppercase(),
        tagColor = if (question) RetroAmber else RetroTeal,
        replyTo = message.replyTo,
        body = message.body,
        footer = formatActivityTime(message.createdAt),
        actions = { BubbleAction("REPLY", RetroAmber, onReply) },
    )
}

@Composable
private fun OutgoingBubble(post: OutgoingPost, onRetry: () -> Unit, onDiscard: () -> Unit) {
    val failed = post.status == OutgoingStatus.FAILED
    Bubble(
        mine = true,
        borderColor = if (failed) RetroRed else RetroTealMuted,
        author = "YOU",
        tag = post.kind.wireName.uppercase(),
        tagColor = RetroTeal,
        replyTo = post.replyTo?.sequence,
        body = post.body,
        footer = when (post.status) {
            OutgoingStatus.SENDING -> "SENDING"
            OutgoingStatus.FAILED -> "NOT SENT — ${post.error ?: "unknown error"}"
        },
        footerColor = if (failed) RetroRed else RetroTealMuted,
        actions = {
            if (failed) {
                if (post.retryable) BubbleAction("RETRY", RetroAmber, onRetry)
                BubbleAction("DISCARD", RetroTealMuted, onDiscard)
            }
        },
    )
}

@Composable
private fun Bubble(
    mine: Boolean,
    borderColor: Color,
    author: String,
    tag: String,
    tagColor: Color,
    replyTo: Long?,
    body: String,
    footer: String,
    footerColor: Color = RetroTealMuted,
    actions: @Composable () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            color = MaterialTheme.colorScheme.surface,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier
                .widthIn(max = 320.dp)
                .border(1.dp, borderColor, MaterialTheme.shapes.medium),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                verticalArrangement = Arrangement.spacedBy(5.dp),
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(author, style = MaterialTheme.typography.labelMedium, color = if (mine) RetroAmber else RetroTeal)
                    Text(tag, style = MaterialTheme.typography.bodySmall, color = tagColor)
                }
                replyTo?.let {
                    Text("↪ REPLY TO SEQ $it", style = MaterialTheme.typography.bodySmall, color = RetroTealMuted)
                }
                Text(richText(body), style = MaterialTheme.typography.bodyMedium, color = RetroCream)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        footer,
                        modifier = Modifier.weight(1f, fill = false),
                        style = MaterialTheme.typography.bodySmall,
                        color = footerColor,
                    )
                    actions()
                }
            }
        }
    }
}

@Composable
private fun BubbleAction(label: String, color: Color, onClick: () -> Unit) {
    TextButton(onClick = onClick, contentPadding = PaddingValues(horizontal = 8.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = color)
    }
}

@Composable
private fun Composer(
    state: HumansUiState,
    agents: List<BusAgent>,
    onDraftChange: (String) -> Unit,
    onKindSelected: (HumanMessageKind) -> Unit,
    onCancelReply: () -> Unit,
    onSend: () -> Unit,
) {
    // The caret position lives here; the view model owns the text.
    var field by remember { mutableStateOf(TextFieldValue(state.draft)) }
    if (field.text != state.draft) {
        field = TextFieldValue(state.draft, TextRange(state.draft.length))
    }
    val token = remember(field) {
        if (field.selection.collapsed) FeedLogic.activeMentionToken(field.text, field.selection.start) else null
    }
    val options = remember(token, agents) {
        token?.let { FeedLogic.mentionOptions(agents, it.prefix, Instant.now()) }.orEmpty()
    }

    Surface(color = MaterialTheme.colorScheme.surface) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (token != null && options.isNotEmpty()) {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(options, key = { it.insert }) { option ->
                        Row(
                            modifier = Modifier
                                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.small)
                                .clickable(onClickLabel = "Mention ${option.insert}") {
                                    val (text, caret) = FeedLogic.applyMention(
                                        field.text, field.selection.start, token, option.insert,
                                    )
                                    if (text.length <= HumanChannel.MAX_BODY_CHARS) {
                                        field = TextFieldValue(text, TextRange(caret))
                                        onDraftChange(text)
                                    }
                                }
                                .padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            if (!option.isGroup) PresenceDot(option.presence)
                            Column {
                                Text(
                                    "@${option.insert}",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = RetroAmber,
                                )
                                Text(option.meta, style = MaterialTheme.typography.bodySmall, color = RetroTealMuted)
                            }
                        }
                    }
                }
            }
            state.replyTo?.let { target ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "↪ ${target.author} (SEQ ${target.sequence}): ${target.preview}",
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        style = MaterialTheme.typography.bodySmall,
                        color = RetroTealMuted,
                    )
                    BubbleAction("CANCEL", RetroTealMuted, onCancelReply)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                HumanMessageKind.entries.forEach { kind ->
                    FilterChip(
                        selected = state.kind == kind,
                        onClick = { onKindSelected(kind) },
                        label = { Text(kind.wireName.uppercase(), style = MaterialTheme.typography.labelMedium) },
                        enabled = state.grantConfigured,
                        colors = FilterChipDefaults.filterChipColors(
                            labelColor = RetroTeal,
                            selectedContainerColor = MaterialTheme.colorScheme.primary,
                            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                    )
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = field,
                    onValueChange = { next ->
                        if (next.text.length <= HumanChannel.MAX_BODY_CHARS) {
                            field = next
                            if (next.text != state.draft) onDraftChange(next.text)
                        }
                    },
                    modifier = Modifier.weight(1f),
                    enabled = state.grantConfigured,
                    placeholder = { Text("Message #humans, @ to mention") },
                    maxLines = 5,
                )
                Button(
                    onClick = onSend,
                    enabled = state.grantConfigured && state.draft.isNotBlank(),
                ) { Text("SEND") }
            }
        }
    }
}

@Composable
private fun HumansNotice(message: String, error: Boolean) {
    val color = if (error) RetroRed else RetroAmber
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp)
            .border(1.dp, color, MaterialTheme.shapes.medium),
    ) {
        Text(message, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodyMedium, color = color)
    }
}
