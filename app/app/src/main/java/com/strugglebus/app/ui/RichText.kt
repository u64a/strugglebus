package com.strugglebus.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.strugglebus.app.ui.theme.LocalAppColors

/** Message text with @mentions emphasised and search hits marked, in the current palette. */
@Composable
fun richText(text: String, highlight: String? = null): AnnotatedString {
    val colors = LocalAppColors.current
    return remember(text, highlight, colors) {
        buildAnnotatedString {
            for (segment in FeedLogic.segment(text, highlight)) {
                when (segment.kind) {
                    SegmentKind.PLAIN -> append(segment.text)
                    SegmentKind.MENTION -> withStyle(
                        SpanStyle(color = colors.accentText, fontWeight = FontWeight.SemiBold),
                    ) { append(segment.text) }
                    SegmentKind.HIT -> withStyle(
                        SpanStyle(color = colors.onAccent, background = colors.accent),
                    ) { append(segment.text) }
                }
            }
        }
    }
}

/** Presence is always paired with a text label elsewhere; the dot is a quick visual cue only. */
@Composable
fun PresenceDot(presence: AgentPresence?, modifier: Modifier = Modifier) {
    val colors = LocalAppColors.current
    val color = when (presence) {
        AgentPresence.ACTIVE -> colors.ok
        AgentPresence.IDLE -> colors.warn
        else -> colors.line
    }
    Box(modifier.size(8.dp).background(color, CircleShape))
}
