package com.strugglebus.app.ui

/**
 * A collapsed one-line summary of a message body.
 *
 * Bus messages are frequently multi-paragraph and several thousand characters long, so the
 * activity list shows a flattened preview and defers the full body to an expanded card.
 */
data class MessageSummary(
    val preview: String,
    val expandable: Boolean,
    val characterCount: Int,
)

object MessagePreview {
    const val PREVIEW_LIMIT = 100

    /** Minimum share of the limit to keep when cutting back to a word boundary. */
    private const val MIN_WORD_BOUNDARY_RATIO = 0.6

    fun summarise(body: String, limit: Int = PREVIEW_LIMIT): MessageSummary {
        require(limit > 0) { "Preview limit must be positive." }
        val flattened = body.replace(WHITESPACE_RUN, " ").trim()
        // Flattening alone justifies expansion: a short multi-line body still loses its
        // original formatting in the collapsed card.
        val flattenedAway = flattened != body.trim() || body.trim() != body

        if (flattened.length <= limit) {
            return MessageSummary(
                preview = flattened,
                expandable = flattenedAway,
                characterCount = body.length,
            )
        }

        val hardCut = flattened.take(limit)
        val lastSpace = hardCut.lastIndexOf(' ')
        val cut = if (lastSpace >= limit * MIN_WORD_BOUNDARY_RATIO) {
            hardCut.take(lastSpace)
        } else {
            hardCut
        }
        return MessageSummary(
            preview = cut.trimEnd().trimEnd(*TRAILING_PUNCTUATION) + "…",
            expandable = true,
            characterCount = body.length,
        )
    }

    private val WHITESPACE_RUN = Regex("\\s+")
    private val TRAILING_PUNCTUATION = charArrayOf(',', ';', ':', '-', '–', '—')
}
