package com.strugglebus.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagePreviewTest {

    @Test
    fun `short single line body is not expandable`() {
        val summary = MessagePreview.summarise("Snapshot loaded.")

        assertEquals("Snapshot loaded.", summary.preview)
        assertFalse(summary.expandable)
        assertEquals(16, summary.characterCount)
    }

    @Test
    fun `long body is truncated at a word boundary with an ellipsis`() {
        val body = "seq 95 confirms revalidation happens twice per iteration, " +
            "once before the batch fetch and again immediately before each message is serialised."
        val summary = MessagePreview.summarise(body)

        assertTrue(summary.expandable)
        assertTrue(summary.preview.endsWith("…"))
        // The ellipsis is the only character allowed past the limit.
        assertTrue(summary.preview.length <= MessagePreview.PREVIEW_LIMIT + 1)
        assertFalse(summary.preview.trimEnd('…').endsWith(" "))
        assertTrue(body.startsWith(summary.preview.trimEnd('…')))
        assertEquals(body.length, summary.characterCount)
    }

    @Test
    fun `multi line body is flattened so the collapsed card is not mostly blank`() {
        val summary = MessagePreview.summarise("Design review\n\n- item one\n- item two")

        assertEquals("Design review - item one - item two", summary.preview)
        assertTrue("Flattening loses formatting, so expansion must stay available", summary.expandable)
    }

    @Test
    fun `body without a usable word boundary is cut hard at the limit`() {
        val body = "x".repeat(400)
        val summary = MessagePreview.summarise(body)

        assertEquals("x".repeat(MessagePreview.PREVIEW_LIMIT) + "…", summary.preview)
        assertEquals(400, summary.characterCount)
    }

    @Test
    fun `character count reports the original body length not the flattened preview`() {
        val body = "a".repeat(50) + "\n\n\n\n" + "b".repeat(50)
        val summary = MessagePreview.summarise(body)

        assertEquals(104, summary.characterCount)
        assertTrue(summary.expandable)
    }

    @Test
    fun `empty body is not expandable`() {
        val summary = MessagePreview.summarise("")

        assertEquals("", summary.preview)
        assertFalse(summary.expandable)
    }
}
