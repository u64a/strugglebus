package com.strugglebus.app.core.network

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.strugglebus.app.core.model.HumanMessageKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class MobileWriteApiClientTest {
    private val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
    private val client = MobileWriteApiClient(moshi)

    @Test
    fun humanPostUsesServerFieldNames() {
        val json = client.humanPostRequestJson(
            requestId = "0f0e0d0c-0b0a-4090-8070-605040302010",
            body = "Can you rebase?",
            kind = HumanMessageKind.ANSWER,
            replyTo = 42,
            grantSecret = "grant",
        )

        @Suppress("UNCHECKED_CAST")
        val fields = moshi.adapter(Map::class.java).fromJson(json) as Map<String, Any?>
        assertEquals(
            setOf("request_id", "body", "kind", "reply_to", "grant_secret"),
            fields.keys,
        )
        assertEquals("answer", fields["kind"])
        assertEquals(42.0, fields["reply_to"])
    }

    @Test
    fun humanPostOmitsMissingReplyTarget() {
        val json = client.humanPostRequestJson(
            requestId = "0f0e0d0c-0b0a-4090-8070-605040302010",
            body = "hello",
            kind = HumanMessageKind.CHAT,
            replyTo = null,
            grantSecret = "grant",
        )

        assertFalse(json.contains("reply_to"))
    }
}
