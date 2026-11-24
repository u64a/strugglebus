package com.strugglebus.app.core.network

import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Test

class PinnedHttpClientProviderTest {
    @Test
    fun reusesClientsForTheSameCaAndSeparatesTimeoutProfiles() {
        var builds = 0
        val provider = PinnedHttpClientProvider {
            builds += 1
            OkHttpClient()
        }
        val ca = byteArrayOf(1, 2, 3)

        val regular = provider.client(ca, stream = false)
        val stream = provider.client(ca, stream = true)

        assertSame(regular, provider.client(ca.copyOf(), stream = false))
        assertSame(stream, provider.client(ca.copyOf(), stream = true))
        assertNotSame(regular, stream)
        assertEquals(10_000, regular.readTimeoutMillis)
        assertEquals(0, stream.readTimeoutMillis)
        assertEquals(1, builds)
    }

    @Test
    fun changingTheCaReplacesTheCachedClients() {
        var builds = 0
        val provider = PinnedHttpClientProvider {
            builds += 1
            OkHttpClient()
        }

        val first = provider.client(byteArrayOf(1), stream = false)
        val second = provider.client(byteArrayOf(2), stream = false)

        assertNotSame(first, second)
        assertEquals(2, builds)
    }
}
