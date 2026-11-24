package com.strugglebus.app.core.network

import okhttp3.OkHttpClient
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class PinnedHttpClientProvider(
    private val clientFactory: (ByteArray) -> OkHttpClient = ::buildPinnedClient,
) {
    @Volatile
    private var cached: CachedClients? = null

    fun client(caDer: ByteArray, stream: Boolean): OkHttpClient {
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(caDer)
        cached?.takeIf { it.fingerprint.contentEquals(fingerprint) }?.let {
            return if (stream) it.stream else it.regular
        }
        return synchronized(this) {
            val current = cached
            if (current != null && current.fingerprint.contentEquals(fingerprint)) {
                if (stream) current.stream else current.regular
            } else {
                val regular = clientFactory(caDer)
                val replacement = CachedClients(
                    fingerprint = fingerprint,
                    regular = regular,
                    stream = regular.newBuilder().readTimeout(0, TimeUnit.MILLISECONDS).build(),
                )
                cached = replacement
                if (stream) replacement.stream else replacement.regular
            }
        }
    }

    private data class CachedClients(
        val fingerprint: ByteArray,
        val regular: OkHttpClient,
        val stream: OkHttpClient,
    )

    private companion object {
        fun buildPinnedClient(caDer: ByteArray): OkHttpClient {
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(caDer.inputStream()) as X509Certificate
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("mobile-ca", certificate)
            }
            val trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm(),
            ).apply { init(keyStore) }
            val trustManager = trustManagerFactory.trustManagers
                .filterIsInstance<X509TrustManager>()
                .single()
            val sslContext = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustManager), null)
            }
            return OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManager)
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(20, TimeUnit.SECONDS)
                .build()
        }
    }
}
