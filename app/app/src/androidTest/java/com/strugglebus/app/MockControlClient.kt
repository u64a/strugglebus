package com.strugglebus.app

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Test-only client for the loopback-bound mock control surface. */
class MockControlClient(caDer: ByteArray) {
    private val client: OkHttpClient

    init {
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(caDer.inputStream()) as X509Certificate
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("mock-ca", certificate)
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
        client = OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .build()
    }

    fun activeStreams(endpoint: String): Int {
        val request = Request.Builder()
            .url(endpoint.trimEnd('/') + "/__control/diagnostics")
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Mock diagnostics failed with HTTP ${response.code}." }
            return JSONObject(checkNotNull(response.body).string()).getInt("active_streams")
        }
    }

    fun setState(endpoint: String, json: String) = post(endpoint, "/__control/state", json)

    fun addMessage(endpoint: String, channel: String, body: String) = post(
        endpoint,
        "/__control/messages",
        """{"channel":"$channel","body":"$body"}""",
    )

    private fun post(endpoint: String, path: String, json: String) {
        val request = Request.Builder()
            .url(endpoint.trimEnd('/') + path)
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Mock control failed with HTTP ${response.code}." }
        }
    }
}
