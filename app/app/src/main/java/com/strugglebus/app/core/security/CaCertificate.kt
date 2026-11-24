package com.strugglebus.app.core.security

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object CaCertificate {
    fun parseAndVerify(pem: String, expectedSha256: String): ByteArray =
        verify(
            CertificateFactory.getInstance("X.509")
                .generateCertificates(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
                .singleOrNull()
                ?.let { (it as? X509Certificate)?.encoded }
                ?: throw IllegalArgumentException("Import exactly one CA certificate."),
            expectedSha256,
        )

    fun parseAndVerify(der: ByteArray, expectedSha256: String): ByteArray =
        verify(der, expectedSha256)

    private fun verify(der: ByteArray, expectedSha256: String): ByteArray {
        require(der.isNotEmpty()) { "CA certificate is empty." }
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
            ?: throw IllegalArgumentException("Certificate is not X.509.")
        require(certificate.basicConstraints >= 0) { "Certificate is not a CA certificate." }
        certificate.checkValidity()

        val actual = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        val expected = expectedSha256.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
        require(MessageDigest.isEqual(actual, expected)) {
            "CA certificate does not match the enrollment payload."
        }
        return certificate.encoded
    }
}
