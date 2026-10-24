package io.github.kinotvapp.quicktunnel

import java.net.Socket
import javax.net.ssl.SSLException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The real shape of the edge's certificates: a leaf issued by a CA the client trusts. These tests exist because a self-signed
 * server certificate bypasses the part of the JDK's trust manager that checks the chain, so everything else passed while the
 * first handshake against the real edge failed with "Unknown authType".
 */
@org.junit.jupiter.api.Timeout(30)
class TlsCaChainTest {
    private val closers = mutableListOf<AutoCloseable>()
    @AfterTest fun cleanup() = closers.forEach { runCatching { it.close() } }

    private companion object { val pki = TestPki("h2.cftunnel.com") }

    private fun echo(p: TestPki) = p.server { c -> val b = ByteArray(64); val n = c.inputStream.read(b); c.outputStream.write(b, 0, n); c.outputStream.flush() }.also { closers += it }

    private fun connect(port: Int, name: String, trust: javax.net.ssl.X509TrustManager) =
        Tls13Connection.connect(Socket("127.0.0.1", port), name, trust, 10_000).also { closers += it }

    @Test fun `a chain issued by the trusted CA completes the handshake and carries data`() {
        val c = connect(echo(pki).localPort, "h2.cftunnel.com", pki.trust)
        c.output.write("through a CA-issued chain".toByteArray()); c.output.flush()
        val buf = ByteArray(64); val n = c.input.read(buf)
        assertEquals("through a CA-issued chain", String(buf, 0, n))
    }

    @Test fun `a certificate the CA issued for ANOTHER name is rejected (any customer of the CA could present one)`() {
        val e = assertFailsWith<SSLException> { connect(echo(pki).localPort, "other.example.com", pki.trust) }
        assertTrue("not valid for" in e.message.orEmpty(), e.message)
    }

    @Test fun `a chain from a different CA is rejected`() {
        val stranger = TestPki("h2.cftunnel.com", caName = "Some Other CA")
        assertFailsWith<SSLException> { connect(echo(pki).localPort, "h2.cftunnel.com", stranger.trust) }
    }
}
