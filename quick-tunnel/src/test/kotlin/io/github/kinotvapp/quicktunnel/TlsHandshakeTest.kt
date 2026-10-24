package io.github.kinotvapp.quicktunnel

import java.io.File
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.net.ssl.X509TrustManager
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The handshake state machine, end to end through [Tls13Connection]: against the JDK's own TLS 1.3 server (an independent
 * implementation) for the paths that must work, and against [FakeTlsServer] for every path that must be refused.
 */
@org.junit.jupiter.api.Timeout(60)
class TlsHandshakeTest {
    private companion object {
        const val NAME = "h2.cftunnel.com"
        val id = TestIdentity(NAME)
    }

    private val closers = mutableListOf<AutoCloseable>()
    @AfterTest fun cleanup() = closers.forEach { runCatching { it.close() } }

    private fun connect(port: Int, name: String = NAME, trust: X509TrustManager = id.trust, random: SecureRandom = SecureRandom()): Tls13Connection =
        Tls13Connection.connect(Socket("127.0.0.1", port), name, trust, 5_000, random).also { closers += it }

    private fun fake(cfg: FakeTlsServer.Config) = FakeTlsServer(cfg).also { closers += it }

    private fun echo(identity: TestIdentity) =
        identity.server { c -> val i = c.inputStream; val o = c.outputStream; val b = ByteArray(8192); while (true) { val n = i.read(b); if (n < 0) break; o.write(b, 0, n); o.flush() } }.also { closers += it }

    private fun roundTrip(c: Tls13Connection) {
        c.output.write("ping".toByteArray()); c.output.flush()
        val buf = ByteArray(16); val n = c.input.read(buf)
        assertEquals("ping", String(buf, 0, n))
    }

    private fun refused(cfg: FakeTlsServer.Config, name: String = NAME, trust: X509TrustManager = id.trust): TlsHandshakeException =
        assertFailsWith<TlsHandshakeException> { connect(fake(cfg).port, name, trust) }

    private fun cfg(
        identity: TestIdentity = id, cipher: Int = 0x1301, legacyVersion: Int = 0x0303, supportedVersion: Int? = 0x0304, shGroup: Int = 0x0017,
        retryGroups: List<Int> = emptyList(), cookie: ByteArray? = null, extra: List<Pair<Int, ByteArray>> = emptyList(), compression: Int = 0,
        sessionIdEcho: ByteArray? = null, offCurvePoint: Boolean = false, sigScheme: Int? = null, coalesce: Boolean = false,
        tamperHello: (ByteArray) -> ByteArray = { it },
        tamper: (String, ByteArray) -> ByteArray = { _, m -> m }, flight: (MutableList<Pair<String, ByteArray>>) -> Unit = {},
    ) = FakeTlsServer.Config(identity, cipher, legacyVersion, supportedVersion, shGroup, retryGroups, cookie, extra, compression, sessionIdEcho, offCurvePoint, sigScheme, tamper, flight, coalesce, tamperHello)

    private fun msg(type: Int, body: ByteArray) = byteArrayOf(type.toByte(), (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
    private fun flip(m: ByteArray, index: Int) = m.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

    // ── against the JDK's server ─────────────────────────────────────────────

    @Test fun `ECDSA P-256 certificate against the JDK server`() { roundTrip(connect(echo(id).localPort)) }

    @Test fun `ECDSA P-384 certificate against the JDK server`() {
        val p384 = TestIdentity(NAME, group = "secp384r1")
        roundTrip(connect(echo(p384).localPort, trust = p384.trust))
    }

    @Test fun `ECDSA P-521 certificate against the JDK server`() {
        val p521 = TestIdentity(NAME, group = "secp521r1")
        roundTrip(connect(echo(p521).localPort, trust = p521.trust))
    }

    @Test fun `RSA certificate with RSA-PSS CertificateVerify against the JDK server`() {
        val rsa = TestIdentity(NAME, keyAlg = "RSA")
        roundTrip(connect(echo(rsa).localPort, trust = rsa.trust))
    }

    @Test fun `a wildcard SAN covers one label only, against the JDK server`() {
        val wild = TestIdentity("origin.test", san = "dns:*.cftunnel.com,dns:cftunnel.com")
        val server = echo(wild)
        roundTrip(connect(server.localPort, name = "h2.cftunnel.com", trust = wild.trust))
        roundTrip(connect(server.localPort, name = "cftunnel.com", trust = wild.trust))
        val deep = assertFailsWith<TlsHandshakeException> { connect(server.localPort, name = "a.b.cftunnel.com", trust = wild.trust) }
        assertEquals(TlsAlert.BAD_CERTIFICATE, deep.alert)
        assertTrue("not valid for a.b.cftunnel.com" in deep.message!!, deep.message)
        assertFailsWith<TlsHandshakeException> { connect(server.localPort, name = "evil.example.com", trust = wild.trust) }
    }

    @Test fun `a trusted certificate for a different name is refused even though the chain validates`() {
        // The Cloudflare Origin CA situation: the trust manager says yes, only the name check can say no.
        val other = TestIdentity("customer.example")
        assertTrue(runCatching { other.trust.checkServerTrusted(arrayOf(other.certificate), "ECDSA") }.isSuccess)
        val e = assertFailsWith<TlsHandshakeException> { connect(echo(other).localPort, name = NAME, trust = other.trust) }
        assertEquals(TlsAlert.BAD_CERTIFICATE, e.alert)
        assertTrue("not valid for $NAME" in e.message!!, e.message)
    }

    @Test fun `a certificate without any SAN is refused`() {
        val noSan = TestIdentity(NAME, san = null)
        assertFailsWith<TlsHandshakeException> { connect(echo(noSan).localPort, trust = noSan.trust) }
    }

    @Test fun `an injected SecureRandom makes the ClientHello random deterministic`() {
        class Fixed : SecureRandom() { override fun nextBytes(bytes: ByteArray) { bytes.fill(7) } }
        val server = fake(cfg())
        runCatching { connect(server.port, random = Fixed()) }
        server.clientFinishedVerified.get(5, TimeUnit.SECONDS)
        assertContentEquals(ByteArray(32) { 7 }, server.clientHellos[0].copyOfRange(6, 38))
    }

    @Test fun `HelloRetryRequest from the JDK server is answered with a new key share`() {
        // jdk.tls.namedGroups is read once per JVM, so the server runs in its own: it only accepts secp384r1, while the
        // client's first share is secp256r1, which can only end in a HelloRetryRequest.
        val p384 = TestIdentity(NAME, group = "secp384r1")
        val dir = File.createTempFile("hrr", "dir").also { it.delete(); it.mkdirs() }
        try {
            val p12 = File(dir, "id.p12").also { f -> f.outputStream().use { p384.keystore.store(it, "changeit".toCharArray()) } }
            val portFile = File(dir, "port"); val log = File(dir, "log")
            File(dir, "HrrServer.java").writeText(HRR_SERVER_SOURCE)
            val java = File(System.getProperty("java.home"), "bin/java").path
            val process = ProcessBuilder(java, "-Djdk.tls.namedGroups=secp384r1", "-Djavax.net.debug=ssl:handshake", File(dir, "HrrServer.java").path, p12.path, portFile.path)
                .redirectErrorStream(true).redirectOutput(log).start()
            closers += AutoCloseable { process.destroyForcibly() }
            val deadline = System.currentTimeMillis() + 30_000
            while (!portFile.exists() && System.currentTimeMillis() < deadline) Thread.sleep(50)
            assertTrue(portFile.exists(), "the helper server did not start: ${log.takeIf { it.exists() }?.readText()}")
            Thread.sleep(100)
            val c = connect(portFile.readText().trim().toInt(), trust = p384.trust)
            roundTrip(c)
            c.close()
            Thread.sleep(300)
            assertTrue("HelloRetryRequest" in log.readText(), "the JDK server must have sent a HelloRetryRequest")
        } finally { dir.deleteRecursively() }
    }

    // ── against the fake server: what must work ──────────────────────────────

    @Test fun `full handshake, NewSessionTicket ignored, data both ways, our Finished verified by the server`() {
        val server = fake(cfg())
        val c = connect(server.port)
        val buf = ByteArray(16); val n = c.input.read(buf)
        assertEquals("pong", String(buf, 0, n))
        c.output.write("ping".toByteArray()); c.output.flush()
        assertTrue(server.clientFinishedVerified.get(5, TimeUnit.SECONDS), "the client Finished must verify at the server")
        assertEquals("ping", server.clientApplicationData.get(5, TimeUnit.SECONDS))
    }

    @Test fun `the whole server flight in one record works too`() {
        val server = fake(cfg(coalesce = true))
        val c = connect(server.port)
        assertEquals('p'.code, c.input.read())
        assertTrue(server.clientFinishedVerified.get(5, TimeUnit.SECONDS))
    }

    @Test fun `the ClientHello is what the scope says`() {
        val server = fake(cfg())
        connect(server.port)
        val ch = server.clientHellos[0]
        assertEquals(1, ch[0].toInt()); assertEquals(0x03, ch[4].toInt()); assertEquals(0x03, ch[5].toInt())
        assertEquals(0, ch[38].toInt(), "empty legacy_session_id")
        assertContentEquals(byteArrayOf(0, 2, 0x13, 1, 1, 0), ch.copyOfRange(39, 45), "one cipher suite, null compression")
        val sni = NAME.toByteArray()
        assertTrue(indexOf(ch, byteArrayOf(0, 0, 0, (sni.size + 5).toByte(), 0, (sni.size + 3).toByte(), 0, 0, sni.size.toByte()) + sni) > 0, "server_name extension")
        assertTrue(indexOf(ch, byteArrayOf(0, 43, 0, 3, 2, 3, 4)) > 0, "supported_versions: TLS 1.3 only")
        assertEquals(-1, indexOf(ch, byteArrayOf(0, 16, 0)), "no ALPN") // a real ALPN extension would start 00 10 00 ..
    }

    private fun indexOf(h: ByteArray, n: ByteArray): Int { outer@ for (i in 0..h.size - n.size) { for (j in n.indices) if (h[i + j] != n[j]) continue@outer; return i }; return -1 }

    @Test fun `HelloRetryRequest to secp384r1 with a cookie is answered and the handshake completes`() {
        val cookie = ByteArray(40) { (it * 3).toByte() }
        val server = fake(cfg(retryGroups = listOf(0x0018), shGroup = 0x0018, cookie = cookie))
        val c = connect(server.port)
        assertEquals('p'.code, c.input.read())
        assertTrue(server.clientFinishedVerified.get(5, TimeUnit.SECONDS), "the transcript with message_hash must agree on both sides")
        assertEquals(2, server.clientHellos.size)
        val (first, second) = server.clientHellos
        assertContentEquals(first.copyOfRange(6, 38), second.copyOfRange(6, 38), "same random in the second ClientHello")
        assertTrue(indexOf(second, byteArrayOf(0, 44, 0, 42, 0, 40) + cookie) > 0, "cookie echoed")
        assertTrue(indexOf(second, byteArrayOf(0, 51, 0, 0x67, 0, 0x65, 0, 0x18, 0, 0x61, 4)) > 0, "a secp384r1 uncompressed share")
    }

    @Test fun `HelloRetryRequest to secp521r1 without a cookie`() {
        val server = fake(cfg(retryGroups = listOf(0x0019), shGroup = 0x0019))
        connect(server.port)
        assertTrue(server.clientFinishedVerified.get(5, TimeUnit.SECONDS))
    }

    // ── HelloRetryRequest abuse ──────────────────────────────────────────────

    @Test fun `a second HelloRetryRequest is refused`() {
        val e = refused(cfg(retryGroups = listOf(0x0018, 0x0019)))
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, e.alert); assertTrue("second HelloRetryRequest" in e.message!!, e.message)
    }

    @Test fun `a HelloRetryRequest for the group already sent is refused`() {
        val e = refused(cfg(retryGroups = listOf(0x0017)))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert)
    }

    @Test fun `a HelloRetryRequest for a group never offered is refused`() {
        val e = refused(cfg(retryGroups = listOf(0x001d))) // x25519
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert); assertTrue("did not offer" in e.message!!, e.message)
    }

    // ── ServerHello validation ───────────────────────────────────────────────

    @Test fun `a cipher suite we did not offer is refused`() {
        val e = refused(cfg(cipher = 0x1302))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert); assertTrue("cipher" in e.message!!, e.message)
    }

    @Test fun `a group we sent no share for is refused`() {
        val e = refused(cfg(shGroup = 0x0018))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert); assertTrue("group" in e.message!!, e.message)
    }

    @Test fun `a ServerHello for TLS 1_2 is refused as a protocol version error`() {
        val noExt = refused(cfg(supportedVersion = null))
        assertEquals(TlsAlert.PROTOCOL_VERSION, noExt.alert); assertTrue("TLS 1.3" in noExt.message!!, noExt.message)
        assertEquals(TlsAlert.PROTOCOL_VERSION, refused(cfg(legacyVersion = 0x0302)).alert)
        assertEquals(TlsAlert.PROTOCOL_VERSION, refused(cfg(supportedVersion = 0x0303)).alert)
    }

    @Test fun `a wrong legacy_session_id_echo is refused`() {
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, refused(cfg(sessionIdEcho = ByteArray(32) { 1 })).alert)
    }

    @Test fun `a compression method other than null is refused`() {
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, refused(cfg(compression = 1)).alert)
    }

    @Test fun `a key share that is not on the curve is refused`() {
        val e = refused(cfg(offCurvePoint = true))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert); assertTrue("curve" in e.message!!, e.message)
    }

    @Test fun `unexpected and duplicated ServerHello extensions are refused`() {
        assertEquals(TlsAlert.UNSUPPORTED_EXTENSION, refused(cfg(extra = listOf(16 to byteArrayOf(0, 0)))).alert)
        assertEquals(TlsAlert.UNSUPPORTED_EXTENSION, refused(cfg(extra = listOf(41 to byteArrayOf(0, 0)))).alert, "pre_shared_key was never offered")
        val dup = refused(cfg(extra = listOf(43 to byteArrayOf(3, 4))))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, dup.alert); assertTrue("duplicate" in dup.message!!, dup.message)
    }

    @Test fun `the downgrade sentinel in ServerHello_random is refused`() {
        val e = refused(cfg(tamperHello = { m -> m.copyOf().also { "DOWNGRD".toByteArray().copyInto(it, 6 + 24); it[6 + 31] = 1 } }))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert)
    }

    @Test fun `a truncated ServerHello is a decode error`() {
        val e = refused(cfg(tamperHello = { m -> msg(2, m.copyOfRange(4, 30)) }))
        assertEquals(TlsAlert.DECODE_ERROR, e.alert)
    }

    @Test fun `a ServerHello with trailing garbage is a decode error`() {
        val e = refused(cfg(tamperHello = { m -> msg(2, m.copyOfRange(4, m.size) + byteArrayOf(1, 2, 3)) }))
        assertEquals(TlsAlert.DECODE_ERROR, e.alert)
    }

    // ── Certificate validation ───────────────────────────────────────────────

    @Test fun `a certificate nobody trusts is refused`() {
        val e = refused(cfg(identity = TestIdentity(NAME)))
        assertEquals(TlsAlert.BAD_CERTIFICATE, e.alert); assertTrue("rejected" in e.message!!, e.message)
    }

    @Test fun `a trusted certificate for another name is refused`() {
        val other = TestIdentity("evil.example.com")
        val e = refused(cfg(identity = other), trust = other.trust)
        assertEquals(TlsAlert.BAD_CERTIFICATE, e.alert); assertTrue("not valid for $NAME" in e.message!!, e.message)
    }

    @Test fun `a wildcard certificate is accepted for one label and refused for two or none`() {
        val wild = TestIdentity("origin.test", san = "dns:*.cftunnel.com")
        val ok = fake(cfg(identity = wild))
        connect(ok.port, name = "h2.cftunnel.com", trust = wild.trust)
        assertTrue(ok.clientFinishedVerified.get(5, TimeUnit.SECONDS))
        assertEquals(TlsAlert.BAD_CERTIFICATE, refused(cfg(identity = wild), name = "a.b.cftunnel.com", trust = wild.trust).alert)
        assertEquals(TlsAlert.BAD_CERTIFICATE, refused(cfg(identity = wild), name = "cftunnel.com", trust = wild.trust).alert)
    }

    @Test fun `an empty certificate list and a non-empty request context are refused`() {
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "Cert") msg(11, byteArrayOf(0, 0, 0, 0)) else m })).alert)
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, refused(cfg(tamper = { n, m -> if (n == "Cert") msg(11, byteArrayOf(1, 9, 0, 0, 0)) else m })).alert)
    }

    @Test fun `garbage instead of a certificate is refused`() {
        val e = refused(cfg(tamper = { n, m -> if (n == "Cert") msg(11, byteArrayOf(0, 0, 0, 8, 0, 0, 3, 1, 2, 3, 0, 0)) else m }))
        assertEquals(TlsAlert.BAD_CERTIFICATE, e.alert)
    }

    // ── CertificateVerify and Finished ───────────────────────────────────────

    @Test fun `a corrupted CertificateVerify signature is refused`() {
        val e = refused(cfg(tamper = { n, m -> if (n == "CV") flip(m, m.size - 5) else m }))
        assertEquals(TlsAlert.DECRYPT_ERROR, e.alert); assertTrue("CertificateVerify" in e.message!!, e.message)
    }

    @Test fun `a corrupted RSA-PSS CertificateVerify signature is refused`() {
        val rsa = TestIdentity(NAME, keyAlg = "RSA")
        connect(fake(cfg(identity = rsa)).port, trust = rsa.trust)
        val e = refused(cfg(identity = rsa, tamper = { n, m -> if (n == "CV") flip(m, m.size - 5) else m }), trust = rsa.trust)
        assertEquals(TlsAlert.DECRYPT_ERROR, e.alert)
    }

    @Test fun `a signature scheme we did not offer is refused`() {
        val e = refused(cfg(sigScheme = 0x0401))
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert); assertTrue("did not offer" in e.message!!, e.message)
    }

    @Test fun `a signature scheme that does not match the key is refused`() {
        val e = refused(cfg(sigScheme = 0x0503)) // P-384 scheme with a P-256 key
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, e.alert)
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, refused(cfg(sigScheme = 0x0804)).alert, "RSA-PSS with an EC key")
    }

    @Test fun `a corrupted Finished is refused`() {
        val e = refused(cfg(tamper = { n, m -> if (n == "Fin") flip(m, 10) else m }))
        assertEquals(TlsAlert.DECRYPT_ERROR, e.alert); assertTrue("Finished" in e.message!!, e.message)
    }

    @Test fun `a Finished of the wrong length is refused`() {
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "Fin") msg(20, ByteArray(10)) else m })).alert)
    }

    // ── message order and shape ──────────────────────────────────────────────

    @Test fun `a CertificateRequest is refused`() {
        val e = refused(cfg(flight = { f -> f.add(1, "CR" to msg(13, byteArrayOf(0, 0, 0))) }))
        assertEquals(TlsAlert.HANDSHAKE_FAILURE, e.alert); assertTrue("client certificate" in e.message!!, e.message)
    }

    @Test fun `a duplicated EncryptedExtensions is refused`() {
        val e = refused(cfg(flight = { f -> f.add(1, f[0]) }))
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, e.alert)
    }

    @Test fun `a missing Certificate, a missing CertificateVerify and a swapped pair are refused`() {
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, refused(cfg(flight = { f -> f.removeAt(1) })).alert)
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, refused(cfg(flight = { f -> f.removeAt(2) })).alert)
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, refused(cfg(flight = { f -> val cv = f.removeAt(2); f.add(1, cv) })).alert)
    }

    @Test fun `Finished first is refused`() {
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, refused(cfg(flight = { f -> val fin = f.removeAt(3); f.add(0, fin) })).alert)
    }

    @Test fun `a ServerHello where EncryptedExtensions belongs is refused`() {
        val e = refused(cfg(flight = { f -> f.add(0, "SH" to msg(2, ByteArray(40))) }))
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, e.alert)
    }

    @Test fun `an unsolicited EncryptedExtensions extension is refused`() {
        val alpn = byteArrayOf(0, 16, 0, 5, 0, 3, 2, 'h'.code.toByte(), '2'.code.toByte())
        val e = refused(cfg(tamper = { n, m -> if (n == "EE") msg(8, byteArrayOf(0, alpn.size.toByte()) + alpn) else m }))
        assertEquals(TlsAlert.UNSUPPORTED_EXTENSION, e.alert)
    }

    @Test fun `server_name and supported_groups in EncryptedExtensions are tolerated`() {
        val exts = byteArrayOf(0, 0, 0, 0, 0, 10, 0, 4, 0, 2, 0, 0x17)
        val server = fake(cfg(tamper = { n, m -> if (n == "EE") msg(8, byteArrayOf(0, exts.size.toByte()) + exts) else m }))
        connect(server.port)
        assertTrue(server.clientFinishedVerified.get(5, TimeUnit.SECONDS))
    }

    @Test fun `garbage and truncated messages are decode errors`() {
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "EE") msg(8, byteArrayOf(-1, -1)) else m })).alert, "extension block longer than the message")
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "EE") msg(8, byteArrayOf(0)) else m })).alert, "one byte of a length")
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "CV") msg(15, byteArrayOf(4, 3)) else m })).alert, "CertificateVerify without a signature")
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "CV") msg(15, byteArrayOf(4, 3, 0, 9, 1, 2)) else m })).alert, "signature longer than the message")
        assertEquals(TlsAlert.DECODE_ERROR, refused(cfg(tamper = { n, m -> if (n == "Cert") msg(11, byteArrayOf(0)) else m })).alert, "Certificate cut short")
    }

    @Test fun `duplicate extensions in EncryptedExtensions are refused`() {
        val twice = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0)
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, refused(cfg(tamper = { n, m -> if (n == "EE") msg(8, byteArrayOf(0, 8) + twice) else m })).alert)
    }

    @Test fun `a handshake message that announces an absurd length is refused without buffering it`() {
        val huge = byteArrayOf(8, 0x7f, -1, -1) // EncryptedExtensions, 8 MB
        val e = refused(cfg(tamper = { n, m -> if (n == "EE") huge else m }))
        assertEquals(TlsAlert.DECODE_ERROR, e.alert); assertTrue("too large" in e.message!!, e.message)
    }

    @Test fun `a server that never answers the ClientHello times out instead of hanging`() {
        val ss = java.net.ServerSocket(0).also { closers += it }
        val started = System.currentTimeMillis()
        assertFailsWith<java.io.IOException> { Tls13Connection.connect(Socket("127.0.0.1", ss.localPort), NAME, id.trust, 800) }
        assertTrue(System.currentTimeMillis() - started < 10_000)
    }

    @Test fun `an IP literal is not sent as SNI and is matched against iPAddress SANs`() {
        val ip = TestIdentity("host.test", san = "ip:127.0.0.1")
        val server = fake(cfg(identity = ip))
        connect(server.port, name = "127.0.0.1", trust = ip.trust)
        assertTrue(server.clientFinishedVerified.get(5, TimeUnit.SECONDS))
        val ch = server.clientHellos[0]
        assertTrue(!(ch[47].toInt() == 0 && ch[48].toInt() == 0), "server_name is the first extension when sent; here the first one must be supported_groups")
        assertEquals(TlsAlert.BAD_CERTIFICATE, refused(cfg(identity = ip), name = "127.0.0.2", trust = ip.trust).alert)
    }
}

private const val HRR_SERVER_SOURCE = """
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.KeyStore;
import javax.net.ssl.*;

public class HrrServer {
    public static void main(String[] a) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(a[0])) { ks.load(in, "changeit".toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, null);
        SSLServerSocket s = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getByName("127.0.0.1"));
        s.setEnabledProtocols(new String[] {"TLSv1.3"});
        Files.write(Paths.get(a[1]), Integer.toString(s.getLocalPort()).getBytes());
        s.setSoTimeout(30000);
        SSLSocket c = (SSLSocket) s.accept();
        InputStream in = c.getInputStream();
        OutputStream out = c.getOutputStream();
        byte[] b = new byte[1024];
        int n;
        while ((n = in.read(b)) >= 0) { out.write(b, 0, n); out.flush(); }
    }
}
"""
