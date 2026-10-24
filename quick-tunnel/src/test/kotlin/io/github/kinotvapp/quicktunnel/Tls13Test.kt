package io.github.kinotvapp.quicktunnel

import java.net.Socket
import java.security.MessageDigest
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The pure-Java TLS 1.3 client checked against an independent implementation: the JDK's TLS server. */
@org.junit.jupiter.api.Timeout(30)
class Tls13Test {
    private companion object { val id = TestIdentity("h2.cftunnel.com") }

    private val closers = mutableListOf<AutoCloseable>()
    @AfterTest fun cleanup() = closers.forEach { runCatching { it.close() } }

    private fun connect(port: Int, name: String = "h2.cftunnel.com", trust: X509TrustManager = id.trust): Tls13Connection {
        val s = Socket("127.0.0.1", port)
        return Tls13Connection.connect(s, name, trust, 10_000).also { closers += it }
    }

    private fun echoServer() = id.server { c -> val i = c.inputStream; val o = c.outputStream; val b = ByteArray(8192); while (true) { val n = i.read(b); if (n < 0) break; o.write(b, 0, n); o.flush() } }.also { closers += it }

    @Test fun `handshake and a small echo`() {
        val c = connect(echoServer().localPort)
        c.output.write("hello over pure-Java TLS 1.3".toByteArray()); c.output.flush()
        val buf = ByteArray(64); val n = c.input.read(buf)
        assertEquals("hello over pure-Java TLS 1.3", String(buf, 0, n))
    }

    @Test fun `megabytes in both directions arrive intact across many records`() {
        val payload = ByteArray(3_000_000) { (it * 31 + it / 7).toByte() }
        val c = connect(echoServer().localPort)
        val sender = thread { c.output.write(payload); c.output.flush() }
        val got = ByteArray(payload.size); var off = 0
        while (off < got.size) { val n = c.input.read(got, off, got.size - off); assertTrue(n > 0); off += n }
        sender.join()
        assertContentEquals(MessageDigest.getInstance("SHA-256").digest(payload), MessageDigest.getInstance("SHA-256").digest(got))
        assertTrue(c.keyUpdatesSeen > 0, "3 MB through a server that rotates every 150 KB must have rotated keys")
    }

    @Test fun `key updates requested by the peer are followed in both directions`() {
        // The test JVM runs with jdk.tls.keyLimits set (see build.gradle.kts): the JDK server asks for a key rotation each
        // time it has read ~150 KB, and rotates its own sending keys when it does. So send a lot and read the echo back.
        val payload = ByteArray(1_500_000) { (it * 13 + it / 5).toByte() }
        val c = connect(echoServer().localPort)
        val sender = thread { c.output.write(payload); c.output.flush() }
        val got = ByteArray(payload.size); var off = 0
        while (off < got.size) { val n = c.input.read(got, off, got.size - off); assertTrue(n > 0); off += n }
        sender.join()
        assertContentEquals(payload, got)
        assertTrue(c.keyUpdatesSeen >= 3, "the server rotated keys ${c.keyUpdatesSeen} times")
        // Our writes after the rotations must still be readable by the server, or it would have killed the connection.
        c.output.write("after".toByteArray()); c.output.flush()
        val buf = ByteArray(16); val n = c.input.read(buf)
        assertEquals("after", String(buf, 0, n))
    }

    @Test fun `concurrent writers do not interleave or corrupt records`() {
        val c = connect(echoServer().localPort)
        val per = 200; val threads = 4
        val writers = (0 until threads).map { t -> thread { repeat(per) { c.output.write(ByteArray(1000) { t.toByte() }) } } }
        val total = per * threads * 1000
        val counts = IntArray(threads); var read = 0
        val buf = ByteArray(8192)
        while (read < total) { val n = c.input.read(buf); assertTrue(n > 0); for (i in 0 until n) counts[buf[i].toInt()]++; read += n }
        writers.forEach { it.join() }
        assertEquals(List(threads) { per * 1000 }, counts.toList())
    }

    @Test fun `close_notify from the server is end of stream`() {
        val server = id.server { c -> c.outputStream.write("bye".toByteArray()); c.outputStream.flush(); c.close() }.also { closers += it }
        val c = connect(server.localPort)
        assertEquals("bye", String(c.input.readNBytesCompat(3)))
        assertEquals(-1, c.input.read())
    }

    @Test fun `closing sends close_notify so the server sees a clean end`() {
        val serverSawEof = java.util.concurrent.CompletableFuture<Boolean>()
        val server = id.server { c -> serverSawEof.complete(c.inputStream.read() == -1) }.also { closers += it }
        connect(server.localPort).close()
        assertTrue(serverSawEof.get(5, java.util.concurrent.TimeUnit.SECONDS))
    }

    @Test fun `a certificate nobody trusts is rejected`() {
        val stranger = TestIdentity("h2.cftunnel.com")
        assertFailsWith<SSLException> { connect(echoServer().localPort, trust = stranger.trust) }
    }

    @Test fun `a certificate for another name is rejected`() {
        assertFailsWith<SSLException> { connect(echoServer().localPort, name = "evil.example.com") }
    }

    @Test fun `a server that only speaks TLS 1_2 fails the handshake with a clear error`() {
        val server = id.server(protocols = arrayOf("TLSv1.2")) { }.also { closers += it }
        assertFailsWith<SSLHandshakeException> { connect(server.localPort) }
    }

    @Test fun `a server that hangs up during the handshake is a handshake error`() {
        val ss = java.net.ServerSocket(0).also { closers += it }
        thread(isDaemon = true) { ss.accept().close() }
        assertFailsWith<SSLHandshakeException> { Tls13Connection.connect(Socket("127.0.0.1", ss.localPort), "h2.cftunnel.com", id.trust, 5_000) }
    }

    @Test fun `HKDF-Expand-Label produces the documented lengths and is deterministic`() {
        val secret = ByteArray(32) { it.toByte() }
        assertEquals(16, Tls13Connection.expandLabel(secret, "key", ByteArray(0), 16).size)
        assertEquals(12, Tls13Connection.expandLabel(secret, "iv", ByteArray(0), 12).size)
        assertContentEquals(Tls13Connection.expandLabel(secret, "key", ByteArray(0), 16), Tls13Connection.expandLabel(secret, "key", ByteArray(0), 16))
        assertTrue(!Tls13Connection.expandLabel(secret, "key", ByteArray(0), 16).contentEquals(Tls13Connection.expandLabel(secret, "iv", ByteArray(0), 16)))
    }

    private fun java.io.InputStream.readNBytesCompat(n: Int): ByteArray { val b = ByteArray(n); var o = 0; while (o < n) { val r = read(b, o, n - o); if (r < 0) break; o += r }; return b.copyOf(o) }
}
