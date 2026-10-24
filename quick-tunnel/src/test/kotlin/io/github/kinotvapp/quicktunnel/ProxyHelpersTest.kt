package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProxyHelpersTest {
    @Test fun `extractPath handles full URLs, bare paths and junk`() {
        assertEquals("/p?q=1", extractPath("https://a.trycloudflare.com/p?q=1"))
        assertEquals("/", extractPath("https://a.trycloudflare.com"))
        assertEquals("/x", extractPath("/x"))
        assertEquals("/", extractPath("garbage"))
    }

    private fun req(vararg h: Pair<String, String>) = ConnectReq("https://x/", 0, httpRequestMeta("GET", "x", *h))

    @Test fun `request shape decides poolability`() {
        assertTrue(analyseRequest(req()).poolable)
        assertTrue(analyseRequest(req("Content-Length" to "5")).poolable)
        assertEquals(5L, analyseRequest(req("content-length" to "5")).contentLength)
        assertFalse(analyseRequest(req("Transfer-Encoding" to "chunked")).poolable)
        assertFalse(analyseRequest(req("Upgrade" to "websocket")).poolable)
        assertFalse(analyseRequest(req("Connection" to "Upgrade")).poolable)
        assertFalse(analyseRequest(req("Connection" to "close")).poolable)
    }

    @Test fun `response shape decides poolability`() {
        assertTrue(analyseResponse(200, listOf("Content-Length" to "3"), false).poolable)
        assertFalse(analyseResponse(200, emptyList(), false).poolable)
        assertFalse(analyseResponse(200, listOf("Content-Length" to "3", "Connection" to "close"), false).poolable)
        assertFalse(analyseResponse(200, listOf("Transfer-Encoding" to "chunked"), false).poolable)
        assertTrue(analyseResponse(101, emptyList(), false).upgrade)
        assertTrue(analyseResponse(304, emptyList(), true).poolable, "no body: length is 0")
        assertEquals(0L, analyseResponse(200, listOf("Content-Length" to "99"), true).contentLength, "HEAD ignores the advertised length")
    }

    @Test fun `bodiless statuses and HEAD`() {
        assertTrue(isBodiless("HEAD", 200)); assertTrue(isBodiless("GET", 204)); assertTrue(isBodiless("GET", 304)); assertTrue(isBodiless("GET", 100))
        assertFalse(isBodiless("GET", 101)); assertFalse(isBodiless("GET", 200))
    }

    @Test fun `request head uses keep-alive only when pooling`() {
        val head = String(buildRequestHead(req("A" to "b"), keepAlive = true))
        assertTrue(head.startsWith("GET / HTTP/1.1\r\nHost: x\r\n")); assertTrue("Connection: keep-alive" in head); assertTrue(head.endsWith("\r\n\r\n"))
        assertTrue("Connection: close" in String(buildRequestHead(req(), keepAlive = false)))
        assertFalse("keep-alive" in String(buildRequestHead(req("Connection" to "Upgrade"), keepAlive = false)), "an explicit Connection header wins")
    }

    /** Hands out one byte per read, so the head parser must cope with the terminator split anywhere. */
    private class Drip(bytes: ByteArray) : InputStream() {
        private val i = ByteArrayInputStream(bytes)
        override fun read() = i.read()
        override fun read(b: ByteArray, off: Int, len: Int) = i.read(b, off, 1)
    }

    @Test fun `response head parses across tiny reads and keeps the leftover`() {
        val h = readResponseHead(Drip("HTTP/1.1 404 Not Found\r\nA: 1\r\nB:2\r\n\r\nBODY".toByteArray()))
        assertEquals(404, h.status); assertEquals(listOf("A" to "1", "B" to "2"), h.headers)
        // Drip returns one byte per read, so the leftover is whatever followed the terminator in that read: empty.
        val h2 = readResponseHead(ByteArrayInputStream("HTTP/1.1 200 OK\r\n\r\nBODY".toByteArray()))
        assertEquals("BODY", String(h2.leftover))
    }

    @Test fun `response head errors`() {
        assertFailsWith<OriginClosed> { readResponseHead(ByteArrayInputStream(ByteArray(0))) }
        assertFailsWith<EOFException> { readResponseHead(ByteArrayInputStream("HTTP/1.1 200".toByteArray())) }
        assertFailsWith<IOException> { readResponseHead(ByteArrayInputStream("NOT HTTP\r\n\r\n".toByteArray())) }
        assertFailsWith<IOException> { readResponseHead(ByteArrayInputStream(ByteArray(40_000) { 'a'.code.toByte() })) }
    }

    @Test fun `chunked decoder handles extensions, trailers and multiple chunks`() {
        val body = "4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\nNEXT"
        val s = ByteArrayInputStream(body.toByteArray())
        assertEquals("Wikipedia", String(ChunkedInputStream(s).readBytes()))
        assertEquals("NEXT", String(s.readBytes()), "stops exactly after the terminating chunk")
    }

    @Test fun `chunked decoder reports truncation`() {
        assertFailsWith<EOFException> { ChunkedInputStream(ByteArrayInputStream("5\r\nhel".toByteArray())).readBytes() }
    }

    @Test fun `copyN is exact and fails on early EOF`() {
        val out = java.io.ByteArrayOutputStream(); val c = java.util.concurrent.atomic.AtomicLong()
        copyN(ByteArrayInputStream(ByteArray(100) { it.toByte() }), out, 40, c)
        assertEquals(40, out.size()); assertEquals(40, c.get())
        assertFailsWith<EOFException> { copyN(ByteArrayInputStream(ByteArray(3)), java.io.ByteArrayOutputStream(), 10, c) }
    }

    @Test fun `ConnectRequest and ConnectResponse survive a round trip`() {
        val bytes = connectRequestBytes("https://a/b", 1, listOf("k1" to "v1", "k2" to "v2"))
        val r = readConnectRequest(ByteArrayInputStream(bytes))
        assertEquals("https://a/b", r.dest); assertEquals(1, r.type); assertEquals("v2", r.meta("k2"))
        val out = java.io.ByteArrayOutputStream()
        writeConnectResponse(out, "boom", listOf("HttpStatus" to "502"))
        val back = parseEdgeResponse(out.toByteArray())
        assertEquals("boom", back.error); assertEquals(502, back.status)
        assertContentEquals(DATA_SIG, out.toByteArray().copyOf(6))
    }

    @Test fun `wrong stream signature is rejected`() {
        assertFailsWith<TunnelException.Internal> { readConnectRequest(ByteArrayInputStream(ByteArray(64))) }
    }

    @Test fun `backoff curve matches the Rust crate`() {
        assertEquals(listOf(1, 2, 4, 8, 16, 30, 30, 30), (1..8).map { (backoffMillis(it) / 1000).toInt() })
    }
}
