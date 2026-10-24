package io.github.kinotvapp.quicktunnel

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Http2ConnectionTest {
    private val open = mutableListOf<AutoCloseable>()
    @AfterTest fun cleanup() = open.forEach { runCatching { it.close() } }
    private fun harness(handler: (Http2Request) -> Unit) = H2Harness(handler).also { open += it }

    @Test fun `server speaks first with its settings and a bigger connection window`() {
        val h = harness({ })
        val s = h.client.serverSettings.get(5, TimeUnit.SECONDS)
        assertEquals(Http2Connection.STREAM_WINDOW, s[Http2Connection.SETTINGS_INITIAL_WINDOW_SIZE])
        assertEquals(1000, s[Http2Connection.SETTINGS_MAX_CONCURRENT_STREAMS])
        assertEquals(0, s[Http2Connection.SETTINGS_ENABLE_PUSH])
        assertEquals(Http2Connection.CONN_WINDOW - Http2Connection.DEFAULT_WINDOW, h.client.serverConnWindowUpdates.poll(5, TimeUnit.SECONDS))
    }

    @Test fun `client SETTINGS are acknowledged`() {
        val h = harness({ })
        h.client.settingsAcks.poll(5, TimeUnit.SECONDS).let { assertNotNull(it) }
    }

    @Test fun `a simple request gets status headers and body`() {
        val h = harness({ req ->
            assertEquals("GET", req.header(":method")); assertEquals("/hello?x=1", req.header(":path")); assertEquals("x.trycloudflare.com", req.header(":authority"))
            assertTrue(req.endStream)
            req.response.sendHeaders(201, listOf("X-Test" to "yes"))
            req.response.body.write("hi there".toByteArray()); req.response.finish()
        })
        val st = h.client.get("/hello?x=1")
        assertEquals(201, st.status); assertEquals("yes", st.header("x-test")); assertEquals("hi there", String(st.bodyBytes()))
    }

    @Test fun `writing a body before the headers sends a bare 200`() {
        val h = harness({ req -> req.response.body.write("x".toByteArray()); req.response.finish() })
        val st = h.client.get("/")
        assertEquals(200, st.status); assertEquals("x", String(st.bodyBytes()))
    }

    @Test fun `a handler that returns without finishing still ends the stream`() {
        val h = harness({ req -> req.response.sendHeaders(204, emptyList()) })
        val st = h.client.get("/")
        assertEquals(204, st.status); st.bodyBytes()
    }

    @Test fun `request bodies arrive intact across many DATA frames`() {
        val payload = ByteArray(700_000) { (it * 7).toByte() }
        val h = harness({ req ->
            val got = req.body.readBytes()
            req.response.sendHeaders(200, emptyList())
            req.response.body.write(java.security.MessageDigest.getInstance("SHA-256").digest(got)); req.response.finish()
        })
        val st = h.client.request("POST", "/up", emptyList(), payload)
        assertContentEquals(java.security.MessageDigest.getInstance("SHA-256").digest(payload), st.bodyBytes())
    }

    @Test fun `a response larger than the client's window waits for WINDOW_UPDATE instead of overrunning it`() {
        val big = ByteArray(300_000) { it.toByte() }
        val h = harness({ req -> req.response.sendHeaders(200, emptyList()); req.response.body.write(big); req.response.finish() })
        h.client.autoWindowUpdate = false
        val st = h.client.get("/")
        Thread.sleep(500)
        // The default initial window is 65,535 bytes and nobody has granted more yet.
        assertEquals(Http2Connection.DEFAULT_WINDOW.toLong(), h.client.receivedDataBytes, "server must stop exactly at the window")
        h.client.autoWindowUpdate = true
        h.client.frame(Http2Connection.WINDOW_UPDATE, 0, 0, Http2Connection.intBytes(1 shl 20))
        h.client.frame(Http2Connection.WINDOW_UPDATE, 0, st.id, Http2Connection.intBytes(1 shl 20))
        assertContentEquals(big, st.bodyBytes())
    }

    @Test fun `raising INITIAL_WINDOW_SIZE mid-flight unblocks streams that were waiting`() {
        val big = ByteArray(200_000)
        val h = harness({ req -> req.response.sendHeaders(200, emptyList()); req.response.body.write(big); req.response.finish() })
        h.client.autoWindowUpdate = false
        val st = h.client.get("/")
        Thread.sleep(300)
        h.client.frame(Http2Connection.SETTINGS, 0, 0, byteArrayOf(0, 4) + Http2Connection.intBytes(1 shl 20))
        h.client.frame(Http2Connection.WINDOW_UPDATE, 0, 0, Http2Connection.intBytes(1 shl 20))
        h.client.autoWindowUpdate = true
        assertEquals(big.size, st.bodyBytes().size)
    }

    @Test fun `header blocks split into CONTINUATION frames are reassembled`() {
        val seen = java.util.concurrent.CompletableFuture<String?>()
        val h = harness({ req -> seen.complete(req.header("cookie")); req.response.sendHeaders(200, emptyList()) })
        val cookie = "a=" + "z".repeat(40_000)
        val st = h.client.requestWithContinuation("/", listOf("cookie" to cookie), pieceSize = 8_000)
        assertEquals(200, st.status)
        assertEquals(cookie, seen.get(5, TimeUnit.SECONDS))
    }

    @Test fun `PING is answered with the same payload`() {
        val h = harness({ })
        val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        h.client.frame(Http2Connection.PING, 0, 0, payload)
        assertContentEquals(payload, h.client.pongs.poll(5, TimeUnit.SECONDS))
    }

    @Test fun `the server pings an idle edge`() {
        val h = H2Harness({ }, pingIntervalMs = 100).also { open += it }
        val deadline = System.currentTimeMillis() + 3000
        while (h.client.serverPings.get() < 3 && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertTrue(h.client.serverPings.get() >= 3, "pings seen: ${h.client.serverPings.get()}")
        assertTrue(!h.server.isClosed, "an edge that answers must keep the connection alive")
    }

    @Test fun `an edge that goes silent is dropped after the idle timeout`() {
        val h = H2Harness({ }, pingIntervalMs = 50, idleTimeoutMs = 300).also { open += it }
        h.client.autoPong = false
        val cause = h.closed.get(5, TimeUnit.SECONDS)
        assertTrue(h.server.isClosed)
        assertNotNull(cause, "a timeout is a failure, not a clean close")
        assertTrue("no data from the edge" in cause.message.orEmpty(), cause.message)
    }

    @Test fun `RST_STREAM from the edge fails a handler blocked on the body`() {
        val failed = java.util.concurrent.CompletableFuture<Throwable>()
        val h = harness({ req -> try { req.body.readBytes(); failed.complete(IllegalStateException("read finished")) } catch (e: java.io.IOException) { failed.complete(e) } })
        val st = h.client.openStreaming("POST", "/")
        Thread.sleep(100)
        h.client.frame(Http2Connection.RST_STREAM, 0, st.id, Http2Connection.intBytes(8))
        assertTrue(failed.get(5, TimeUnit.SECONDS) is java.io.IOException)
    }

    @Test fun `answering before the request body ends resets the stream with NO_ERROR`() {
        val h = harness({ req -> req.response.sendHeaders(200, emptyList(), endStream = true) })
        val st = h.client.openStreaming("POST", "/")
        assertEquals(200, st.status)
        assertEquals(Http2Connection.NO_ERROR, st.reset.get(5, TimeUnit.SECONDS))
    }

    @Test fun `GOAWAY from the edge ends the connection`() {
        val h = harness({ })
        h.client.frame(Http2Connection.GOAWAY, 0, 0, ByteArray(8))
        assertEquals(null, h.closed.get(5, TimeUnit.SECONDS))
    }

    @Test fun `even stream ids are refused`() {
        val h = harness({ it.response.sendHeaders(200, emptyList()) })
        val st = MiniH2Client.ClientStream(2).also { h.client.streams[2] = it }
        val block = com.twitter.hpack.Encoder(4096).let { e -> java.io.ByteArrayOutputStream().also { b -> listOf(":method" to "GET", ":scheme" to "https", ":authority" to "x", ":path" to "/").forEach { (n, v) -> e.encodeHeader(b, n.toByteArray(), v.toByteArray(), false) } }.toByteArray() }
        h.client.frame(Http2Connection.HEADERS, Http2Connection.FLAG_END_HEADERS or Http2Connection.FLAG_END_STREAM, 2, block)
        assertEquals(Http2Connection.REFUSED_STREAM, st.reset.get(5, TimeUnit.SECONDS))
    }

    @Test fun `padded DATA is unpadded and its padding still counts for flow control`() {
        val got = java.util.concurrent.CompletableFuture<String>()
        val h = harness({ req -> got.complete(String(req.body.readBytes())); req.response.sendHeaders(200, emptyList(), endStream = true) })
        val st = h.client.openStreaming("POST", "/")
        val pad = 7
        val payload = byteArrayOf(pad.toByte()) + "padded".toByteArray() + ByteArray(pad)
        h.client.frame(Http2Connection.DATA, Http2Connection.FLAG_PADDED or Http2Connection.FLAG_END_STREAM, st.id, payload)
        assertEquals("padded", got.get(5, TimeUnit.SECONDS))
    }

    @Test fun `unknown frame types and DATA for unknown streams are ignored`() {
        val h = harness({ it.response.sendHeaders(200, emptyList(), endStream = true) })
        h.client.frame(0xfa, 0, 0, byteArrayOf(1, 2, 3))
        h.client.frame(Http2Connection.DATA, 0, 99, byteArrayOf(1, 2, 3))
        assertEquals(200, h.client.get("/").status)
    }

    @Test fun `many streams run concurrently on one connection`() {
        val count = AtomicInteger()
        val h = harness({ req -> count.incrementAndGet(); req.response.sendHeaders(200, emptyList()); req.response.body.write(req.header(":path")!!.toByteArray()); req.response.finish() })
        val sts = (0 until 100).map { h.client.get("/s$it") }
        sts.forEachIndexed { i, st -> assertEquals("/s$i", String(st.bodyBytes())) }
        assertEquals(100, count.get())
    }

    @Test fun `a handler exception becomes RST_STREAM INTERNAL_ERROR and the connection survives`() {
        val h = harness({ req -> if (req.header(":path") == "/boom") error("boom") else req.response.sendHeaders(200, emptyList(), endStream = true) })
        val bad = h.client.get("/boom")
        assertEquals(Http2Connection.INTERNAL_ERROR, bad.reset.get(5, TimeUnit.SECONDS))
        assertEquals(200, h.client.get("/ok").status)
    }

    @Test fun `closing drains running requests first`() {
        val release = java.util.concurrent.CompletableFuture<Unit>()
        val h = harness({ req -> req.response.sendHeaders(200, emptyList()); release.get(); req.response.body.write("late".toByteArray()); req.response.finish() })
        val st = h.client.get("/")
        assertEquals(200, st.status)
        val closing = Thread { h.server.close(graceMs = 5_000) }.also { it.start() }
        Thread.sleep(200); assertTrue(!h.server.isClosed, "still draining")
        release.complete(Unit)
        assertEquals("late", String(st.bodyBytes())); closing.join(5_000)
        assertTrue(h.server.isClosed)
    }

    @Test fun `a bad connection preface closes the connection`() {
        val h = H2Harness({ }, sendPreface = false).also { open += it }
        h.client.frame(Http2Connection.SETTINGS, 0, 0, ByteArray(30)) // 39 bytes, none of them the preface
        h.closed.get(5, TimeUnit.SECONDS).let { assertNotNull(it) }
    }

    @Test fun `trailers after the body only end the stream`() {
        val got = java.util.concurrent.CompletableFuture<String>()
        val h = harness({ req -> got.complete(String(req.body.readBytes())); req.response.sendHeaders(200, emptyList(), endStream = true) })
        val st = h.client.openStreaming("POST", "/")
        h.client.data(st.id, "body".toByteArray(), endStream = false)
        val trailers = com.twitter.hpack.Encoder(4096).let { e -> java.io.ByteArrayOutputStream().also { b -> e.encodeHeader(b, "x-trailer".toByteArray(), "1".toByteArray(), false) }.toByteArray() }
        h.client.frame(Http2Connection.HEADERS, Http2Connection.FLAG_END_HEADERS or Http2Connection.FLAG_END_STREAM, st.id, trailers)
        assertEquals("body", got.get(5, TimeUnit.SECONDS))
    }
}
