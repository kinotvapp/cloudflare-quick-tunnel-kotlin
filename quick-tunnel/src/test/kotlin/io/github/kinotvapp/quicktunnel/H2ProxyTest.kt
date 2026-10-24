package io.github.kinotvapp.quicktunnel

import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The HTTP/2 transport end to end: a mini edge sends requests, [routeH2] proxies them to a real local origin. */
class H2ProxyTest {
    private val open = mutableListOf<AutoCloseable>()
    @AfterTest fun cleanup() = open.forEach { runCatching { it.close() } }

    private fun setup(origin: FakeOrigin?, port: Int = origin!!.port): Triple<H2Harness, TunnelMetrics, LocalPool> {
        val metrics = TunnelMetrics(); val pool = LocalPool(port)
        val ctx = H2Context(port, pool, metrics)
        open += AutoCloseable { pool.close() }
        val h = H2Harness({ routeH2(it, ctx) }).also { open += it }
        return Triple(h, metrics, pool)
    }

    private fun userHeaders(st: MiniH2Client.ClientStream) = H2Headers.deserialize(st.header(H2Headers.RESPONSE_USER_HEADERS) ?: "")

    @Test fun `GET returns the status, real content-length, serialized user headers and the origin meta`() {
        FakeOrigin { _, path, _, _, out -> out.respond("200 OK", "hello $path".toByteArray(), "Content-Type: text/plain", "Set-Cookie: a=1", "Set-Cookie: b=2"); true }.use { o ->
            val (h, _, _) = setup(o)
            val st = h.client.get("/greet?x=1")
            assertEquals(200, st.status)
            assertEquals("hello /greet?x=1", String(st.bodyBytes()))
            assertEquals("11".let { "hello /greet?x=1".length.toString() }, st.header("content-length"))
            assertEquals(H2Headers.META_ORIGIN, st.header(H2Headers.RESPONSE_META))
            val user = userHeaders(st)
            assertEquals("text/plain", user.first { it.first.equals("Content-Type", true) }.second)
            assertEquals(listOf("a=1", "b=2"), user.filter { it.first.equals("Set-Cookie", true) }.map { it.second }, "repeated headers survive")
            assertNull(st.header("content-type"), "user headers are not real HTTP/2 headers")
        }
    }

    @Test fun `the origin sees an HTTP 1 1 request rebuilt from pseudo-headers without internal headers`() {
        var seen: Map<String, String> = emptyMap(); var method = ""; var path = ""
        FakeOrigin { m, p, headers, _, out -> method = m; path = p; seen = headers; out.respond("200 OK", ByteArray(0)); true }.use { o ->
            val (h, _, _) = setup(o)
            h.client.get("/a/b?q=1", "x-custom" to "yes", "cf-cloudflared-secret" to "internal", "cf-ray" to "abc").bodyBytes()
            assertEquals("GET", method); assertEquals("/a/b?q=1", path)
            assertEquals("x.trycloudflare.com", seen["host"]); assertEquals("yes", seen["x-custom"]); assertEquals("abc", seen["cf-ray"])
            assertTrue(seen.keys.none { it.startsWith("cf-cloudflared") }, "internal headers must not reach the origin")
        }
    }

    @Test fun `statuses pass through`() {
        for (code in listOf("404 Not Found", "302 Found", "500 Internal Server Error")) {
            FakeOrigin { _, _, _, _, out -> out.respond(code, ByteArray(0)); true }.use { o ->
                assertEquals(code.take(3).toInt(), setup(o).first.client.get("/").status)
            }
        }
    }

    @Test fun `POST with Content-Length is forwarded byte for byte`() {
        val payload = ByteArray(400_000) { (it * 13).toByte() }
        FakeOrigin { _, _, _, body, out -> out.respond("200 OK", java.security.MessageDigest.getInstance("SHA-256").digest(body)); true }.use { o ->
            val (h, m, _) = setup(o)
            val st = h.client.request("POST", "/up", listOf("content-length" to payload.size.toString()), payload)
            assertContentEquals(java.security.MessageDigest.getInstance("SHA-256").digest(payload), st.bodyBytes())
            assertEquals(payload.size.toLong(), m.bytesIn.get())
        }
    }

    @Test fun `a request body of unknown length is re-chunked for the origin`() {
        val payload = ByteArray(150_000) { (it * 3).toByte() }
        var te: String? = null
        FakeOrigin { _, _, headers, body, out -> te = headers["transfer-encoding"]; out.respond("200 OK", java.security.MessageDigest.getInstance("SHA-256").digest(body)); true }.use { o ->
            val (h, _, _) = setup(o)
            val st = h.client.request("POST", "/stream", emptyList(), payload) // no content-length header
            assertContentEquals(java.security.MessageDigest.getInstance("SHA-256").digest(payload), st.bodyBytes())
            assertEquals("chunked", te)
        }
    }

    @Test fun `a chunked origin response is decoded and Transfer-Encoding is not forwarded`() {
        FakeOrigin { _, _, _, _, out ->
            out.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".toByteArray()); false
        }.use { o ->
            val st = setup(o).first.client.get("/")
            assertEquals("hello world", String(st.bodyBytes()))
            assertTrue(userHeaders(st).none { it.first.equals("Transfer-Encoding", true) })
            assertNull(st.header("content-length"))
        }
    }

    @Test fun `HEAD returns headers and no body without waiting for the advertised length`() {
        FakeOrigin { _, _, _, _, out -> out.write("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n".toByteArray()); true }.use { o ->
            val st = setup(o).first.client.request("HEAD", "/", emptyList(), null)
            assertEquals(200, st.status); assertEquals(0, st.bodyBytes().size)
        }
    }

    @Test fun `a large response is paced by the edge's flow control windows`() {
        val big = ByteArray(3_000_000) { (it % 251).toByte() }
        FakeOrigin { _, _, _, _, out -> out.respond("200 OK", big); true }.use { o ->
            val st = setup(o).first.client.get("/")
            assertContentEquals(big, st.bodyBytes())
        }
    }

    @Test fun `an unreachable origin is a 502 attributed to cloudflared`() {
        val closed = ServerSocket(0).use { it.localPort }
        val (h, _, _) = setup(null, closed)
        val st = h.client.get("/")
        assertEquals(502, st.status); assertEquals(H2Headers.META_CLOUDFLARED, st.header(H2Headers.RESPONSE_META)); assertEquals(0, st.bodyBytes().size)
    }

    @Test fun `TCP streams are refused over HTTP2`() {
        FakeOrigin { _, _, _, _, out -> out.respond("200 OK", ByteArray(0)); true }.use { o ->
            assertEquals(502, setup(o).first.client.get("/", H2Headers.TCP_SRC to "1.2.3.4:5").status)
        }
    }

    @Test fun `remote configuration updates are answered, not applied`() {
        FakeOrigin { _, _, _, _, out -> out.respond("200 OK", ByteArray(0)); true }.use { o ->
            val st = setup(o).first.client.request("POST", "/", listOf(H2Headers.UPGRADE to H2Headers.CONFIGURATION), """{"version":3,"config":{}}""".toByteArray())
            assertEquals(200, st.status)
            assertTrue("not supported" in String(st.bodyBytes()))
        }
    }

    @Test fun `websocket upgrade restores the hop-by-hop headers and pumps both ways`() {
        val server = ServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"))
        val originSaw = java.util.concurrent.CompletableFuture<String>()
        thread(isDaemon = true) {
            server.accept().use { s ->
                val i = s.getInputStream(); val buf = java.io.ByteArrayOutputStream()
                while (!buf.toString(Charsets.ISO_8859_1).contains("\r\n\r\n")) buf.write(i.read())
                originSaw.complete(buf.toString(Charsets.ISO_8859_1))
                s.getOutputStream().write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc\r\n\r\n".toByteArray())
                val b = ByteArray(1024)
                while (true) { val n = i.read(b); if (n < 0) break; s.getOutputStream().write("echo:".toByteArray() + b.copyOf(n)); s.getOutputStream().flush() }
            }
        }
        val (h, _, _) = setup(null, server.localPort)
        val st = h.client.openStreaming("GET", "/ws", listOf(H2Headers.UPGRADE to H2Headers.WEBSOCKET, "sec-websocket-key" to "k", "sec-websocket-version" to "13"))
        assertEquals(200, st.status, "101 does not exist in HTTP/2")
        val head = originSaw.get(5, TimeUnit.SECONDS).lowercase()
        assertTrue("connection: upgrade" in head && "upgrade: websocket" in head && "sec-websocket-key: k" in head, head)
        assertTrue("cf-cloudflared" !in head)
        val user = userHeaders(st).map { it.first.lowercase() }
        assertTrue("sec-websocket-accept" in user && "connection" in user && "upgrade" in user, "websocket client headers must reach the edge: $user")
        val out = h.client.outputOf(st); val inp = h.client.inputOf(st)
        out.write("ping".toByteArray())
        val buf = ByteArray(32); val n = inp.read(buf)
        assertEquals("echo:ping", String(buf, 0, n))
        out.write("again".toByteArray())
        val n2 = inp.read(buf); assertEquals("echo:again", String(buf, 0, n2))
        server.close()
    }

    @Test fun `parallel requests share one connection and one pool`() {
        FakeOrigin { _, path, _, _, out -> out.respond("200 OK", path.toByteArray()); true }.use { o ->
            val (h, m, _) = setup(o)
            val sts = (0 until 60).map { h.client.get("/r$it") }
            sts.forEachIndexed { i, st -> assertEquals("/r$i", String(st.bodyBytes())) }
            assertEquals(60, m.streams.get())
        }
    }

    // The edge may send a GET as HEADERS (no END_STREAM) followed by an empty DATA(END_STREAM).
    private fun getWithLateEnd(h: H2Harness, path: String, delayMs: Long): MiniH2Client.ClientStream {
        val st = h.client.openStreaming("GET", path)
        Thread.sleep(delayMs)
        h.client.data(st.id, ByteArray(0), endStream = true)
        return st
    }

    @Test fun `a GET whose END_STREAM arrives in a separate empty DATA frame is not sent as chunked`() {
        val seen = java.util.concurrent.CompletableFuture<Map<String, String>>()
        FakeOrigin { _, _, headers, _, out -> seen.complete(headers); out.respond("200 OK", "ok".toByteArray()); true }.use { o ->
            val (h, _, _) = setup(o)
            val st = getWithLateEnd(h, "/late", delayMs = 30)
            assertEquals("ok", String(st.bodyBytes()))
            val headers = seen.get(5, TimeUnit.SECONDS)
            assertNull(headers["transfer-encoding"], "an empty body must not turn into a chunked request: $headers")
            assertNull(headers["content-length"])
        }
    }

    @Test fun `a body that really follows HEADERS is still re-chunked`() {
        var te: String? = null
        FakeOrigin { _, _, headers, body, out -> te = headers["transfer-encoding"]; out.respond("200 OK", body); true }.use { o ->
            val (h, _, _) = setup(o)
            val st = h.client.openStreaming("POST", "/slow")
            Thread.sleep(30)
            h.client.data(st.id, "payload".toByteArray(), endStream = true)
            assertEquals("payload", String(st.bodyBytes())); assertEquals("chunked", te)
        }
    }

    @Test fun `when the first byte is slower than the probe the request falls back to chunked`() {
        var te: String? = null
        FakeOrigin { _, _, headers, _, out -> te = headers["transfer-encoding"]; out.respond("200 OK", ByteArray(0)); true }.use { o ->
            val (h, _, _) = setup(o)
            val st = getWithLateEnd(h, "/very-late", delayMs = BODY_PROBE_MS + 300)
            st.bodyBytes()
            assertEquals("chunked", te, "undecided after the probe: safe default is a chunked request that ends right away")
        }
    }
}
