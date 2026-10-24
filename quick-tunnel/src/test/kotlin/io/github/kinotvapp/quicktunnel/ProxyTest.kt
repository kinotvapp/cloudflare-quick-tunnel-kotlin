package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.security.MessageDigest
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProxyTest {
    private fun get(path: String, vararg h: Pair<String, String>, method: String = "GET") =
        connectRequestBytes("https://x.trycloudflare.com$path", 0, httpRequestMeta(method, "x.trycloudflare.com", *h))

    @Test fun `simple GET returns status headers and body`() {
        FakeOrigin { _, path, _, _, out -> out.respond("200 OK", "hello $path".toByteArray(), "Content-Type: text/plain"); true }.use { origin ->
            val pool = LocalPool(origin.port)
            val r = runProxy(get("/a?b=1"), origin.port, pool)
            assertEquals(200, r.status, "edge error: ${r.error}")
            assertEquals("text/plain", r.header("Content-Type"))
            assertEquals("hello /a?b=1", String(r.body))
            pool.close()
        }
    }

    @Test fun `request head is rebuilt from the edge metadata`() {
        var seen: Map<String, String> = emptyMap()
        FakeOrigin { _, _, headers, _, out -> seen = headers; out.respond("200 OK", ByteArray(0)); true }.use { origin ->
            val pool = LocalPool(origin.port)
            runProxy(get("/", "X-Custom" to "1", "Host" to "ignored.example"), origin.port, pool)
            assertEquals("x.trycloudflare.com", seen["host"], "Host comes from HttpHost, not from a header")
            assertEquals("1", seen["x-custom"])
            assertEquals("keep-alive", seen["connection"])
            pool.close()
        }
    }

    @Test fun `sequential requests reuse one pooled socket`() {
        FakeOrigin { _, _, _, _, out -> out.respond("200 OK", "ok".toByteArray()); true }.use { origin ->
            val pool = LocalPool(origin.port)
            repeat(3) { assertEquals(200, runProxy(get("/$it"), origin.port, pool).status) }
            assertEquals(1, origin.accepted, "one TCP connection serves all three requests")
            assertEquals(1, pool.idleCount())
            pool.close()
        }
    }

    @Test fun `a pooled socket the origin already closed is retried on a fresh one`() {
        FakeOrigin { _, _, _, _, out -> out.respond("200 OK", "ok".toByteArray()); true }.use { origin ->
            val pool = LocalPool(origin.port)
            assertEquals(200, runProxy(get("/1"), origin.port, pool).status)
            origin.closeClients()
            Thread.sleep(100)
            val r = runProxy(get("/2"), origin.port, pool)
            assertEquals(200, r.status, "edge error: ${r.error}")
            assertEquals(2, origin.accepted)
            pool.close()
        }
    }

    @Test fun `POST forwards exactly Content-Length bytes`() {
        val payload = ByteArray(300_000) { (it * 31).toByte() }
        FakeOrigin { _, _, _, body, out ->
            out.respond("200 OK", MessageDigest.getInstance("SHA-256").digest(body)); true
        }.use { origin ->
            val pool = LocalPool(origin.port)
            val req = connectRequestBytes("https://x.trycloudflare.com/up", 0, httpRequestMeta("POST", "x.trycloudflare.com", "Content-Length" to payload.size.toString())) + payload
            val metrics = TunnelMetrics()
            val r = runProxy(req, origin.port, pool, metrics)
            assertContentEquals(MessageDigest.getInstance("SHA-256").digest(payload), r.body)
            assertEquals(payload.size.toLong(), metrics.bytesIn.get())
            pool.close()
        }
    }

    @Test fun `HEAD does not wait for a body its Content-Length promises`() {
        FakeOrigin { _, _, _, _, out -> out.write("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n".toByteArray()); true }.use { origin ->
            val pool = LocalPool(origin.port)
            val r = runProxy(get("/", method = "HEAD"), origin.port, pool)
            assertEquals(200, r.status)
            assertEquals(0, r.body.size)
            assertEquals(1, pool.idleCount(), "the socket is still reusable")
            pool.close()
        }
    }

    @Test fun `204 and 304 end without a body and keep the socket`() {
        for (status in listOf("204 No Content", "304 Not Modified")) {
            FakeOrigin { _, _, _, _, out -> out.write("HTTP/1.1 $status\r\n\r\n".toByteArray()); true }.use { origin ->
                val pool = LocalPool(origin.port)
                assertEquals(status.take(3).toInt(), runProxy(get("/"), origin.port, pool).status)
                assertEquals(1, pool.idleCount())
                pool.close()
            }
        }
    }

    @Test fun `chunked response is decoded and the header dropped`() {
        FakeOrigin { _, _, _, _, out ->
            out.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".toByteArray()); false
        }.use { origin ->
            val pool = LocalPool(origin.port)
            val r = runProxy(get("/"), origin.port, pool)
            assertEquals("hello world", String(r.body))
            assertNull(r.header("Transfer-Encoding"), "the edge does not re-chunk, so the header must not reach it")
            assertEquals(0, pool.idleCount(), "close-delimited responses are never pooled")
            pool.close()
        }
    }

    @Test fun `response without length is read until the origin closes`() {
        FakeOrigin { _, _, _, _, out -> out.write("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil-eof".toByteArray()); false }.use { origin ->
            val pool = LocalPool(origin.port)
            assertEquals("until-eof", String(runProxy(get("/"), origin.port, pool).body))
            pool.close()
        }
    }

    @Test fun `connection refused becomes a 502 with the reason`() {
        val closedPort = ServerSocket(0).use { it.localPort }
        val pool = LocalPool(closedPort)
        val r = runProxy(get("/"), closedPort, pool)
        assertEquals(502, r.status)
        assertTrue(r.error.startsWith("local connect"), r.error)
    }

    @Test fun `WebSocket-style upgrade pumps both directions without pooling`() {
        val server = ServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) {
            server.accept().use { s ->
                val i = s.getInputStream(); val buf = ByteArrayOutputStream()
                while (!buf.toString(Charsets.ISO_8859_1).contains("\r\n\r\n")) buf.write(i.read())
                s.getOutputStream().write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".toByteArray())
                val echo = i.readBytes() // until the proxy half-closes after the edge's bytes
                s.getOutputStream().write("echo:".toByteArray() + echo)
            }
        }
        val pool = LocalPool(server.localPort)
        val head = connectRequestBytes("https://x.trycloudflare.com/ws", 0, httpRequestMeta("GET", "x.trycloudflare.com", "Connection" to "Upgrade", "Upgrade" to "websocket"))
        val out = ByteArrayOutputStream()
        proxyConnection(ByteArrayInputStream(head + "ping".toByteArray()), out, server.localPort, pool, TunnelMetrics())
        val r = parseEdgeResponse(out.toByteArray())
        assertEquals(101, r.status)
        assertEquals("echo:ping", String(r.body))
        assertEquals(0, pool.idleCount())
        server.close()
    }

    @Test fun `TCP streams are piped raw`() {
        val server = ServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) { server.accept().use { s -> val d = s.getInputStream().readBytes(); s.getOutputStream().write(d.reversedArray()) } }
        val out = ByteArrayOutputStream()
        proxyConnection(ByteArrayInputStream(connectRequestBytes("127.0.0.1:1", 2, emptyList()) + "abc".toByteArray()), out, server.localPort, LocalPool(server.localPort), TunnelMetrics())
        assertEquals("cba", String(parseEdgeResponse(out.toByteArray()).body))
        server.close()
    }

    @Test fun `metrics count streams and bytes`() {
        FakeOrigin { _, _, _, _, out -> out.respond("200 OK", ByteArray(1000)); true }.use { origin ->
            val pool = LocalPool(origin.port); val m = TunnelMetrics()
            runProxy(get("/"), origin.port, pool, m)
            assertEquals(1, m.streams.get()); assertEquals(1000, m.bytesOut.get())
            pool.close()
        }
    }
}
