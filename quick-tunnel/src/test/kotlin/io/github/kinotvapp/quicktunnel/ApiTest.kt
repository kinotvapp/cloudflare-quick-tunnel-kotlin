package io.github.kinotvapp.quicktunnel

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ApiTest {
    private val hits = AtomicInteger()
    private var userAgent: String? = null
    private var contentType: String? = null
    private var server: HttpServer? = null

    private fun serve(vararg replies: Pair<Int, String>): String {
        val queue = replies.toMutableList()
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        s.createContext("/tunnel") { ex ->
            hits.incrementAndGet(); userAgent = ex.requestHeaders.getFirst("User-Agent"); contentType = ex.requestHeaders.getFirst("Content-Type")
            check(ex.requestMethod == "POST")
            val (code, body) = if (queue.size > 1) queue.removeAt(0) else queue[0]
            val bytes = body.toByteArray(); ex.sendResponseHeaders(code, bytes.size.toLong()); ex.responseBody.use { it.write(bytes) }
        }
        s.start(); server = s
        return "http://127.0.0.1:${s.address.port}"
    }

    @AfterTest fun stop() { server?.stop(0) }

    private val ok = """{"success":true,"result":{"id":"8f6d3c2a-1111-4d2e-9b9b-aaaaaaaaaaaa","name":"quick-tunnel-abc","hostname":"abc-123.trycloudflare.com","account_tag":"deadbeefcafef00d","secret":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},"errors":[]}"""
    private val noSleep: (Long) -> Unit = {}

    @Test fun `happy path parses credentials and sends the expected headers`() {
        val t = requestTunnel(serve(200 to ok), sleep = noSleep)
        assertEquals("abc-123.trycloudflare.com", t.hostname); assertEquals("https://abc-123.trycloudflare.com", t.url)
        assertEquals("deadbeefcafef00d", t.accountTag); assertEquals(32, t.secret.size); assertEquals(1, t.secret[0].toInt())
        assertEquals(DEFAULT_USER_AGENT, userAgent); assertEquals("application/json", contentType)
    }

    @Test fun `custom user agent is sent`() {
        requestTunnel(serve(200 to ok), userAgent = "kino/1", sleep = noSleep)
        assertEquals("kino/1", userAgent)
    }

    @Test fun `business error is surfaced and not retried`() {
        val e = assertFailsWith<TunnelException.ApiBusiness> { requestTunnel(serve(200 to """{"success":false,"errors":[{"code":1003,"message":"tunnel quota exceeded"}]}"""), sleep = noSleep) }
        assertEquals(listOf(ApiError(1003, "tunnel quota exceeded")), e.errors); assertEquals(1, hits.get()); assertFalse(e.transient)
    }

    @Test fun `HTML body from a rate limit keeps a readable snippet and is not retried on 4xx`() {
        val e = assertFailsWith<TunnelException.ApiNonJson> { requestTunnel(serve(429 to "<html><body>rate limited</body></html>"), sleep = noSleep) }
        assertEquals(429, e.status); assertTrue("rate limited" in e.bodySnippet); assertEquals(1, hits.get())
    }

    @Test fun `5xx is retried with growing backoff then succeeds`() {
        val sleeps = mutableListOf<Long>()
        val t = requestTunnel(serve(503 to "service unavailable", 503 to "again", 200 to ok), sleep = { sleeps += it })
        assertEquals("abc-123.trycloudflare.com", t.hostname); assertEquals(3, hits.get()); assertEquals(listOf(1000L, 2000L), sleeps)
    }

    @Test fun `5xx forever gives up after the retry budget`() {
        assertFailsWith<TunnelException.ApiNonJson> { requestTunnel(serve(500 to "boom"), sleep = noSleep) }
        assertEquals(MAX_API_RETRIES + 1, hits.get())
    }

    @Test fun `4xx JSON error is a business error and is not retried`() {
        assertFailsWith<TunnelException.ApiBusiness> { requestTunnel(serve(400 to """{"success":false,"errors":[{"code":400,"message":"bad request"}]}"""), sleep = noSleep) }
        assertEquals(1, hits.get())
    }

    @Test fun `success without result and a bad uuid are internal errors`() {
        assertFailsWith<TunnelException.Internal> { requestTunnel(serve(200 to """{"success":true}"""), sleep = noSleep) }
        assertFailsWith<TunnelException.Internal> { requestTunnel(serve(200 to ok.replace("8f6d3c2a-1111-4d2e-9b9b-aaaaaaaaaaaa", "not-a-uuid")), sleep = noSleep) }
    }

    @Test fun `an unreachable API is a transient network error`() {
        val e = assertFailsWith<TunnelException.Api> { requestTunnel("http://127.0.0.1:1", timeoutMs = 500, sleep = noSleep) }
        assertTrue(e.transient)
    }
}
