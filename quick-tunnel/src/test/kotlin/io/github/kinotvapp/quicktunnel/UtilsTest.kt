package io.github.kinotvapp.quicktunnel

import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UtilsTest {
    @Test fun `Base64Lite matches java's encoder and decoder for every length`() {
        val r = Random(42)
        for (n in 0..300) {
            val data = ByteArray(n).also { r.nextBytes(it) }
            val padded = java.util.Base64.getEncoder().encodeToString(data)
            val raw = java.util.Base64.getEncoder().withoutPadding().encodeToString(data)
            assertEquals(padded, Base64Lite.encode(data, padded = true)); assertEquals(raw, Base64Lite.encode(data, padded = false))
            assertContentEquals(data, Base64Lite.decode(padded)); assertContentEquals(data, Base64Lite.decode(raw))
        }
    }

    @Test fun `Base64Lite rejects characters outside the alphabet`() {
        assertFailsWith<IllegalArgumentException> { Base64Lite.decode("ab*d") }
        assertFailsWith<IllegalArgumentException> { Base64Lite.decode("é") }
    }

    @Test fun `the tunnel secret from the API decodes to its 32 bytes`() {
        val b = Base64Lite.decode("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
        assertEquals(32, b.size); assertEquals(1, b[0].toInt()); assertEquals(32, b[31].toInt())
    }

    @Test fun `serialized headers use raw base64 pairs like cloudflared`() {
        assertEquals("YQ:Yg", H2Headers.serialize(listOf("a" to "b")))
        assertEquals("", H2Headers.serialize(emptyList()))
        val h = listOf("Content-Type" to "text/plain; charset=utf-8", "Set-Cookie" to "a=1; Path=/", "Set-Cookie" to "b=é")
        assertEquals(h, H2Headers.deserialize(H2Headers.serialize(h)))
    }

    @Test fun `deserialize rejects malformed pairs`() {
        assertFailsWith<IllegalArgumentException> { H2Headers.deserialize("YQ:Yg:extra") }
        assertFailsWith<IllegalArgumentException> { H2Headers.deserialize("justone") }
    }

    @Test fun `control headers are hidden from the origin response except websocket ones`() {
        listOf(":status", "cf-int-x", "cf-cloudflared-anything", "cf-proxy-y").forEach { assertTrue(H2Headers.isControlHeader(it), it) }
        listOf("content-type", "set-cookie", "x-custom").forEach { assertFalse(H2Headers.isControlHeader(it), it) }
        assertTrue(H2Headers.isWebsocketClientHeader("connection")); assertTrue(H2Headers.isWebsocketClientHeader("sec-websocket-accept"))
        assertFalse(H2Headers.isWebsocketClientHeader("content-type"))
    }

    @Test fun `copyChunked frames a body of unknown length`() {
        val out = java.io.ByteArrayOutputStream()
        copyChunked(java.io.ByteArrayInputStream("hello world".toByteArray()), out, java.util.concurrent.atomic.AtomicLong())
        assertEquals("b\r\nhello world\r\n0\r\n\r\n", out.toString())
        assertEquals("hello world", String(ChunkedInputStream(java.io.ByteArrayInputStream(out.toByteArray())).readBytes()))
    }

    @Test fun `HPACK integer encoding crosses the prefix boundary`() {
        fun enc(v: Int) = java.io.ByteArrayOutputStream().also { Http2Connection.writeInt(it, v, 7, 0) }.toByteArray().map { it.toInt() and 0xff }
        assertEquals(listOf(10), enc(10)); assertEquals(listOf(126), enc(126))
        assertEquals(listOf(127, 0), enc(127)); assertEquals(listOf(127, 1), enc(128)); assertEquals(listOf(127, 0x80 or 0x7f, 0x01), enc(127 + 255))
    }
}
