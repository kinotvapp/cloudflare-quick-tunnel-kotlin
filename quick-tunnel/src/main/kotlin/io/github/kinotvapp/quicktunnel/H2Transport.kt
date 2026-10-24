package io.github.kinotvapp.quicktunnel

import java.util.concurrent.CompletableFuture

/** Headers cloudflared and the edge use to tell HTTP/2 requests apart (connection/http2.go, connection/header.go). */
internal object H2Headers {
    const val UPGRADE = "cf-cloudflared-proxy-connection-upgrade"
    const val TCP_SRC = "cf-cloudflared-proxy-src"
    const val RESPONSE_USER_HEADERS = "cf-cloudflared-response-headers"
    const val RESPONSE_META = "cf-cloudflared-response-meta"
    const val CONTROL_STREAM = "control-stream"
    const val WEBSOCKET = "websocket"
    const val CONFIGURATION = "update-configuration"
    const val META_ORIGIN = """{"src":"origin"}"""
    const val META_CLOUDFLARED = """{"src":"cloudflared"}"""

    /** The edge reads user response headers from one serialized header, not from real HTTP/2 headers. */
    fun isControlHeader(lowerName: String) =
        lowerName.startsWith(":") || lowerName.startsWith("cf-int-") || lowerName.startsWith("cf-cloudflared-") || lowerName.startsWith("cf-proxy-")

    fun isWebsocketClientHeader(lowerName: String) = lowerName == "sec-websocket-accept" || lowerName == "connection" || lowerName == "upgrade"

    /** `name:value;name:value`, each side base64 without padding. Header values are bytes: ISO-8859-1 keeps them lossless. */
    fun serialize(headers: List<Pair<String, String>>): String = headers.joinToString(";") { (n, v) ->
        Base64Lite.encode(n.toByteArray(Charsets.ISO_8859_1), padded = false) + ":" + Base64Lite.encode(v.toByteArray(Charsets.ISO_8859_1), padded = false)
    }

    fun deserialize(text: String): List<Pair<String, String>> = text.split(';').filter { it.isNotEmpty() }.map {
        val (n, v) = it.split(':').also { parts -> require(parts.size == 2) { "Unable to deserialize headers" } }
        String(Base64Lite.decode(n), Charsets.ISO_8859_1) to String(Base64Lite.decode(v), Charsets.ISO_8859_1)
    }
}

/** HTTP/2: the status and headers are real frames; user headers travel serialized inside one header. */
class H2Sink(private val resp: Http2Response) : ResponseSink {
    override fun head(status: Int, headers: List<Pair<String, String>>) {
        val out = ArrayList<Pair<String, String>>()
        headers.filter { it.first.equals("content-length", true) }.forEach { out += "content-length" to it.second }
        val user = headers.filter { val n = it.first.lowercase(); !H2Headers.isControlHeader(n) || H2Headers.isWebsocketClientHeader(n) }
        out += H2Headers.RESPONSE_USER_HEADERS to H2Headers.serialize(user)
        out += H2Headers.RESPONSE_META to H2Headers.META_ORIGIN
        // 101 cannot exist in HTTP/2: the upgrade is acknowledged with 200 and the stream becomes the tunnel.
        resp.sendHeaders(if (status == 101) 200 else status, out)
    }

    override fun error(status: Int, message: String) =
        resp.sendHeaders(status, listOf(H2Headers.RESPONSE_META to H2Headers.META_CLOUDFLARED), endStream = true)

    override fun acceptTcp() = error(502, "TCP streams are not supported over HTTP/2")
    override val body get() = resp.body
    override fun finish() { runCatching { resp.finish() } }
}

/** What an HTTP/2 connection needs to serve what the edge opens on it. */
internal class H2Context(val localPort: Int, val pool: LocalPool, val metrics: TunnelMetrics) {
    /** The edge opens the control stream first thing; registration happens on it. */
    val control = CompletableFuture<Http2Request>()
    /** Keeps the control stream's handler thread alive until the link is closed. */
    val release = CompletableFuture<Unit>()
}

internal fun routeH2(req: Http2Request, ctx: H2Context) {
    when (req.header(H2Headers.UPGRADE)) {
        H2Headers.CONTROL_STREAM -> {
            ctx.control.complete(req)
            ctx.release.get()
        }
        H2Headers.CONFIGURATION -> {
            req.body.readBytes()
            val sink = H2Sink(req.response)
            req.response.sendHeaders(200, listOf(H2Headers.RESPONSE_META to H2Headers.META_CLOUDFLARED))
            req.response.body.write("""{"lastAppliedVersion":-1,"err":"remote configuration is not supported"}""".toByteArray())
            sink.finish()
        }
        else -> {
            val sink = H2Sink(req.response)
            if (req.header(H2Headers.TCP_SRC) != null) serve(sink, ctx.metrics) { sink.acceptTcp() }
            else serve(sink, ctx.metrics) { started -> proxyHttp(req.body, sink, toConnectReq(req), ctx.pool, ctx.metrics, started) }
        }
    }
}

/** Rebuilds the HTTP/1.1 request the origin expects from the HTTP/2 pseudo-headers and headers. */
internal fun toConnectReq(req: Http2Request): ConnectReq {
    val websocket = req.header(H2Headers.UPGRADE) == H2Headers.WEBSOCKET
    val regular = req.headers.filter { !it.first.startsWith(":") && !it.first.startsWith("cf-cloudflared-") }
    // A body of unknown length (no Content-Length) has to be re-chunked for HTTP/1.1.
    val chunk = !req.endStream && regular.none { it.first == "content-length" } && !websocket
    val metadata = ArrayList<Pair<String, String>>()
    metadata += HTTP_METHOD_KEY to (req.header(":method") ?: "GET")
    metadata += HTTP_HOST_KEY to (req.header(":authority") ?: "")
    regular.forEach { metadata += "$HTTP_HEADER:${it.first}" to it.second }
    if (chunk) metadata += "$HTTP_HEADER:Transfer-Encoding" to "chunked"
    if (websocket) { // hop-by-hop headers cannot exist in HTTP/2, so the edge drops them; the origin needs them back
        if (regular.none { it.first == "connection" }) metadata += "$HTTP_HEADER:Connection" to "Upgrade"
        if (regular.none { it.first == "upgrade" }) metadata += "$HTTP_HEADER:Upgrade" to "websocket"
    }
    return ConnectReq(req.header(":path") ?: "/", 0, metadata, chunkRequestBody = chunk)
}
