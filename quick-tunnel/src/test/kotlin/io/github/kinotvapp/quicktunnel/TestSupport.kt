package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/** A request as the edge would describe it: method, host and headers in the metadata. */
fun httpRequestMeta(method: String, host: String, vararg headers: Pair<String, String>) =
    listOf(HTTP_METHOD_KEY to method, HTTP_HOST_KEY to host) + headers.map { "$HTTP_HEADER:${it.first}" to it.second }

class EdgeResponse(val status: Int, val headers: List<Pair<String, String>>, val error: String, val body: ByteArray) {
    fun header(name: String) = headers.firstOrNull { it.first.equals(name, true) }?.second
}

/** Captures what the proxy would put on the wire, whatever the transport. */
class RecordingSink : ResponseSink {
    private var status = 0
    private var headers: List<Pair<String, String>> = emptyList()
    private var error = ""
    override val body = ByteArrayOutputStream()
    override fun head(status: Int, headers: List<Pair<String, String>>) { this.status = status; this.headers = headers }
    override fun error(status: Int, message: String) { this.status = status; error = message }
    override fun finish() {}
    fun response() = EdgeResponse(status, headers, error, body.toByteArray())
}

/** Runs one request through [serve] + [proxyHttp] exactly as the HTTP/2 router does. [edgeBody] is what the edge sends after the head. */
fun runProxy(req: ConnectReq, @Suppress("UNUSED_PARAMETER") port: Int, pool: LocalPool, metrics: TunnelMetrics = TunnelMetrics(), edgeBody: ByteArray = ByteArray(0)): EdgeResponse {
    val sink = RecordingSink()
    serve(sink, metrics) { started -> proxyHttp(ByteArrayInputStream(edgeBody), sink, req, pool, metrics, started) }
    return sink.response()
}

/** A tiny HTTP/1.1 origin: each accepted socket serves requests with [handler] until it closes. */
class FakeOrigin(val handler: (method: String, path: String, headers: Map<String, String>, body: ByteArray, out: java.io.OutputStream) -> Boolean) : AutoCloseable {
    val server = ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
    val port get() = server.localPort
    @Volatile var accepted = 0
    // Iterated by closeClients() while the accept thread appends: a plain synchronized list throws ConcurrentModificationException.
    private val sockets = java.util.concurrent.CopyOnWriteArrayList<Socket>()

    init {
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val s = try { server.accept() } catch (_: Exception) { break }
                sockets += s; accepted++ // register before counting, so a test that waits on `accepted` can close it
                thread(isDaemon = true) { serve(s) }
            }
        }
    }

    private fun serve(s: Socket) = try {
        val inp = s.getInputStream().buffered()
        while (true) {
            val first = readLine(inp) ?: break
            val (method, path) = first.split(' ').let { it[0] to it[1] }
            val headers = mutableMapOf<String, String>()
            while (true) { val l = readLine(inp) ?: break; if (l.isEmpty()) break; headers[l.substringBefore(':').lowercase()] = l.substringAfter(':').trim() }
            val body = if (headers["transfer-encoding"]?.contains("chunked", true) == true) ChunkedInputStream(inp).readBytes()
                else headers["content-length"]?.toInt()?.let { n -> ByteArray(n).also { inp.readFully(it) } } ?: ByteArray(0)
            val keep = handler(method, path, headers, body, s.getOutputStream())
            s.getOutputStream().flush()
            if (!keep) break
        }
        s.close()
    } catch (_: Exception) { runCatching { s.close() } }

    private fun readLine(i: java.io.InputStream): String? {
        val sb = StringBuilder()
        while (true) { val c = i.read(); if (c < 0) return if (sb.isEmpty()) null else sb.toString(); if (c == '\n'.code) return sb.toString().trimEnd('\r'); sb.append(c.toChar()) }
    }

    /** A client's connect() completes in the kernel backlog before this thread has accepted it: wait for the accept. */
    fun awaitAccepted(n: Int) { val end = System.currentTimeMillis() + 5000; while (accepted < n && System.currentTimeMillis() < end) Thread.sleep(5); check(accepted >= n) { "origin accepted $accepted of $n connections" } }

    fun closeClients() = sockets.forEach { runCatching { it.close() } }
    override fun close() { runCatching { server.close() }; closeClients() }
}

fun java.io.OutputStream.respond(status: String, body: ByteArray, vararg headers: String) {
    write(("HTTP/1.1 $status\r\n" + headers.joinToString("") { "$it\r\n" } + "Content-Length: ${body.size}\r\n\r\n").toByteArray()); write(body)
}
