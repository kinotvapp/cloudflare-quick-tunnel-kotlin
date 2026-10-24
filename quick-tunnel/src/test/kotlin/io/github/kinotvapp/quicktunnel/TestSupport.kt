package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/** Builds what the edge writes on a request stream: signature + version + capnp ConnectRequest. */
fun connectRequestBytes(dest: String, type: Int, metadata: List<Pair<String, String>>): ByteArray {
    val frame = CapnpBuilder().apply {
        val root = root(1, 2)
        text(root + 1, dest); u16(root, 0, type)
        val list = structList(root + 2, metadata.size, 0, 2)
        metadata.forEachIndexed { n, (k, v) -> text(list + n * 2, k); text(list + n * 2 + 1, v) }
    }.frame()
    return DATA_SIG + "01".toByteArray() + frame
}

fun httpRequestMeta(method: String, host: String, vararg headers: Pair<String, String>) =
    listOf(HTTP_METHOD_KEY to method, HTTP_HOST_KEY to host) + headers.map { "$HTTP_HEADER:${it.first}" to it.second }

class EdgeResponse(val error: String, val metadata: List<Pair<String, String>>, val body: ByteArray) {
    val status get() = metadata.first { it.first == HTTP_STATUS_KEY }.second.toInt()
    fun header(name: String) = metadata.firstOrNull { it.first.equals("$HTTP_HEADER:$name", true) }?.second
}

/** Parses what we write back to the edge: preamble + ConnectResponse + raw body. */
fun parseEdgeResponse(bytes: ByteArray): EdgeResponse {
    val inp = ByteArrayInputStream(bytes)
    val sig = ByteArray(6).also { inp.readFully(it) }
    check(sig.contentEquals(DATA_SIG)) { "bad signature" }
    ByteArray(2).also { inp.readFully(it) }
    val root = CapnpMessage.read(inp).root()!!
    val meta = root.structList(1).map { (it.text(0) ?: "") to (it.text(1) ?: "") }
    return EdgeResponse(root.text(0) ?: "", meta, inp.readBytes())
}

/** Runs one request through proxyConnection exactly as a QUIC stream would. */
fun runProxy(request: ByteArray, port: Int, pool: LocalPool, metrics: TunnelMetrics = TunnelMetrics()): EdgeResponse {
    val out = ByteArrayOutputStream()
    proxyConnection(ByteArrayInputStream(request), out, port, pool, metrics)
    return parseEdgeResponse(out.toByteArray())
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
