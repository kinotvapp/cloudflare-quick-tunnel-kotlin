package io.github.kinotvapp.quicktunnel

import tech.kwik.core.QuicStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

val DATA_SIG = byteArrayOf(0x0A, 0x36, 0xCD.toByte(), 0x12, 0xA1.toByte(), 0x3E)
const val HTTP_HEADER = "HttpHeader"
const val HTTP_METHOD_KEY = "HttpMethod"
const val HTTP_HOST_KEY = "HttpHost"
const val HTTP_STATUS_KEY = "HttpStatus"
const val MAX_HEADER_BYTES = 32 * 1024
private const val TYPE_TCP = 2

class TunnelMetrics {
    val streams = AtomicLong(); val bytesIn = AtomicLong(); val bytesOut = AtomicLong(); val reconnects = AtomicLong()
    override fun toString() = "streams=$streams in=$bytesIn out=$bytesOut reconnects=$reconnects"
}

class ConnectReq(val dest: String, val type: Int, val metadata: List<Pair<String, String>>) {
    fun meta(key: String) = metadata.firstOrNull { it.first == key }?.second
    fun headers() = metadata.filter { it.first.startsWith("$HTTP_HEADER:") }.map { it.first.removePrefix("$HTTP_HEADER:") to it.second }
}

/** Reads preamble (6-byte signature + 2-byte version) and the capnp ConnectRequest. */
fun readConnectRequest(i: InputStream): ConnectReq {
    val sig = ByteArray(6).also { i.readFully(it) }
    if (!sig.contentEquals(DATA_SIG)) throw TunnelException.Internal("unexpected stream signature")
    ByteArray(2).also { i.readFully(it) }
    val req = CapnpMessage.read(i).root() ?: throw TunnelException.Internal("empty ConnectRequest")
    return ConnectReq(req.text(0) ?: "", req.u16(0), req.structList(1).map { (it.text(0) ?: "") to (it.text(1) ?: "") })
}

/** Writes preamble + ConnectResponse { error, metadata }. */
fun writeConnectResponse(o: OutputStream, error: String, metadata: List<Pair<String, String>>) {
    val frame = CapnpBuilder().apply {
        val resp = root(0, 2)
        if (error.isNotEmpty()) text(resp, error)
        val list = structList(resp + 1, metadata.size, 0, 2)
        metadata.forEachIndexed { n, (k, v) -> text(list + n * 2, k); text(list + n * 2 + 1, v) }
    }.frame()
    o.write(DATA_SIG); o.write("01".toByteArray()); o.write(frame); o.flush()
}

fun extractPath(dest: String): String {
    val scheme = dest.indexOf("://")
    if (scheme >= 0) {
        val rest = dest.substring(scheme + 3)
        val slash = rest.indexOf('/')
        return if (slash >= 0) rest.substring(slash) else "/"
    }
    return if (dest.startsWith("/")) dest else "/"
}

// ── Shapes: what decides pooled vs bidirectional ─────────────────────────────

class RequestShape(val contentLength: Long?, val chunked: Boolean, val upgrade: Boolean, val wantsClose: Boolean) {
    val poolable get() = !chunked && !upgrade && !wantsClose
}

fun analyseRequest(req: ConnectReq): RequestShape {
    var cl: Long? = null; var chunked = false; var upgrade = false; var close = false
    for ((name, value) in req.headers()) {
        val v = value.lowercase()
        when (name.lowercase()) {
            "content-length" -> cl = value.trim().toLongOrNull()
            "transfer-encoding" -> if ("chunked" in v) chunked = true
            "upgrade" -> upgrade = true
            "connection" -> { if ("upgrade" in v) upgrade = true; if ("close" in v) close = true }
        }
    }
    return RequestShape(cl, chunked, upgrade, close)
}

class ResponseShape(val contentLength: Long?, val chunked: Boolean, val upgrade: Boolean, val wantsClose: Boolean) {
    val poolable get() = contentLength != null && !chunked && !upgrade && !wantsClose
}

/** [noBody] covers HEAD, 1xx, 204 and 304: their Content-Length (if any) describes bytes that never follow. */
fun analyseResponse(status: Int, headers: List<Pair<String, String>>, noBody: Boolean): ResponseShape {
    var cl: Long? = null; var chunked = false; var upgrade = status == 101; var close = false
    for ((name, value) in headers) {
        val v = value.lowercase()
        when (name.lowercase()) {
            "content-length" -> cl = value.trim().toLongOrNull()
            "transfer-encoding" -> if ("chunked" in v) chunked = true
            "connection" -> { if ("close" in v) close = true; if ("upgrade" in v) upgrade = true }
            "upgrade" -> upgrade = true
        }
    }
    if (noBody && !upgrade) cl = 0
    return ResponseShape(cl, chunked && !noBody, upgrade, close)
}

fun isBodiless(method: String, status: Int) = method.equals("HEAD", true) || (status in 100..199 && status != 101) || status == 204 || status == 304

fun buildRequestHead(req: ConnectReq, keepAlive: Boolean): ByteArray {
    val sb = StringBuilder()
    sb.append(req.meta(HTTP_METHOD_KEY) ?: "GET").append(' ').append(extractPath(req.dest)).append(" HTTP/1.1\r\n")
    req.meta(HTTP_HOST_KEY)?.takeIf { it.isNotEmpty() }?.let { sb.append("Host: ").append(it).append("\r\n") }
    var sawConnection = false
    for ((k, v) in req.headers()) {
        if (k.equals("host", true)) continue
        if (k.equals("connection", true)) sawConnection = true
        sb.append(k).append(": ").append(v).append("\r\n")
    }
    if (!sawConnection) sb.append(if (keepAlive) "Connection: keep-alive\r\n" else "Connection: close\r\n")
    sb.append("\r\n")
    return sb.toString().toByteArray(Charsets.ISO_8859_1)
}

// ── Origin response head ─────────────────────────────────────────────────────

/** The origin closed before sending a single response byte: the signature of a stale pooled socket. */
class OriginClosed : IOException("local origin closed before sending response head")

class ResponseHead(val status: Int, val headers: List<Pair<String, String>>, val leftover: ByteArray)

fun readResponseHead(i: InputStream): ResponseHead {
    val buf = ByteArrayOutputStream()
    val tmp = ByteArray(2048)
    var end = -1
    while (end < 0) {
        val n = i.read(tmp)
        if (n < 0) throw if (buf.size() == 0) OriginClosed() else EOFException("local origin closed mid-head")
        val before = buf.size()
        buf.write(tmp, 0, n)
        if (buf.size() > MAX_HEADER_BYTES) throw IOException("response header exceeds $MAX_HEADER_BYTES bytes")
        val a = buf.toByteArray()
        for (p in maxOf(0, before - 3)..a.size - 4) {
            if (a[p] == 13.toByte() && a[p + 1] == 10.toByte() && a[p + 2] == 13.toByte() && a[p + 3] == 10.toByte()) { end = p + 4; break }
        }
    }
    val all = buf.toByteArray()
    val lines = String(all, 0, end - 4, Charsets.ISO_8859_1).split("\r\n")
    val status = lines[0].split(' ').getOrNull(1)?.toIntOrNull() ?: throw IOException("bad status line: ${lines[0]}")
    val headers = lines.drop(1).filter { it.contains(':') }.map { it.substringBefore(':').trim() to it.substringAfter(':').trim() }
    return ResponseHead(status, headers, all.copyOfRange(end, all.size))
}

// ── One edge-opened stream, start to finish ──────────────────────────────────

fun proxyStream(s: QuicStream, localPort: Int, pool: LocalPool, metrics: TunnelMetrics) =
    proxyConnection(s.inputStream, s.outputStream, localPort, pool, metrics)

fun proxyConnection(edgeIn: InputStream, edgeOut: OutputStream, localPort: Int, pool: LocalPool, metrics: TunnelMetrics) {
    metrics.streams.incrementAndGet()
    var started = false // once the response head is out, an error response would corrupt the stream
    try {
        val req = readConnectRequest(edgeIn)
        if (req.type == TYPE_TCP) pipeTcp(edgeIn, edgeOut, localPort, metrics)
        else proxyHttp(edgeIn, edgeOut, req, pool, metrics) { started = true }
    } catch (e: Exception) {
        if (!started) runCatching { errorResponse(edgeOut, 502, "proxy error: ${e.message}") }
    } finally {
        runCatching { edgeOut.close() }
    }
}

private fun proxyHttp(edgeIn: InputStream, edgeOut: OutputStream, req: ConnectReq, pool: LocalPool, m: TunnelMetrics, onStarted: () -> Unit) {
    val shape = analyseRequest(req)
    val method = req.meta(HTTP_METHOD_KEY) ?: "GET"
    var lease = try {
        pool.acquire()
    } catch (e: SocketTimeoutException) {
        return errorResponse(edgeOut, 504, "local connect timed out")
    } catch (e: IOException) {
        return errorResponse(edgeOut, 502, "local connect: ${e.message}")
    }
    val head = buildRequestHead(req, shape.poolable)
    val bodyless = (shape.contentLength ?: 0L) == 0L && !shape.chunked && !shape.upgrade
    var released = false
    try {
        if (shape.poolable) {
            var resp: ResponseHead
            var retried = false
            while (true) {
                try {
                    val out = lease.output
                    out.write(head); out.flush()
                    shape.contentLength?.takeIf { it > 0 }?.let { copyN(edgeIn, out, it, m.bytesIn); out.flush() }
                    resp = readResponseHead(lease.input)
                    break
                } catch (e: IOException) {
                    // A pooled socket the server already closed fails before any byte comes back; retry once on a fresh one.
                    if (lease.reused && !retried && bodyless) { lease.discard(); lease = pool.acquireFresh(); retried = true; continue }
                    throw e
                }
            }
            val rs = analyseResponse(resp.status, resp.headers, isBodiless(method, resp.status))
            sendHead(edgeOut, resp, rs, onStarted)
            if (rs.poolable) {
                val remaining = (rs.contentLength ?: 0) - resp.leftover.size
                writeLeftover(edgeOut, resp, m)
                if (remaining > 0) copyN(lease.input, edgeOut, remaining, m.bytesOut)
                edgeOut.flush(); edgeOut.close()
                pool.release(lease); released = true
            } else {
                copy(bodyOf(lease.input, resp, rs), edgeOut, m.bytesOut)
                edgeOut.flush()
            }
        } else {
            runBidi(edgeIn, edgeOut, lease, head, method, m, onStarted)
        }
    } finally {
        if (!released) lease.discard()
    }
}

/** WebSocket upgrades, chunked uploads and Connection: close requests: two concurrent pumps, socket never pooled. */
private fun runBidi(edgeIn: InputStream, edgeOut: OutputStream, lease: Lease, head: ByteArray, method: String, m: TunnelMetrics, onStarted: () -> Unit) {
    lease.output.apply { write(head); flush() }
    thread(isDaemon = true, name = "cfqt-up") {
        try { copy(edgeIn, lease.output, m.bytesIn); runCatching { lease.socket.shutdownOutput() } } catch (_: Exception) { /* local closed first */ }
    }
    val resp = readResponseHead(lease.input)
    val rs = analyseResponse(resp.status, resp.headers, isBodiless(method, resp.status))
    sendHead(edgeOut, resp, rs, onStarted)
    copy(bodyOf(lease.input, resp, rs), edgeOut, m.bytesOut)
    edgeOut.flush()
}

/** The edge does not re-chunk: decode here and drop the header, like cloudflared's http.Transport does. */
private fun sendHead(edgeOut: OutputStream, resp: ResponseHead, rs: ResponseShape, onStarted: () -> Unit) {
    val meta = buildList {
        add(HTTP_STATUS_KEY to resp.status.toString())
        resp.headers.filterNot { rs.chunked && it.first.equals("transfer-encoding", true) }.forEach { add("$HTTP_HEADER:${it.first}" to it.second) }
    }
    writeConnectResponse(edgeOut, "", meta)
    onStarted()
}

private fun writeLeftover(edgeOut: OutputStream, resp: ResponseHead, m: TunnelMetrics) {
    if (resp.leftover.isNotEmpty()) {
        edgeOut.write(resp.leftover); m.bytesOut.addAndGet(resp.leftover.size.toLong())
    }
}

/** Body bytes after the head: the bytes already read with the head, then the rest of the socket; decoded if chunked. */
private fun bodyOf(src: InputStream, resp: ResponseHead, rs: ResponseShape): InputStream {
    val all = SequenceInputStream(resp.leftover.inputStream(), src)
    return if (rs.chunked) ChunkedInputStream(all) else all
}

private fun pipeTcp(edgeIn: InputStream, edgeOut: OutputStream, port: Int, m: TunnelMetrics) {
    Socket("127.0.0.1", port).use { sock ->
        writeConnectResponse(edgeOut, "", emptyList())
        val up = thread(isDaemon = true) { runCatching { copy(edgeIn, sock.getOutputStream(), m.bytesIn); sock.shutdownOutput() } }
        copy(sock.getInputStream(), edgeOut, m.bytesOut)
        up.join(1000)
    }
}

fun errorResponse(o: OutputStream, status: Int, msg: String) =
    writeConnectResponse(o, msg, listOf(HTTP_STATUS_KEY to status.toString()))

/** Copies until EOF, flushing each chunk so streaming bodies (SSE, downloads) are not held back. */
fun copy(src: InputStream, dst: OutputStream, counter: AtomicLong) {
    val buf = ByteArray(16 * 1024)
    while (true) {
        val n = src.read(buf)
        if (n < 0) return
        dst.write(buf, 0, n); dst.flush()
        counter.addAndGet(n.toLong())
    }
}

/** Copies exactly [n] bytes; the source ending early is an error. */
fun copyN(src: InputStream, dst: OutputStream, n: Long, counter: AtomicLong) {
    val buf = ByteArray(16 * 1024)
    var left = n
    while (left > 0) {
        val r = src.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
        if (r < 0) throw EOFException("source EOF with $left bytes still expected")
        dst.write(buf, 0, r)
        counter.addAndGet(r.toLong()); left -= r
    }
}

/** Decodes an HTTP/1.1 chunked body; ends at the 0-size chunk (trailers are skipped). */
class ChunkedInputStream(private val src: InputStream) : InputStream() {
    private var left = 0L
    private var done = false

    private fun line(): String {
        val sb = StringBuilder()
        while (true) {
            val c = src.read()
            if (c < 0) throw EOFException("chunked body truncated")
            if (c == '\n'.code) return sb.toString().trimEnd('\r')
            sb.append(c.toChar())
        }
    }

    private fun nextChunk() {
        val size = line().substringBefore(';').trim().toLong(16)
        if (size == 0L) { while (line().isNotEmpty()) { /* trailers */ }; done = true } else left = size
    }

    override fun read(): Int { val b = ByteArray(1); return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 0xff }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (done) return -1
        if (left == 0L) { nextChunk(); if (done) return -1 }
        val n = src.read(b, off, minOf(len.toLong(), left).toInt())
        if (n < 0) throw EOFException("chunk truncated")
        left -= n
        if (left == 0L) line() // CRLF after the chunk data
        return n
    }
}
