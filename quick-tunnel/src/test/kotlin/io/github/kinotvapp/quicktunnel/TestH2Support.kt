package io.github.kinotvapp.quicktunnel

import com.twitter.hpack.Decoder
import com.twitter.hpack.Encoder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** A connected loopback socket pair: (server side, client side). */
fun socketPair(): Pair<Socket, Socket> {
    ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { ss ->
        val client = Socket("127.0.0.1", ss.localPort)
        return ss.accept() to client
    }
}

/**
 * The edge's side of an HTTP/2 connection, written independently of [Http2Connection] (HPACK encoding comes from the
 * twitter library): opens streams, sends DATA, answers PING/SETTINGS, and collects what the server sends back.
 */
class MiniH2Client(private val sock: Socket, private val sendPreface: Boolean = true, clientSettings: List<Pair<Int, Int>> = emptyList()) : AutoCloseable {
    class ClientStream(val id: Int) {
        val headers = CompletableFuture<List<Pair<String, String>>>()
        val data = ByteArrayOutputStream()
        val chunks = LinkedBlockingQueue<ByteArray>()
        val ended = CompletableFuture<Unit>()
        val reset = CompletableFuture<Int>()
        val status get() = headers.get(10, TimeUnit.SECONDS).first { it.first == ":status" }.second.toInt()
        fun header(name: String) = headers.get(10, TimeUnit.SECONDS).firstOrNull { it.first == name }?.second
        fun bodyBytes(): ByteArray { ended.get(15, TimeUnit.SECONDS); return synchronized(data) { data.toByteArray() } }
    }

    private val out = sock.getOutputStream()
    private val inp = DataInputStream(sock.getInputStream().buffered())
    private val encoder = Encoder(4096)
    private val decoder = Decoder(64 * 1024, 4096)
    private val writeLock = Any()
    private var nextStream = 1
    val streams = ConcurrentHashMap<Int, ClientStream>()
    val serverSettings = CompletableFuture<Map<Int, Int>>()
    val serverConnWindowUpdates = LinkedBlockingQueue<Int>()
    val pongs = LinkedBlockingQueue<ByteArray>()
    val goAway = CompletableFuture<Int>()
    val settingsAcks = LinkedBlockingQueue<Unit>()
    /** Grant the server more window as DATA arrives, like a normal client. Tests of flow control turn this off. */
    @Volatile var autoWindowUpdate = true
    /** Answer the server's PINGs. Turn off to look like an edge that went silent. */
    @Volatile var autoPong = true
    val serverPings = java.util.concurrent.atomic.AtomicInteger()
    @Volatile var receivedDataBytes = 0L

    init {
        if (sendPreface) {
            synchronized(writeLock) { out.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()); out.flush() }
            val b = ByteArrayOutputStream(); clientSettings.forEach { (id, v) -> b.write(id ushr 8); b.write(id); b.write(Http2Connection.intBytes(v)) }
            frame(Http2Connection.SETTINGS, 0, 0, b.toByteArray())
        }
        thread(isDaemon = true, name = "mini-h2-read") { try { readLoop() } catch (_: Exception) { streams.values.forEach { it.ended.complete(Unit); it.headers.completeExceptionally(java.io.IOException("closed")) } } }
    }

    fun frame(type: Int, flags: Int, streamId: Int, payload: ByteArray = ByteArray(0)) = synchronized(writeLock) {
        val len = payload.size
        out.write(byteArrayOf((len ushr 16).toByte(), (len ushr 8).toByte(), len.toByte(), type.toByte(), flags.toByte()))
        out.write(Http2Connection.intBytes(streamId)); out.write(payload); out.flush()
    }

    private fun encode(headers: List<Pair<String, String>>): ByteArray {
        val b = ByteArrayOutputStream()
        headers.forEach { (n, v) -> encoder.encodeHeader(b, n.toByteArray(), v.toByteArray(), false) }
        return b.toByteArray()
    }

    fun get(path: String, vararg extra: Pair<String, String>) = request("GET", path, extra.toList(), null)

    /** Opens a stream; [body] null means no body (END_STREAM on HEADERS). */
    fun request(method: String, path: String, extra: List<Pair<String, String>> = emptyList(), body: ByteArray?, authority: String = "x.trycloudflare.com"): ClientStream {
        val id = synchronized(this) { nextStream.also { nextStream += 2 } }
        val st = ClientStream(id).also { streams[id] = it }
        val headers = listOf(":method" to method, ":scheme" to "https", ":authority" to authority, ":path" to path) + extra
        frame(Http2Connection.HEADERS, Http2Connection.FLAG_END_HEADERS or (if (body == null) Http2Connection.FLAG_END_STREAM else 0), id, encode(headers))
        if (body != null) { data(id, body, endStream = true) }
        return st
    }

    fun openStreaming(method: String, path: String, extra: List<Pair<String, String>> = emptyList()): ClientStream {
        val id = synchronized(this) { nextStream.also { nextStream += 2 } }
        val st = ClientStream(id).also { streams[id] = it }
        val headers = listOf(":method" to method, ":scheme" to "https", ":authority" to "x.trycloudflare.com", ":path" to path) + extra
        frame(Http2Connection.HEADERS, Http2Connection.FLAG_END_HEADERS, id, encode(headers))
        return st
    }

    /** HEADERS split into HEADERS + CONTINUATION frames. */
    fun requestWithContinuation(path: String, extra: List<Pair<String, String>>, pieceSize: Int): ClientStream {
        val id = synchronized(this) { nextStream.also { nextStream += 2 } }
        val st = ClientStream(id).also { streams[id] = it }
        val block = encode(listOf(":method" to "GET", ":scheme" to "https", ":authority" to "x", ":path" to path) + extra)
        var off = 0; var first = true
        while (off < block.size) {
            val n = minOf(pieceSize, block.size - off); val last = off + n >= block.size
            val flags = (if (last) Http2Connection.FLAG_END_HEADERS else 0) or (if (first) Http2Connection.FLAG_END_STREAM else 0)
            frame(if (first) Http2Connection.HEADERS else Http2Connection.CONTINUATION, flags, id, block.copyOfRange(off, off + n))
            off += n; first = false
        }
        return st
    }

    fun data(id: Int, bytes: ByteArray, endStream: Boolean) {
        var off = 0
        if (bytes.isEmpty()) { frame(Http2Connection.DATA, if (endStream) Http2Connection.FLAG_END_STREAM else 0, id); return }
        while (off < bytes.size) {
            val n = minOf(16_384, bytes.size - off); val last = off + n >= bytes.size
            frame(Http2Connection.DATA, if (last && endStream) Http2Connection.FLAG_END_STREAM else 0, id, bytes.copyOfRange(off, off + n))
            off += n
        }
    }

    fun outputOf(st: ClientStream): OutputStream = object : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) = data(st.id, b.copyOfRange(off, off + len), endStream = false)
        override fun close() = data(st.id, ByteArray(0), endStream = true)
    }

    fun inputOf(st: ClientStream): InputStream = object : InputStream() {
        private var cur: ByteArray? = null; private var pos = 0
        override fun read(): Int { val one = ByteArray(1); return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (cur == null || pos >= cur!!.size) {
                val next = st.chunks.poll(20, TimeUnit.SECONDS) ?: throw java.io.IOException("timed out waiting for the server")
                if (next.isEmpty()) return -1
                cur = next; pos = 0
            }
            val n = minOf(len, cur!!.size - pos); System.arraycopy(cur!!, pos, b, off, n); pos += n; return n
        }
    }

    private fun readLoop() {
        var contStream = 0; var contFlags = 0; var cont: ByteArrayOutputStream? = null
        while (true) {
            val len = (inp.readUnsignedByte() shl 16) or (inp.readUnsignedByte() shl 8) or inp.readUnsignedByte()
            val type = inp.readUnsignedByte(); val flags = inp.readUnsignedByte(); val sid = inp.readInt() and 0x7fffffff
            val p = ByteArray(len).also { inp.readFully(it) }
            when (type) {
                Http2Connection.SETTINGS -> if (flags and 1 == 0) {
                    val m = HashMap<Int, Int>(); var i = 0
                    while (i + 6 <= p.size) { m[((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)] = ByteArrayInputStream(p, i + 2, 4).let { DataInputStream(it).readInt() }; i += 6 }
                    serverSettings.complete(m); frame(Http2Connection.SETTINGS, 1, 0)
                } else settingsAcks.put(Unit)
                Http2Connection.WINDOW_UPDATE -> if (sid == 0) serverConnWindowUpdates.put(DataInputStream(ByteArrayInputStream(p)).readInt())
                Http2Connection.PING -> if (flags and 1 == 0) { serverPings.incrementAndGet(); if (autoPong) frame(Http2Connection.PING, 1, 0, p) } else pongs.put(p)
                Http2Connection.GOAWAY -> goAway.complete(DataInputStream(ByteArrayInputStream(p, 4, 4)).readInt())
                Http2Connection.RST_STREAM -> streams[sid]?.let { it.reset.complete(DataInputStream(ByteArrayInputStream(p)).readInt()); it.ended.complete(Unit); it.chunks.put(ByteArray(0)) }
                Http2Connection.HEADERS, Http2Connection.CONTINUATION -> {
                    if (type == Http2Connection.HEADERS) {
                        if (flags and 4 == 0) { cont = ByteArrayOutputStream().also { it.write(p) }; contStream = sid; contFlags = flags; continue }
                        headersDone(sid, flags, p)
                    } else {
                        cont!!.write(p)
                        if (flags and 4 != 0) { headersDone(contStream, contFlags, cont.toByteArray()); cont = null }
                    }
                }
                Http2Connection.DATA -> {
                    receivedDataBytes += len
                    val st = streams[sid]
                    if (len > 0) {
                        val end = if (flags and 8 != 0) len - (p[0].toInt() and 0xff) else len; val start = if (flags and 8 != 0) 1 else 0
                        if (st != null && end > start) { val chunk = p.copyOfRange(start, end); synchronized(st.data) { st.data.write(chunk) }; st.chunks.put(chunk) }
                        if (autoWindowUpdate) { frame(Http2Connection.WINDOW_UPDATE, 0, 0, Http2Connection.intBytes(len)); frame(Http2Connection.WINDOW_UPDATE, 0, sid, Http2Connection.intBytes(len)) }
                    }
                    if (flags and 1 != 0) { st?.ended?.complete(Unit); st?.chunks?.put(ByteArray(0)) }
                }
            }
        }
    }

    private fun headersDone(sid: Int, flags: Int, block: ByteArray) {
        val h = ArrayList<Pair<String, String>>()
        decoder.decode(ByteArrayInputStream(block)) { n, v, _ -> h += String(n) to String(v) }; decoder.endHeaderBlock()
        val st = streams[sid] ?: return
        st.headers.complete(h)
        if (flags and 1 != 0) { st.ended.complete(Unit); st.chunks.put(ByteArray(0)) }
    }

    override fun close() { runCatching { sock.close() } }
}

/** Runs an [Http2Connection] on one end of a loopback pair with [handler], and gives back a client on the other. */
class H2Harness(handler: (Http2Request) -> Unit, pingIntervalMs: Long = 60_000, idleTimeoutMs: Long = 120_000, sendPreface: Boolean = true, clientSettings: List<Pair<Int, Int>> = emptyList()) : AutoCloseable {
    private val pair = socketPair()
    val closed = CompletableFuture<Throwable?>()
    private val executor = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
    val server = Http2Connection(pair.first.getInputStream(), pair.first.getOutputStream(), executor, handler, { closed.complete(it) }, pingIntervalMs, idleTimeoutMs).also { it.start() }
    val client = MiniH2Client(pair.second, sendPreface, clientSettings)
    override fun close() { client.close(); runCatching { pair.first.close() }; executor.shutdownNow() }
}
