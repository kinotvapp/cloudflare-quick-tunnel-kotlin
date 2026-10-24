package io.github.kinotvapp.quicktunnel

import com.twitter.hpack.Decoder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

/**
 * A minimal HTTP/2 *server* over an existing byte stream (RFC 9113). The edge dials nothing: we open the TLS
 * connection and then play the server, exactly like cloudflared's `--protocol http2`. Supports what that needs:
 * SETTINGS, HEADERS/CONTINUATION, DATA, WINDOW_UPDATE flow control in both directions, PING, RST_STREAM, GOAWAY.
 * No server push, no priorities, no upgrade from HTTP/1.1.
 */
class Http2Connection(
    private val input: InputStream,
    private val output: OutputStream,
    private val executor: Executor,
    private val onRequest: (Http2Request) -> Unit,
    /** Called once when the connection ends; the argument is null for a clean close or a GOAWAY. */
    private val onClosed: (Throwable?) -> Unit,
    private val pingIntervalMs: Long = 10_000,
    private val idleTimeoutMs: Long = 40_000,
) {
    private class StreamState(val id: Int, initialSendWindow: Long) {
        @Volatile var sendWindow = initialSendWindow
        val body = BodyQueue()
        @Volatile var remoteClosed = false
        @Volatile var localClosed = false
        @Volatile var reset = false
        val done = CompletableFuture<Unit>()
    }

    // Everything that decides whether we may send DATA lives under [lock]; frames are serialized by [writeLock].
    private val lock = ReentrantLock()
    private val windowOpen = lock.newCondition()
    private val writeLock = Any()
    private val streams = ConcurrentHashMap<Int, StreamState>()
    private var connSendWindow = DEFAULT_WINDOW.toLong()
    private var peerInitialWindow = DEFAULT_WINDOW
    @Volatile private var peerMaxFrame = DEFAULT_MAX_FRAME
    @Volatile private var closed = false
    @Volatile private var goAwayReceived = false
    @Volatile private var lastRead = System.currentTimeMillis()
    private val activeHandlers = AtomicInteger()
    private val decoder = Decoder(MAX_HEADER_LIST, 4096)
    private var pendingConnUpdate = 0

    val isClosed get() = closed

    fun start() {
        val dataIn = DataInputStream(input.buffered(32 * 1024))
        thread(isDaemon = true, name = "cfqt-h2-read") {
            var failure: Throwable? = null
            try {
                val preface = ByteArray(PREFACE.size).also { dataIn.readFully(it) }
                if (!preface.contentEquals(PREFACE)) throw IOException("bad HTTP/2 connection preface")
                // Our settings: big stream windows so uploads and downloads are not throttled to 64 KiB per round trip.
                sendSettings(listOf(SETTINGS_MAX_CONCURRENT_STREAMS to 1000, SETTINGS_INITIAL_WINDOW_SIZE to STREAM_WINDOW, SETTINGS_ENABLE_PUSH to 0))
                writeFrame(WINDOW_UPDATE, 0, 0, intBytes(CONN_WINDOW - DEFAULT_WINDOW))
                readLoop(dataIn)
            } catch (e: Throwable) {
                if (!(closed || e is EOFException)) failure = e
            } finally {
                shutdown(failure)
            }
        }
        thread(isDaemon = true, name = "cfqt-h2-ping") { keepAlive() }
    }

    // ── Reading ──────────────────────────────────────────────────────────────

    private fun readLoop(inp: DataInputStream) {
        var headerStream = 0
        var headerFlags = 0
        var headerBlock: ByteArrayOutputStream? = null
        while (!closed) {
            val length = (inp.readUnsignedByte() shl 16) or (inp.readUnsignedByte() shl 8) or inp.readUnsignedByte()
            val type = inp.readUnsignedByte()
            val flags = inp.readUnsignedByte()
            val streamId = inp.readInt() and 0x7fffffff
            if (length > MAX_FRAME_WE_ACCEPT) throw IOException("frame of $length bytes exceeds the limit we advertised")
            val payload = ByteArray(length).also { inp.readFully(it) }
            lastRead = System.currentTimeMillis()

            if (headerBlock != null && (type != CONTINUATION || streamId != headerStream)) throw IOException("expected CONTINUATION")
            when (type) {
                DATA -> onData(streamId, flags, payload)
                HEADERS -> {
                    var off = 0; var end = payload.size
                    if (flags and FLAG_PADDED != 0) { val pad = payload[0].toInt() and 0xff; off = 1; end -= pad }
                    if (flags and FLAG_PRIORITY != 0) off += 5
                    if (off > end) throw IOException("malformed HEADERS")
                    val block = ByteArrayOutputStream().apply { write(payload, off, end - off) }
                    if (flags and FLAG_END_HEADERS != 0) onHeaders(streamId, flags, block.toByteArray())
                    else { headerBlock = block; headerStream = streamId; headerFlags = flags }
                }
                CONTINUATION -> {
                    val block = headerBlock ?: throw IOException("unexpected CONTINUATION")
                    block.write(payload)
                    if (flags and FLAG_END_HEADERS != 0) { onHeaders(headerStream, headerFlags, block.toByteArray()); headerBlock = null }
                }
                SETTINGS -> if (flags and FLAG_ACK == 0) onSettings(payload)
                WINDOW_UPDATE -> onWindowUpdate(streamId, payload)
                PING -> if (flags and FLAG_ACK == 0) writeFrame(PING, FLAG_ACK, 0, payload)
                RST_STREAM -> streams[streamId]?.let { st -> st.reset = true; finishStream(st, IOException("stream reset by the edge")) }
                GOAWAY -> { goAwayReceived = true; closeSoon() }
                PRIORITY, PUSH_PROMISE -> {} // not used by the edge
                else -> {} // unknown frame types must be ignored (RFC 9113 §4.1)
            }
        }
    }

    private fun onSettings(p: ByteArray) {
        var i = 0
        while (i + 6 <= p.size) {
            val id = ((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)
            val v = ((p[i + 2].toInt() and 0xff) shl 24) or ((p[i + 3].toInt() and 0xff) shl 16) or ((p[i + 4].toInt() and 0xff) shl 8) or (p[i + 5].toInt() and 0xff)
            when (id) {
                SETTINGS_INITIAL_WINDOW_SIZE -> lock.withLock {
                    val delta = v.toLong() - peerInitialWindow
                    peerInitialWindow = v
                    streams.values.forEach { it.sendWindow += delta }
                    windowOpen.signalAll()
                }
                SETTINGS_MAX_FRAME_SIZE -> peerMaxFrame = v.coerceIn(DEFAULT_MAX_FRAME, (1 shl 24) - 1)
                // HEADER_TABLE_SIZE needs no action: our encoder never uses the dynamic table.
            }
            i += 6
        }
        writeFrame(SETTINGS, FLAG_ACK, 0, ByteArray(0))
    }

    private fun onWindowUpdate(streamId: Int, p: ByteArray) {
        if (p.size != 4) throw IOException("malformed WINDOW_UPDATE")
        val inc = ((p[0].toInt() and 0x7f) shl 24) or ((p[1].toInt() and 0xff) shl 16) or ((p[2].toInt() and 0xff) shl 8) or (p[3].toInt() and 0xff)
        lock.withLock {
            if (streamId == 0) connSendWindow += inc else streams[streamId]?.let { it.sendWindow += inc }
            windowOpen.signalAll()
        }
    }

    private fun onData(streamId: Int, flags: Int, p: ByteArray) {
        // Flow control counts the whole frame, padding included. The connection window is refilled right away,
        // the stream window only when the handler actually reads, so a slow origin pushes back on the edge.
        creditConnection(p.size)
        val st = streams[streamId] ?: return
        var off = 0; var end = p.size
        if (flags and FLAG_PADDED != 0) { val pad = p[0].toInt() and 0xff; off = 1; end -= pad; if (off > end) throw IOException("malformed DATA") }
        if (end > off) st.body.offer(p.copyOfRange(off, end))
        if (p.size > end - off) st.body.padding(streamId, p.size - (end - off))
        if (flags and FLAG_END_STREAM != 0) { st.remoteClosed = true; st.body.endOfStream() }
    }

    private fun creditConnection(n: Int) {
        val send: Int
        synchronized(this) { pendingConnUpdate += n; send = if (pendingConnUpdate >= 32 * 1024) pendingConnUpdate else 0; if (send > 0) pendingConnUpdate = 0 }
        if (send > 0) writeFrame(WINDOW_UPDATE, 0, 0, intBytes(send))
    }

    private fun onHeaders(streamId: Int, flags: Int, block: ByteArray) {
        val headers = ArrayList<Pair<String, String>>()
        decoder.decode(ByteArrayInputStream(block)) { name, value, _ -> headers += String(name, Charsets.ISO_8859_1) to String(value, Charsets.ISO_8859_1) }
        decoder.endHeaderBlock()
        val existing = streams[streamId]
        if (existing != null) { // trailers: only the END_STREAM flag matters to us
            if (flags and FLAG_END_STREAM != 0) { existing.remoteClosed = true; existing.body.endOfStream() }
            return
        }
        if (streamId % 2 == 0 || goAwayReceived) { sendRst(streamId, REFUSED_STREAM); return }
        val st = StreamState(streamId, lock.withLock { peerInitialWindow.toLong() })
        st.body.onConsumed = { n -> if (!st.remoteClosed) sendWindowUpdate(streamId, n) } // nothing more can arrive after END_STREAM
        streams[streamId] = st
        if (flags and FLAG_END_STREAM != 0) { st.remoteClosed = true; st.body.endOfStream() }
        val request = Http2Request(streamId, headers, flags and FLAG_END_STREAM != 0, st.body, Http2Response(this, st), st.done)
        activeHandlers.incrementAndGet()
        executor.execute {
            try {
                onRequest(request)
            } catch (e: Throwable) {
                if (!st.localClosed) sendRst(streamId, INTERNAL_ERROR)
            } finally {
                if (!st.localClosed) runCatching { endLocal(st) }
                // Responding before the request body is finished: tell the edge to stop sending it.
                if (!st.remoteClosed && !st.reset) sendRst(streamId, NO_ERROR)
                finishStream(st, null)
                activeHandlers.decrementAndGet()
            }
        }
    }

    // ── Writing ──────────────────────────────────────────────────────────────

    private fun writeFrame(type: Int, flags: Int, streamId: Int, payload: ByteArray, off: Int = 0, len: Int = payload.size) {
        synchronized(writeLock) {
            if (closed) throw IOException("HTTP/2 connection closed")
            try {
                val h = ByteArray(9)
                h[0] = (len ushr 16).toByte(); h[1] = (len ushr 8).toByte(); h[2] = len.toByte(); h[3] = type.toByte(); h[4] = flags.toByte()
                h[5] = (streamId ushr 24).toByte(); h[6] = (streamId ushr 16).toByte(); h[7] = (streamId ushr 8).toByte(); h[8] = streamId.toByte()
                output.write(h); output.write(payload, off, len); output.flush()
            } catch (e: IOException) {
                shutdown(e); throw e
            }
        }
    }

    private fun sendSettings(s: List<Pair<Int, Int>>) {
        val b = ByteArrayOutputStream()
        s.forEach { (id, v) -> b.write(id ushr 8); b.write(id); b.write(intBytes(v)) }
        writeFrame(SETTINGS, 0, 0, b.toByteArray())
    }

    private fun sendWindowUpdate(streamId: Int, n: Int) { if (n > 0 && !closed) runCatching { writeFrame(WINDOW_UPDATE, 0, streamId, intBytes(n)) } }
    private fun sendRst(streamId: Int, code: Int) { if (!closed) runCatching { writeFrame(RST_STREAM, 0, streamId, intBytes(code)) } }

    internal fun sendHeaders(st: Any, headers: List<Pair<String, String>>, endStream: Boolean) {
        st as StreamState
        if (st.reset) throw IOException("stream was reset")
        // Literal header fields without indexing: valid for any peer table size and never touches the dynamic table.
        val block = ByteArrayOutputStream()
        headers.forEach { (n, v) ->
            block.write(0x00)
            val nb = n.lowercase().toByteArray(Charsets.ISO_8859_1); val vb = v.toByteArray(Charsets.ISO_8859_1)
            writeInt(block, nb.size, 7, 0); block.write(nb)
            writeInt(block, vb.size, 7, 0); block.write(vb)
        }
        val all = block.toByteArray()
        synchronized(writeLock) {
            val max = peerMaxFrame
            var off = 0
            var first = true
            while (first || off < all.size) {
                val n = minOf(max, all.size - off)
                val last = off + n >= all.size
                val type = if (first) HEADERS else CONTINUATION
                val flags = (if (last) FLAG_END_HEADERS else 0) or (if (first && endStream) FLAG_END_STREAM else 0)
                writeFrame(type, flags, st.id, all, off, n)
                off += n; first = false
            }
        }
        if (endStream) st.localClosed = true
    }

    internal fun sendData(st: Any, b: ByteArray, off: Int, len: Int) {
        st as StreamState
        var o = off; var left = len
        while (left > 0) {
            val n: Int
            lock.withLock {
                while (!closed && !st.reset && (connSendWindow <= 0 || st.sendWindow <= 0)) windowOpen.await(1, TimeUnit.SECONDS)
                if (closed) throw IOException("HTTP/2 connection closed")
                if (st.reset) throw IOException("stream was reset")
                n = minOf(left.toLong(), connSendWindow, st.sendWindow, peerMaxFrame.toLong()).toInt()
                connSendWindow -= n; st.sendWindow -= n
            }
            writeFrame(DATA, 0, st.id, b, o, n)
            o += n; left -= n
        }
    }

    internal fun endLocal(st: Any) {
        st as StreamState
        if (st.localClosed || st.reset) return
        st.localClosed = true
        writeFrame(DATA, FLAG_END_STREAM, st.id, ByteArray(0))
    }

    internal fun resetStream(st: Any, code: Int) { st as StreamState; st.reset = true; sendRst(st.id, code); finishStream(st, IOException("stream reset locally")) }

    private fun finishStream(st: StreamState, error: Throwable?) {
        if (error != null) st.body.fail(error)
        if (st.remoteClosed || st.reset) streams.remove(st.id)
        st.done.complete(Unit)
        lock.withLock { windowOpen.signalAll() }
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    private fun keepAlive() {
        while (!closed) {
            try { Thread.sleep(pingIntervalMs) } catch (_: InterruptedException) { return }
            if (closed) return
            if (System.currentTimeMillis() - lastRead > idleTimeoutMs) { shutdown(IOException("no data from the edge for ${idleTimeoutMs}ms")); return }
            runCatching { writeFrame(PING, 0, 0, ByteArray(8) { it.toByte() }) }
        }
    }

    private fun closeSoon() = thread(isDaemon = true) { shutdown(null) }

    /** Sends GOAWAY, lets running requests finish (up to [graceMs]), then closes the connection. */
    fun close(graceMs: Long = 0) {
        if (closed) return
        runCatching { writeFrame(GOAWAY, 0, 0, ByteArray(8)) }
        val deadline = System.currentTimeMillis() + graceMs
        while (activeHandlers.get() > 0 && System.currentTimeMillis() < deadline) Thread.sleep(50)
        shutdown(null)
    }

    private val notified = java.util.concurrent.atomic.AtomicBoolean(false)

    private fun shutdown(cause: Throwable?) {
        closed = true
        runCatching { input.close() }; runCatching { output.close() }
        val error = cause ?: IOException("HTTP/2 connection closed")
        streams.values.forEach { it.body.fail(error); it.done.complete(Unit) }
        streams.clear()
        lock.withLock { windowOpen.signalAll() }
        if (notified.compareAndSet(false, true)) onClosed(cause)
    }

    private class BodyQueue : InputStream(), ProbeableBody {
        private val chunks = LinkedBlockingQueue<Any>()
        private var current: ByteArray? = null
        private var pos = 0
        @Volatile private var finished = false
        var onConsumed: (Int) -> Unit = {}
        private var unacked = 0
        private var paddingCredit = 0
        private object End

        /** One item taken from the queue by [probe] and not yet consumed by [read]. */
        private var peeked: Any? = null

        /**
         * Waits up to [timeoutMs] for the first sign of the body: true when bytes are there, false when the body is empty
         * (END_STREAM), null if nothing has arrived yet. Does not consume anything.
         */
        override fun probe(timeoutMs: Long): Boolean? {
            val cur = current
            if (cur != null && pos < cur.size) return true
            val item = peeked ?: chunks.poll(timeoutMs, TimeUnit.MILLISECONDS)?.also { peeked = it } ?: return null
            return item is ByteArray
        }

        fun offer(b: ByteArray) { chunks.put(b) }
        fun padding(streamId: Int, n: Int) { synchronized(this) { paddingCredit += n } }
        fun endOfStream() { chunks.put(End) }
        fun fail(e: Throwable) { chunks.put(e) }

        override fun read(): Int { val one = ByteArray(1); return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (finished) return -1
            var cur = current
            if (cur == null || pos >= cur.size) {
                when (val next = peeked?.also { peeked = null } ?: chunks.take()) {
                    is ByteArray -> { cur = next; current = next; pos = 0 }
                    is Throwable -> { finished = true; throw IOException(next.message, next) }
                    else -> { finished = true; return -1 }
                }
            }
            val n = minOf(len, cur!!.size - pos)
            System.arraycopy(cur, pos, b, off, n)
            pos += n
            val credit: Int
            synchronized(this) { unacked += n; credit = if (unacked >= 16 * 1024 || pos >= cur.size) unacked + paddingCredit else 0; if (credit > 0) { unacked = 0; paddingCredit = 0 } }
            if (credit > 0) onConsumed(credit)
            return n
        }
    }

    companion object {
        private val PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        const val DATA = 0; const val HEADERS = 1; const val PRIORITY = 2; const val RST_STREAM = 3; const val SETTINGS = 4
        const val PUSH_PROMISE = 5; const val PING = 6; const val GOAWAY = 7; const val WINDOW_UPDATE = 8; const val CONTINUATION = 9
        const val FLAG_END_STREAM = 1; const val FLAG_ACK = 1; const val FLAG_END_HEADERS = 4; const val FLAG_PADDED = 8; const val FLAG_PRIORITY = 0x20
        const val SETTINGS_HEADER_TABLE_SIZE = 1; const val SETTINGS_ENABLE_PUSH = 2; const val SETTINGS_MAX_CONCURRENT_STREAMS = 3
        const val SETTINGS_INITIAL_WINDOW_SIZE = 4; const val SETTINGS_MAX_FRAME_SIZE = 5
        const val NO_ERROR = 0; const val INTERNAL_ERROR = 2; const val REFUSED_STREAM = 7
        const val DEFAULT_WINDOW = 65_535
        const val STREAM_WINDOW = 1 shl 20
        const val CONN_WINDOW = 4 shl 20
        const val DEFAULT_MAX_FRAME = 16_384
        const val MAX_FRAME_WE_ACCEPT = 16_384
        const val MAX_HEADER_LIST = 64 * 1024

        fun intBytes(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

        /** HPACK integer with an N-bit prefix (RFC 7541 §5.1). */
        fun writeInt(out: ByteArrayOutputStream, value: Int, prefixBits: Int, firstByteBits: Int) {
            val max = (1 shl prefixBits) - 1
            if (value < max) { out.write(firstByteBits or value); return }
            out.write(firstByteBits or max)
            var v = value - max
            while (v >= 128) { out.write((v and 0x7f) or 0x80); v = v ushr 7 }
            out.write(v)
        }
    }
}

class Http2Request internal constructor(
    val streamId: Int,
    /** Pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) first, then regular headers, names lowercase. */
    val headers: List<Pair<String, String>>,
    /** True when the request has no body at all (END_STREAM arrived with HEADERS). */
    val endStream: Boolean,
    val body: InputStream,
    val response: Http2Response,
    /** Completes when the stream is over, or the connection died. */
    val done: CompletableFuture<Unit>,
) {
    fun header(name: String) = headers.firstOrNull { it.first == name }?.second

    /**
     * Whether a body follows when HEADERS did not carry END_STREAM: the edge sometimes sends a GET as HEADERS and then an
     * empty DATA with END_STREAM. true = bytes arrived, false = empty body, null = still undecided after [timeoutMs].
     */
    fun probeBody(timeoutMs: Long): Boolean? = (body as? ProbeableBody)?.probe(timeoutMs)
}

/** A request body that can be peeked at without consuming it. */
internal interface ProbeableBody { fun probe(timeoutMs: Long): Boolean? }

class Http2Response internal constructor(private val connection: Http2Connection, private val stream: Any) {
    @Volatile var headersSent = false
        private set

    fun sendHeaders(status: Int, headers: List<Pair<String, String>>, endStream: Boolean = false) {
        check(!headersSent) { "headers already sent" }
        headersSent = true
        connection.sendHeaders(stream, listOf(":status" to status.toString()) + headers, endStream)
    }

    /** Response body. Writing before [sendHeaders] sends a bare `200` first, like Go's http2 server. */
    val body: OutputStream = object : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) {
            if (!headersSent) sendHeaders(200, emptyList())
            connection.sendData(stream, b, off, len)
        }
        override fun close() = finish()
    }

    /** Ends the stream (END_STREAM). Idempotent. */
    fun finish() {
        if (!headersSent) sendHeaders(200, emptyList(), endStream = true) else connection.endLocal(stream)
    }

    fun reset(code: Int = Http2Connection.INTERNAL_ERROR) = connection.resetStream(stream, code)
}
