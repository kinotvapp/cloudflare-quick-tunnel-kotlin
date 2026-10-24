package io.github.kinotvapp.quicktunnel

import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager

/**
 * TLS 1.3 over a plain TCP socket in pure Java: the handshake is our own state machine ([Tls13ClientHandshake], written
 * from RFC 8446), and this file is the TLS record layer around it (RFC 8446 section 5). The platform's TLS only
 * speaks 1.3 from Android 10, and the edge's TCP endpoint requires 1.3, so this is what lets the HTTP/2 transport run on
 * Android 7 to 9.
 *
 * Only TLS_AES_128_GCM_SHA256 is offered. No session resumption, no early data, no client certificates.
 */
internal class Tls13Connection private constructor(private val socket: Socket) : AutoCloseable {
    /** Keys and per-direction state for one record protection epoch. */
    private class Epoch(var secret: ByteArray) {
        var key = SecretKeySpec(expandLabel(secret, "key", ByteArray(0), 16), "AES")
        var iv = expandLabel(secret, "iv", ByteArray(0), 12)
        var seq = 0L

        /** KeyUpdate: the next secret, with the sequence number starting over (RFC 8446 section 7.2). */
        fun next() = Epoch(expandLabel(secret, "traffic upd", ByteArray(0), 32))

        fun nonce(): ByteArray = iv.copyOf().also { n -> for (i in 0 until 8) n[11 - i] = (n[11 - i].toInt() xor (seq ushr (8 * i)).toInt()).toByte() }
    }

    private val rawIn = DataInputStream(BufferedInputStream(socket.getInputStream(), 20 * 1024))
    private val rawOut = socket.getOutputStream()
    private var readEpoch: Epoch? = null
    private var writeEpoch: Epoch? = null
    private val writeLock = ReentrantLock()

    /** The peer asked us to rotate our keys too. The reader must never wait for the write lock (see [onKeyUpdate]). */
    @Volatile private var keyUpdateReplyPending = false

    private lateinit var handshake: Tls13ClientHandshake
    private var handshakeBytes = ByteArray(0)
    @Volatile private var eof = false
    @Volatile private var closed = false

    /** How many KeyUpdate messages the peer sent (for tests). */
    @Volatile internal var keyUpdatesSeen = 0

    val input: InputStream = object : InputStream() {
        private var current = ByteArray(0)
        private var pos = 0
        override fun read(): Int { val one = ByteArray(1); return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (pos >= current.size) {
                if (eof) return -1
                current = readApplicationData() ?: return -1
                pos = 0
            }
            val n = minOf(len, current.size - pos)
            System.arraycopy(current, pos, b, off, n); pos += n
            return n
        }
        override fun close() = this@Tls13Connection.close()
    }

    val output: OutputStream = object : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) {
            var o = off; var left = len
            while (left > 0) { val n = minOf(left, MAX_FRAGMENT); writeRecord(APPLICATION_DATA, b, o, n); o += n; left -= n }
        }
        override fun flush() { writeLock.lock(); try { rawOut.flush() } finally { writeLock.unlock() } }
        override fun close() = this@Tls13Connection.close()
    }

    // ── Handshake ────────────────────────────────────────────────────────────

    private fun handshake(serverName: String, trust: X509TrustManager, random: SecureRandom) {
        val hs = Tls13ClientHandshake(serverName, trust, random)
        handshake = hs
        writeRecord(HANDSHAKE, hs.clientHello(), protect = false)
        while (!hs.isComplete) {
            val (type, content) = readRecord() ?: throw SSLHandshakeException("the server closed the connection during the handshake")
            when (type) {
                HANDSHAKE -> onHandshakeBytes(content)
                ALERT -> throw SSLHandshakeException("TLS alert during the handshake: level ${content.getOrNull(0)}, description ${content.getOrNull(1)}")
                CHANGE_CIPHER_SPEC -> {} // middlebox compatibility record: ignored
                else -> throw SSLHandshakeException("unexpected record type $type during the handshake")
            }
        }
    }

    /** Handshake messages can span records and a record can hold several messages. */
    private fun onHandshakeBytes(bytes: ByteArray) {
        handshakeBytes += bytes
        while (handshakeBytes.size >= 4) {
            val length = ((handshakeBytes[1].toInt() and 0xff) shl 16) or ((handshakeBytes[2].toInt() and 0xff) shl 8) or (handshakeBytes[3].toInt() and 0xff)
            // No legitimate message is anywhere near this (a long certificate chain is a few KB): do not buffer what a hostile peer announces.
            if (length > MAX_HANDSHAKE_MESSAGE) throw TlsHandshakeException(TlsAlert.DECODE_ERROR, "handshake message of $length bytes is too large")
            if (handshakeBytes.size < 4 + length) return
            val message = handshakeBytes.copyOfRange(0, 4 + length)
            handshakeBytes = handshakeBytes.copyOfRange(4 + length, handshakeBytes.size)
            if (handshake.isComplete) {
                if (message[0].toInt() == KEY_UPDATE) onKeyUpdate(message) else handshake.onPostHandshake(message)
                continue
            }
            val outgoing = handshake.receive(message, underHandshakeKeys = readEpoch != null)
            // Key changes (RFC 8446 section 5.1): the message that changes keys must be the last thing in its record.
            val secrets = handshake.handshakeSecrets
            if (secrets != null && readEpoch == null) {
                if (handshakeBytes.isNotEmpty()) throw TlsHandshakeException(TlsAlert.UNEXPECTED_MESSAGE, "data after the ServerHello in the same record")
                readEpoch = Epoch(secrets.server); writeEpoch = Epoch(secrets.client)
            }
            for (o in outgoing) writeRecord(HANDSHAKE, o.bytes, protect = o.underHandshakeKeys) // our Finished still goes under the handshake keys
            val app = handshake.applicationSecrets
            if (handshake.isComplete && app != null) {
                if (handshakeBytes.isNotEmpty()) throw TlsHandshakeException(TlsAlert.UNEXPECTED_MESSAGE, "data after the server Finished in the same record")
                withWriteLock { writeEpoch = Epoch(app.client) }
                readEpoch = Epoch(app.server)
            }
        }
    }

    // ── Post-handshake ───────────────────────────────────────────────────────

    /**
     * RFC 8446 section 4.6.3: the peer rotated its sending keys, and may ask us to rotate ours.
     *
     * The reply is deferred to the next write instead of being sent from here. The reader thread must never wait for the
     * write lock: a writer blocked on a full TCP buffer holds it, the peer stops reading because it is itself blocked writing
     * to us, and we would not be reading either. The RFC only requires the reply "prior to sending its next Application Data".
     */
    private fun onKeyUpdate(message: ByteArray) {
        if (message.size != 5 || (message[4].toInt() and 0xff) > 1) throw SSLException("malformed KeyUpdate")
        keyUpdatesSeen++
        readEpoch = readEpoch!!.next()
        if (message[4].toInt() == 1) keyUpdateReplyPending = true
    }

    private fun readApplicationData(): ByteArray? {
        while (true) {
            val (type, content) = readRecord() ?: run { eof = true; return null }
            when (type) {
                APPLICATION_DATA -> if (content.isNotEmpty()) return content
                HANDSHAKE -> onHandshakeBytes(content)
                ALERT -> {
                    val description = content.getOrNull(1)?.toInt() ?: -1
                    when (description) {
                        0 -> { eof = true; return null } // close_notify
                        90 -> {} // user_canceled: RFC 8446 section 6.1 says to ignore it; a close_notify follows (the JDK sends both)
                        else -> throw alertException(content)
                    }
                }
                else -> throw SSLException("unexpected TLS record type $type")
            }
        }
    }

    private fun alertException(content: ByteArray) = SSLException("TLS alert: level ${content.getOrNull(0)}, description ${content.getOrNull(1)}")

    // ── Record layer ─────────────────────────────────────────────────────────

    private inline fun <T> withWriteLock(block: () -> T): T { writeLock.lock(); try { return block() } finally { writeLock.unlock() } }

    private fun writeRecord(type: Int, data: ByteArray, off: Int = 0, len: Int = data.size, protect: Boolean = true) {
        withWriteLock {
            if (closed) throw IOException("TLS connection closed")
            if (protect && keyUpdateReplyPending && type == APPLICATION_DATA) {
                keyUpdateReplyPending = false
                writeOne(HANDSHAKE, byteArrayOf(KEY_UPDATE.toByte(), 0, 0, 1, 0), 0, 5, protect = true) // update_not_requested, under the OLD keys
                writeEpoch = writeEpoch!!.next()
            }
            writeOne(type, data, off, len, protect)
        }
    }

    private fun writeOne(type: Int, data: ByteArray, off: Int, len: Int, protect: Boolean) {
        val epoch = if (protect) writeEpoch else null
        val record: ByteArray
        if (epoch == null) {
            record = ByteArray(5 + len)
            record[0] = type.toByte(); record[1] = 3; record[2] = 3; record[3] = (len ushr 8).toByte(); record[4] = len.toByte()
            System.arraycopy(data, off, record, 5, len)
        } else {
            val inner = ByteArray(len + 1).also { System.arraycopy(data, off, it, 0, len); it[len] = type.toByte() }
            val encryptedLength = inner.size + 16
            val header = byteArrayOf(APPLICATION_DATA.toByte(), 3, 3, (encryptedLength ushr 8).toByte(), encryptedLength.toByte())
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, epoch.key, GCMParameterSpec(128, epoch.nonce()))
            cipher.updateAAD(header)
            record = header + cipher.doFinal(inner)
            epoch.seq++
        }
        rawOut.write(record)
    }

    /** Reads one record and returns (content type, content), decrypting when keys are installed; null at end of stream. */
    private fun readRecord(): Pair<Int, ByteArray>? {
        val header = ByteArray(5)
        try { rawIn.readFully(header) } catch (_: EOFException) { return null }
        val outerType = header[0].toInt() and 0xff
        val length = ((header[3].toInt() and 0xff) shl 8) or (header[4].toInt() and 0xff)
        if (length > MAX_FRAGMENT + 256) throw SSLException("TLS record too large: $length")
        val body = ByteArray(length).also { rawIn.readFully(it) }
        val epoch = readEpoch
        // Plain records are only legal before the handshake keys exist; a ChangeCipherSpec may appear at any time.
        if (epoch == null || outerType == CHANGE_CIPHER_SPEC) return outerType to body
        if (outerType != APPLICATION_DATA) throw SSLException("unprotected record of type $outerType after the handshake keys were installed")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, epoch.key, GCMParameterSpec(128, epoch.nonce()))
        cipher.updateAAD(header)
        val inner = try { cipher.doFinal(body) } catch (e: java.security.GeneralSecurityException) { throw SSLException("bad_record_mac: ${e.message}") }
        epoch.seq++
        var end = inner.size
        while (end > 0 && inner[end - 1].toInt() == 0) end--
        if (end == 0) throw SSLException("TLS record without a content type")
        return (inner[end - 1].toInt() and 0xff) to inner.copyOf(end - 1)
    }

    override fun close() {
        if (closed) return
        // close_notify is best effort: if a writer is stuck on a full socket, closing the socket is what unsticks it.
        if (writeLock.tryLock(200, TimeUnit.MILLISECONDS)) {
            try { if (writeEpoch != null && !closed) writeOne(ALERT, byteArrayOf(1, 0), 0, 2, protect = true) } catch (_: Exception) { } finally { writeLock.unlock() }
        }
        closed = true
        runCatching { socket.close() }
    }

    companion object {
        private const val CHANGE_CIPHER_SPEC = 20
        private const val ALERT = 21
        private const val HANDSHAKE = 22
        private const val APPLICATION_DATA = 23
        private const val KEY_UPDATE = 24
        private const val MAX_FRAGMENT = 16_384
        private const val MAX_HANDSHAKE_MESSAGE = 1 shl 17

        /** Runs the TLS 1.3 handshake on an already connected [socket] (SNI [serverName], certificates checked by [trust] and matched to the name). */
        fun connect(socket: Socket, serverName: String, trust: X509TrustManager, handshakeTimeoutMs: Int, random: SecureRandom = SecureRandom()): Tls13Connection {
            val c = Tls13Connection(socket)
            try {
                socket.soTimeout = handshakeTimeoutMs
                c.handshake(serverName, trust, random)
                socket.soTimeout = 0
                return c
            } catch (e: Exception) {
                runCatching { socket.close() }
                throw e
            }
        }

        /** HKDF-Expand-Label (RFC 8446 section 7.1); the implementation lives in [Tls13Crypto]. */
        fun expandLabel(secret: ByteArray, label: String, context: ByteArray, length: Int): ByteArray = Tls13Crypto.expandLabel(secret, label, context, length)
    }
}
