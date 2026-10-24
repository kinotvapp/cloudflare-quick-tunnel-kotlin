package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.concurrent.CompletableFuture
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.KeyFactory

/**
 * A hand-made TLS 1.3 server for tests: it speaks the protocol with its own helpers so that a test can corrupt one chosen
 * thing (a signature, a Finished, the cipher, the order of messages, ...) and check that the client refuses. It is a TEST
 * double and trusts nothing: its key schedule is the [Tls13KeySchedule] that the RFC 8448 test verifies byte for byte.
 */
internal class FakeTlsServer(private val cfg: Config) : AutoCloseable {
    class Config(
        val identity: TestIdentity,
        val cipher: Int = 0x1301,
        val legacyVersion: Int = 0x0303,
        /** null = leave supported_versions out of the ServerHello (what a TLS 1.2 server does). */
        val supportedVersion: Int? = 0x0304,
        /** The group the ServerHello claims. If the client sent no share for it, the server invents a key and the secret is junk. */
        val shGroup: Int = 0x0017,
        /** Send one HelloRetryRequest per entry (asking for that group) before the real ServerHello. */
        val retryGroups: List<Int> = emptyList(),
        val cookie: ByteArray? = null,
        val extraServerHelloExt: List<Pair<Int, ByteArray>> = emptyList(),
        val compression: Int = 0,
        val sessionIdEcho: ByteArray? = null,
        val offCurvePoint: Boolean = false,
        val sigSchemeOverride: Int? = null,
        /** Edit a message just before it is added to the transcript and sent. [name] is EE, Cert, CV or Fin. */
        val tamper: (name: String, message: ByteArray) -> ByteArray = { _, m -> m },
        /** Edit the finished flight (insert, drop, duplicate, reorder). Names as above. */
        val flight: (MutableList<Pair<String, ByteArray>>) -> Unit = {},
        /** Put the whole flight in one record instead of one record per message. */
        val coalesce: Boolean = false,
        /** Edit the (non-retry) ServerHello message before it is added to the transcript and sent. */
        val tamperHello: (ByteArray) -> ByteArray = { it },
    )

    private val ss = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = ss.localPort
    val clientHellos = mutableListOf<ByteArray>()
    /** True when the client's Finished arrived under the handshake keys and verified. */
    val clientFinishedVerified = CompletableFuture<Boolean>()
    /** What the client wrote after the handshake (decrypted with the application keys). */
    val clientApplicationData = CompletableFuture<String>()
    private val rnd = SecureRandom()

    init { Thread({ try { serve(ss.accept().also { it.soTimeout = 10_000 }) } catch (e: Throwable) { clientFinishedVerified.complete(false); clientApplicationData.completeExceptionally(e) } }, "fake-tls-server").apply { isDaemon = true }.start() }

    override fun close() { runCatching { ss.close() } }

    // ── records ──────────────────────────────────────────────────────────────

    private class Keys(secret: ByteArray) {
        val key = SecretKeySpec(Tls13Crypto.expandLabel(secret, "key", ByteArray(0), 16), "AES")
        val iv = Tls13Crypto.expandLabel(secret, "iv", ByteArray(0), 12)
        var seq = 0L
        fun nonce() = iv.copyOf().also { n -> for (i in 0 until 8) n[11 - i] = (n[11 - i].toInt() xor (seq ushr (8 * i)).toInt()).toByte() }
    }

    private fun plainRecord(out: OutputStream, type: Int, data: ByteArray) {
        out.write(byteArrayOf(type.toByte(), 3, 3, (data.size ushr 8).toByte(), data.size.toByte())); out.write(data); out.flush()
    }

    private fun protectedRecord(out: OutputStream, k: Keys, type: Int, data: ByteArray) {
        val inner = data + byteArrayOf(type.toByte())
        val len = inner.size + 16
        val header = byteArrayOf(23, 3, 3, (len ushr 8).toByte(), len.toByte())
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, k.key, GCMParameterSpec(128, k.nonce())); updateAAD(header) }
        k.seq++
        out.write(header); out.write(c.doFinal(inner)); out.flush()
    }

    private fun readRecord(inp: DataInputStream): Pair<Int, ByteArray> {
        val h = ByteArray(5); inp.readFully(h)
        val body = ByteArray(((h[3].toInt() and 0xff) shl 8) or (h[4].toInt() and 0xff)); inp.readFully(body)
        return (h[0].toInt() and 0xff) to body
    }

    private fun readProtected(inp: DataInputStream, k: Keys): Pair<Int, ByteArray> {
        val h = ByteArray(5); inp.readFully(h)
        val body = ByteArray(((h[3].toInt() and 0xff) shl 8) or (h[4].toInt() and 0xff)); inp.readFully(body)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, k.key, GCMParameterSpec(128, k.nonce())); updateAAD(h) }
        k.seq++
        val inner = c.doFinal(body)
        var end = inner.size; while (end > 0 && inner[end - 1].toInt() == 0) end--
        return (inner[end - 1].toInt() and 0xff) to inner.copyOf(end - 1)
    }

    // ── messages ─────────────────────────────────────────────────────────────

    private fun msg(type: Int, body: ByteArray) = byteArrayOf(type.toByte(), (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    private fun ext(type: Int, body: ByteArray) = u16(type) + u16(body.size) + body

    /** Pulls the key shares and the session id out of a ClientHello message. */
    private class ParsedHello(val sessionId: ByteArray, val shares: Map<Int, ByteArray>, val cookie: ByteArray?)

    private fun parseHello(m: ByteArray): ParsedHello {
        var p = 4 + 2 + 32
        val sid = m.copyOfRange(p + 1, p + 1 + (m[p].toInt() and 0xff)); p += 1 + sid.size
        p += 2 + (((m[p].toInt() and 0xff) shl 8) or (m[p + 1].toInt() and 0xff))
        p += 1 + (m[p].toInt() and 0xff)
        val extEnd = p + 2 + (((m[p].toInt() and 0xff) shl 8) or (m[p + 1].toInt() and 0xff)); p += 2
        val shares = HashMap<Int, ByteArray>(); var cookie: ByteArray? = null
        while (p < extEnd) {
            val type = ((m[p].toInt() and 0xff) shl 8) or (m[p + 1].toInt() and 0xff)
            val len = ((m[p + 2].toInt() and 0xff) shl 8) or (m[p + 3].toInt() and 0xff)
            val d = m.copyOfRange(p + 4, p + 4 + len); p += 4 + len
            if (type == 51) {
                var q = 2
                while (q < d.size) {
                    val g = ((d[q].toInt() and 0xff) shl 8) or (d[q + 1].toInt() and 0xff)
                    val l = ((d[q + 2].toInt() and 0xff) shl 8) or (d[q + 3].toInt() and 0xff)
                    shares[g] = d.copyOfRange(q + 4, q + 4 + l); q += 4 + l
                }
            }
            if (type == 44) cookie = d.copyOfRange(2, d.size)
        }
        return ParsedHello(sid, shares, cookie)
    }

    private fun curveName(group: Int) = when (group) { 0x0017 -> "secp256r1"; 0x0018 -> "secp384r1"; else -> "secp521r1" }

    private fun serve(socket: Socket) {
        val inp = DataInputStream(socket.getInputStream()); val out = socket.getOutputStream()
        val transcript = ByteArrayOutputStream()

        var hello = readRecord(inp).second; clientHellos += hello
        transcript.write(hello)
        var parsed = parseHello(hello)
        for (group in cfg.retryGroups) {
            val body = ByteArrayOutputStream().apply {
                write(u16(cfg.legacyVersion)); write(HRR_RANDOM); write(parsed.sessionId.size); write(parsed.sessionId)
                write(u16(cfg.cipher)); write(cfg.compression)
                val e = ByteArrayOutputStream().apply {
                    write(ext(43, u16(0x0304))); write(ext(51, u16(group)))
                    cfg.cookie?.let { write(ext(44, u16(it.size) + it)) }
                }.toByteArray()
                write(u16(e.size)); write(e)
            }.toByteArray()
            val hrr = msg(2, body)
            val firstHash = Tls13Crypto.sha256(transcript.toByteArray())
            transcript.reset(); transcript.write(msg(254, firstHash)); transcript.write(hrr)
            plainRecord(out, 22, hrr)
            hello = readRecord(inp).second; clientHellos += hello
            transcript.write(hello)
            parsed = parseHello(hello)
        }

        // ServerHello
        val curve = curveName(cfg.shGroup)
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
        val pub = kp.public as ECPublicKey
        val size = (pub.params.curve.field.fieldSize + 7) / 8
        fun fixed(v: BigInteger) = v.toByteArray().let { r -> if (r.size > size) r.copyOfRange(r.size - size, r.size) else ByteArray(size - r.size) + r }
        val y = if (cfg.offCurvePoint) fixed(pub.w.affineY.add(BigInteger.ONE)) else fixed(pub.w.affineY)
        val point = byteArrayOf(4) + fixed(pub.w.affineX) + y
        val clientShare = parsed.shares[cfg.shGroup]
        val shared = if (clientShare != null) {
            val params: ECParameterSpec = pub.params
            val half = clientShare.size / 2
            val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, clientShare.copyOfRange(1, 1 + half)), BigInteger(1, clientShare.copyOfRange(1 + half, clientShare.size))), params))
            KeyAgreement.getInstance("ECDH").run { init(kp.private); doPhase(peer, true); generateSecret() }
        } else ByteArray(32)
        val random = ByteArray(32).also { rnd.nextBytes(it) }
        val shExts = ByteArrayOutputStream().apply {
            cfg.supportedVersion?.let { write(ext(43, u16(it))) }
            write(ext(51, u16(cfg.shGroup) + u16(point.size) + point))
            cfg.extraServerHelloExt.forEach { write(ext(it.first, it.second)) }
        }.toByteArray()
        val sid = cfg.sessionIdEcho ?: parsed.sessionId
        val sh = cfg.tamperHello(msg(2, ByteArrayOutputStream().apply {
            write(u16(cfg.legacyVersion)); write(random); write(sid.size); write(sid); write(u16(cfg.cipher)); write(cfg.compression); write(u16(shExts.size)); write(shExts)
        }.toByteArray()))
        transcript.write(sh)
        plainRecord(out, 22, sh)

        val ks = Tls13KeySchedule(shared, Tls13Crypto.sha256(transcript.toByteArray()))
        val writeHs = Keys(ks.serverHandshakeTrafficSecret); val readHs = Keys(ks.clientHandshakeTrafficSecret)

        // Encrypted flight, built in order so each message is in the transcript the next one signs.
        val flight = mutableListOf<Pair<String, ByteArray>>()
        fun add(name: String, m: ByteArray): ByteArray { val t = cfg.tamper(name, m); transcript.write(t); flight += name to t; return t }
        add("EE", msg(8, u16(0)))
        val der = cfg.identity.certificate.encoded
        add("Cert", msg(11, byteArrayOf(0) + byteArrayOf((((der.size + 5) ushr 16)).toByte(), ((der.size + 5) ushr 8).toByte(), (der.size + 5).toByte()) +
            byteArrayOf((der.size ushr 16).toByte(), (der.size ushr 8).toByte(), der.size.toByte()) + der + u16(0)))
        val certHash = Tls13Crypto.sha256(transcript.toByteArray())
        val signed = ByteArray(64) { 0x20 } + "TLS 1.3, server CertificateVerify".toByteArray() + byteArrayOf(0) + certHash
        val key = cfg.identity.certificate.publicKey
        val (scheme, signature) = when {
            key is RSAPublicKey -> 0x0804 to Signature.getInstance("RSASSA-PSS").run {
                setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)); initSign(cfg.identity.privateKey); update(signed); sign()
            }
            key is ECPublicKey && key.params.curve.field.fieldSize == 384 -> 0x0503 to Signature.getInstance("SHA384withECDSA").run { initSign(cfg.identity.privateKey); update(signed); sign() }
            key is ECPublicKey && key.params.curve.field.fieldSize == 521 -> 0x0603 to Signature.getInstance("SHA512withECDSA").run { initSign(cfg.identity.privateKey); update(signed); sign() }
            else -> 0x0403 to Signature.getInstance("SHA256withECDSA").run { initSign(cfg.identity.privateKey); update(signed); sign() }
        }
        add("CV", msg(15, u16(cfg.sigSchemeOverride ?: scheme) + u16(signature.size) + signature))
        add("Fin", msg(20, Tls13Crypto.finishedVerifyData(ks.serverHandshakeTrafficSecret, Tls13Crypto.sha256(transcript.toByteArray()))))
        val throughFinished = Tls13Crypto.sha256(transcript.toByteArray())

        cfg.flight(flight)
        if (cfg.coalesce) protectedRecord(out, writeHs, 22, flight.fold(ByteArray(0)) { a, p -> a + p.second })
        else flight.forEach { protectedRecord(out, writeHs, 22, it.second) }

        // The client's Finished, under its handshake keys.
        val (type, fin) = readProtected(inp, readHs)
        val expected = msg(20, Tls13Crypto.finishedVerifyData(ks.clientHandshakeTrafficSecret, throughFinished))
        clientFinishedVerified.complete(type == 22 && fin.contentEquals(expected))

        // Application data both ways, preceded by a NewSessionTicket that the client has to accept and ignore.
        val writeApp = Keys(ks.serverApplicationTrafficSecret(throughFinished)); val readApp = Keys(ks.clientApplicationTrafficSecret(throughFinished))
        val ticket = msg(4, byteArrayOf(0, 0, 0x1e, 0, 1, 2, 3, 4, 2, 9, 9, 0, 3, 7, 7, 7, 0, 0))
        protectedRecord(out, writeApp, 22, ticket)
        protectedRecord(out, writeApp, 23, "pong".toByteArray())
        val (t2, data) = readProtected(inp, readApp)
        clientApplicationData.complete(if (t2 == 23) String(data) else "unexpected record type $t2")
    }

    companion object {
        val HRR_RANDOM = ByteArray(32).also {
            val h = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
            for (i in 0 until 32) it[i] = h.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        }
    }
}
