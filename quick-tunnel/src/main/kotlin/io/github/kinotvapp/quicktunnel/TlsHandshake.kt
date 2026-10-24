package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager

/**
 * A TLS 1.3 handshake failure. [alert] is the RFC 8446 section 6 alert description that a conforming client would send for
 * it; the state machine itself does no I/O, so it is only informational. It extends [SSLHandshakeException] so callers that
 * catch the platform's exception type keep working.
 */
internal class TlsHandshakeException(val alert: Int, message: String, cause: Throwable? = null) : SSLHandshakeException(message) {
    init { if (cause != null) initCause(cause) }
}

/** Alert descriptions (RFC 8446 section 6.2) used by [Tls13ClientHandshake]. */
internal object TlsAlert {
    const val UNEXPECTED_MESSAGE = 10
    const val HANDSHAKE_FAILURE = 40
    const val BAD_CERTIFICATE = 42
    const val UNSUPPORTED_CERTIFICATE = 43
    const val ILLEGAL_PARAMETER = 47
    const val DECODE_ERROR = 50
    const val DECRYPT_ERROR = 51
    const val PROTOCOL_VERSION = 70
    const val INTERNAL_ERROR = 80
    const val MISSING_EXTENSION = 109
    const val UNSUPPORTED_EXTENSION = 110
}

/**
 * HKDF (RFC 5869) with HMAC-SHA-256 and the TLS 1.3 key schedule helpers (RFC 8446 section 7.1), written on top of
 * `javax.crypto.Mac` only, so they behave the same on the JDK and on every Android version.
 */
internal object Tls13Crypto {
    const val HASH_LENGTH = 32
    private const val HMAC = "HmacSHA256"
    val EMPTY = ByteArray(0)
    val ZEROS = ByteArray(HASH_LENGTH)

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance(HMAC).apply { init(SecretKeySpec(key, HMAC)) }.doFinal(data)

    /** HKDF-Extract. An empty salt means a string of zero bytes as long as the hash, per RFC 5869. */
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray = hmac(if (salt.isEmpty()) ZEROS else salt, ikm)

    /** HKDF-Expand (RFC 5869 section 2.3). */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 0..255 * HASH_LENGTH)
        val mac = Mac.getInstance(HMAC).apply { init(SecretKeySpec(prk, HMAC)) }
        val out = ByteArrayOutputStream()
        var previous = EMPTY
        var counter = 1
        while (out.size() < length) {
            mac.update(previous); mac.update(info); mac.update(counter.toByte())
            previous = mac.doFinal()
            out.write(previous)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    /** HKDF-Expand-Label (RFC 8446 section 7.1): the info is length, "tls13 " + label, and the context, each length-prefixed. */
    fun expandLabel(secret: ByteArray, label: String, context: ByteArray, length: Int): ByteArray {
        val full = "tls13 $label".toByteArray(Charsets.ISO_8859_1)
        val info = ByteArrayOutputStream().apply {
            write(length ushr 8); write(length); write(full.size); write(full); write(context.size); write(context)
        }.toByteArray()
        return expand(secret, info, length)
    }

    /** Derive-Secret: Expand-Label with the transcript hash as context and the hash length as output length. */
    fun deriveSecret(secret: ByteArray, label: String, transcriptHash: ByteArray): ByteArray = expandLabel(secret, label, transcriptHash, HASH_LENGTH)

    /** The verify_data of a Finished message (RFC 8446 section 4.4.4). */
    fun finishedVerifyData(trafficSecret: ByteArray, transcriptHash: ByteArray): ByteArray =
        hmac(expandLabel(trafficSecret, "finished", EMPTY, HASH_LENGTH), transcriptHash)
}

/**
 * The TLS 1.3 key schedule for TLS_AES_128_GCM_SHA256 (RFC 8446 section 7.1), up to the application traffic secrets.
 * It is a plain function of the ECDHE shared secret and of two transcript hashes, which is what makes it checkable
 * byte for byte against the RFC 8448 traces.
 *
 * @param helloHash Hash(ClientHello .. ServerHello)
 */
internal class Tls13KeySchedule(ecdheSecret: ByteArray, helloHash: ByteArray) {
    private val emptyHash = Tls13Crypto.sha256(Tls13Crypto.EMPTY)

    // No PSK is ever offered, so the early secret comes from an all-zero PSK.
    val earlySecret: ByteArray = Tls13Crypto.extract(Tls13Crypto.ZEROS, Tls13Crypto.ZEROS)
    val handshakeSecret: ByteArray = Tls13Crypto.extract(Tls13Crypto.deriveSecret(earlySecret, "derived", emptyHash), ecdheSecret)
    val clientHandshakeTrafficSecret: ByteArray = Tls13Crypto.deriveSecret(handshakeSecret, "c hs traffic", helloHash)
    val serverHandshakeTrafficSecret: ByteArray = Tls13Crypto.deriveSecret(handshakeSecret, "s hs traffic", helloHash)
    val masterSecret: ByteArray = Tls13Crypto.extract(Tls13Crypto.deriveSecret(handshakeSecret, "derived", emptyHash), Tls13Crypto.ZEROS)

    /** @param finishedHash Hash(ClientHello .. server Finished) */
    fun clientApplicationTrafficSecret(finishedHash: ByteArray): ByteArray = Tls13Crypto.deriveSecret(masterSecret, "c ap traffic", finishedHash)
    fun serverApplicationTrafficSecret(finishedHash: ByteArray): ByteArray = Tls13Crypto.deriveSecret(masterSecret, "s ap traffic", finishedHash)
}

/**
 * The client side of a TLS 1.3 1-RTT handshake (RFC 8446), as a state machine with no I/O.
 *
 * The record layer feeds it one complete handshake message at a time (4-byte header included) and says whether the record
 * carrying it was protected with the handshake keys. It answers with the messages that must be sent and exposes the traffic
 * secrets the record layer has to install:
 *
 * 1. [clientHello] -> send in plaintext.
 * 2. [receive] each server message. A HelloRetryRequest makes it return a second ClientHello (plaintext). After the
 *    ServerHello, [handshakeSecrets] is set: install both directions BEFORE reading the next record.
 * 3. After the server Finished verifies, [receive] returns our Finished (send it under the HANDSHAKE write keys), and
 *    [applicationSecrets] and [isComplete] are set: switch both directions to the application keys.
 * 4. Later messages (NewSessionTicket) go to [onPostHandshake]; KeyUpdate stays with the record layer.
 *
 * Scope: TLS_AES_128_GCM_SHA256, secp256r1/384/521 ECDHE, no PSK, no early data, no ALPN, no client certificate.
 * The server certificate chain must pass [trust], its leaf must match the server name (see [TlsHostname]), and the
 * CertificateVerify and Finished messages must verify; nothing else is accepted. Any violation throws
 * [TlsHandshakeException] and leaves the machine unusable.
 *
 * @param random injectable so tests can make the handshake deterministic.
 */
internal class Tls13ClientHandshake(
    serverName: String,
    private val trust: X509TrustManager,
    private val random: SecureRandom = SecureRandom(),
) {
    /** A handshake message to send. [underHandshakeKeys] false = plaintext record (ClientHello); true = protected with the handshake keys. */
    class Outgoing(val bytes: ByteArray, val underHandshakeKeys: Boolean)

    class TrafficSecrets(val client: ByteArray, val server: ByteArray)

    private enum class State { START, WAIT_SERVER_HELLO, WAIT_SERVER_HELLO_AFTER_RETRY, WAIT_ENCRYPTED_EXTENSIONS, WAIT_CERTIFICATE, WAIT_CERTIFICATE_VERIFY, WAIT_FINISHED, CONNECTED, FAILED }

    /** One ephemeral key share: the key pair, its curve parameters (for validating the peer's point) and the wire encoding. */
    private class KeyShare(val group: Int, val pair: KeyPair, val params: ECParameterSpec, val encoded: ByteArray)

    /** The name we want to reach, as compared with the certificate: no trailing dot, A-labels, lower case (or an IP literal as given). */
    private val peerName: String
    private val sendSni: Boolean

    private var state = State.START
    private val clientRandom = ByteArray(32)
    private val transcript = ByteArrayOutputStream()
    private var keyShare: KeyShare? = null
    private var cookie: ByteArray? = null
    private var schedule: Tls13KeySchedule? = null
    private var certificateHash: ByteArray? = null
    private var leaf: X509Certificate? = null

    /** Handshake traffic secrets, available once the ServerHello has been processed. */
    var handshakeSecrets: TrafficSecrets? = null
        private set

    /** Application traffic secrets, available once the server Finished has been verified. */
    var applicationSecrets: TrafficSecrets? = null
        private set

    val isComplete: Boolean get() = state == State.CONNECTED

    init {
        EcParametersPolyfill.ensureInstalled()
        if (TlsHostname.isIpLiteral(serverName)) { peerName = serverName; sendSni = false }
        else { peerName = TlsHostname.normalize(serverName) ?: throw IllegalArgumentException("invalid server name: $serverName"); sendSni = true }
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /** The first ClientHello (a complete handshake message), to be sent in a plaintext record. Call exactly once, first. */
    fun clientHello(): ByteArray {
        check(state == State.START) { "clientHello() was already called" }
        random.nextBytes(clientRandom)
        keyShare = generateShare(GROUP_SECP256R1)
        val hello = buildClientHello()
        transcript.write(hello)
        state = State.WAIT_SERVER_HELLO
        return hello
    }

    /**
     * Legacy_session_id is empty on purpose: it is only needed for middlebox compatibility mode, which a record layer that
     * ignores ChangeCipherSpec does not require, and it keeps the ServerHello echo check trivial.
     */
    private fun buildClientHello(): ByteArray {
        val share = keyShare!!
        val exts = ByteArrayOutputStream()
        if (sendSni) {
            val name = peerName.toByteArray(Charsets.US_ASCII)
            exts.extension(EXT_SERVER_NAME, ByteArrayOutputStream().apply { u16(name.size + 3); u8(0); u16(name.size); write(name) }.toByteArray())
        }
        exts.extension(EXT_SUPPORTED_GROUPS, ByteArrayOutputStream().apply { u16(SUPPORTED_GROUPS.size * 2); SUPPORTED_GROUPS.forEach { u16(it) } }.toByteArray())
        exts.extension(EXT_SIGNATURE_ALGORITHMS, ByteArrayOutputStream().apply { u16(TlsSignatures.OFFERED.size * 2); TlsSignatures.OFFERED.forEach { u16(it) } }.toByteArray())
        exts.extension(EXT_SUPPORTED_VERSIONS, byteArrayOf(2, 3, 4))
        exts.extension(EXT_KEY_SHARE, ByteArrayOutputStream().apply { u16(share.encoded.size + 4); u16(share.group); u16(share.encoded.size); write(share.encoded) }.toByteArray())
        cookie?.let { c -> exts.extension(EXT_COOKIE, ByteArrayOutputStream().apply { u16(c.size); write(c) }.toByteArray()) }

        val body = ByteArrayOutputStream().apply {
            u16(0x0303); write(clientRandom)
            u8(0) // legacy_session_id: empty
            u16(2); u16(CIPHER_TLS_AES_128_GCM_SHA256)
            u8(1); u8(0) // compression: null only
            u16(exts.size()); write(exts.toByteArray())
        }.toByteArray()
        return handshakeMessage(HS_CLIENT_HELLO, body)
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /**
     * Processes one complete server handshake message. Returns what to send in response (usually nothing).
     * @param underHandshakeKeys whether the record that carried it was protected with the handshake keys
     */
    fun receive(message: ByteArray, underHandshakeKeys: Boolean): List<Outgoing> {
        try {
            return dispatch(message, underHandshakeKeys)
        } catch (e: TlsHandshakeException) {
            state = State.FAILED; throw e
        } catch (e: RuntimeException) { // a bug or a platform quirk must still fail closed
            state = State.FAILED; throw TlsHandshakeException(TlsAlert.INTERNAL_ERROR, "internal error during the TLS handshake: $e", e)
        }
    }

    private fun dispatch(message: ByteArray, underHandshakeKeys: Boolean): List<Outgoing> {
        if (message.size < 4) fail(TlsAlert.DECODE_ERROR, "truncated handshake message header")
        val type = message[0].toInt() and 0xff
        val declared = ((message[1].toInt() and 0xff) shl 16) or ((message[2].toInt() and 0xff) shl 8) or (message[3].toInt() and 0xff)
        if (declared != message.size - 4) fail(TlsAlert.DECODE_ERROR, "handshake message length ($declared) does not match the data (${message.size - 4})")
        when (state) {
            State.START -> fail(TlsAlert.UNEXPECTED_MESSAGE, "no ClientHello was sent yet")
            State.FAILED -> fail(TlsAlert.INTERNAL_ERROR, "the handshake already failed")
            State.CONNECTED -> fail(TlsAlert.UNEXPECTED_MESSAGE, "handshake message $type after the handshake finished; use onPostHandshake")
            State.WAIT_SERVER_HELLO, State.WAIT_SERVER_HELLO_AFTER_RETRY -> {
                if (type != HS_SERVER_HELLO) fail(TlsAlert.UNEXPECTED_MESSAGE, "expected ServerHello, got handshake message $type")
                if (underHandshakeKeys) fail(TlsAlert.UNEXPECTED_MESSAGE, "ServerHello must not be encrypted")
                return serverHello(message)
            }
            else -> if (!underHandshakeKeys) fail(TlsAlert.UNEXPECTED_MESSAGE, "handshake message $type arrived unprotected after the ServerHello")
        }
        return when (state) {
            State.WAIT_ENCRYPTED_EXTENSIONS -> { expect(type, HS_ENCRYPTED_EXTENSIONS, "EncryptedExtensions"); encryptedExtensions(message); transcript.write(message); state = State.WAIT_CERTIFICATE; emptyList() }
            State.WAIT_CERTIFICATE -> {
                if (type == HS_CERTIFICATE_REQUEST) fail(TlsAlert.HANDSHAKE_FAILURE, "the server asked for a client certificate, which this client does not support")
                expect(type, HS_CERTIFICATE, "Certificate")
                certificate(message); transcript.write(message)
                certificateHash = transcriptHash() // CertificateVerify signs the transcript up to and including Certificate
                state = State.WAIT_CERTIFICATE_VERIFY; emptyList()
            }
            State.WAIT_CERTIFICATE_VERIFY -> { expect(type, HS_CERTIFICATE_VERIFY, "CertificateVerify"); certificateVerify(message); transcript.write(message); state = State.WAIT_FINISHED; emptyList() }
            State.WAIT_FINISHED -> { expect(type, HS_FINISHED, "Finished"); finished(message) }
            else -> fail(TlsAlert.INTERNAL_ERROR, "unreachable state $state")
        }
    }

    private fun expect(actual: Int, wanted: Int, name: String) {
        if (actual != wanted) fail(TlsAlert.UNEXPECTED_MESSAGE, "expected $name, got handshake message $actual")
    }

    /** Messages that follow the handshake. NewSessionTicket is accepted and ignored (no resumption); anything else is a protocol error. */
    fun onPostHandshake(message: ByteArray) {
        if (state != State.CONNECTED) fail(TlsAlert.UNEXPECTED_MESSAGE, "post-handshake message before the handshake finished")
        if (message.size < 4) fail(TlsAlert.DECODE_ERROR, "truncated handshake message header")
        val type = message[0].toInt() and 0xff
        if (type != HS_NEW_SESSION_TICKET) fail(TlsAlert.UNEXPECTED_MESSAGE, "unexpected post-handshake message $type")
        val r = Reader(message, 4)
        r.u32(); r.u32(); r.bytes(r.u8()) // lifetime, age_add, nonce
        if (r.bytes(r.u16()).isEmpty()) fail(TlsAlert.DECODE_ERROR, "NewSessionTicket without a ticket")
        parseExtensions(r.sub(r.u16())); r.expectEnd()
    }

    // ── ServerHello / HelloRetryRequest ──────────────────────────────────────

    private fun serverHello(message: ByteArray): List<Outgoing> {
        val r = Reader(message, 4)
        val legacyVersion = r.u16()
        val serverRandom = r.bytes(32)
        val sessionId = r.bytes(r.u8())
        val cipher = r.u16()
        val compression = r.u8()
        val exts = parseExtensions(if (r.remaining() == 0) Reader(EMPTY, 0) else r.sub(r.u16()))
        r.expectEnd()

        // Version first: a TLS 1.2 server answers with a perfectly valid 1.2 ServerHello whose extensions we would not understand.
        if (legacyVersion != 0x0303) fail(TlsAlert.PROTOCOL_VERSION, "the server selected a protocol older than TLS 1.3 (0x${legacyVersion.toString(16)})")
        val versions = exts[EXT_SUPPORTED_VERSIONS] ?: fail(TlsAlert.PROTOCOL_VERSION, "the server does not support TLS 1.3 (no supported_versions in its ServerHello)")
        if (versions.size != 2) fail(TlsAlert.DECODE_ERROR, "malformed supported_versions in ServerHello")
        val selected = ((versions[0].toInt() and 0xff) shl 8) or (versions[1].toInt() and 0xff)
        if (selected != 0x0304) fail(TlsAlert.PROTOCOL_VERSION, "the server selected TLS version 0x${selected.toString(16)}, not 1.3")

        if (!sessionId.contentEquals(EMPTY)) fail(TlsAlert.ILLEGAL_PARAMETER, "legacy_session_id_echo does not match the (empty) session id we sent")
        if (cipher != CIPHER_TLS_AES_128_GCM_SHA256) fail(TlsAlert.ILLEGAL_PARAMETER, "the server selected cipher suite 0x${cipher.toString(16)}, which we did not offer")
        if (compression != 0) fail(TlsAlert.ILLEGAL_PARAMETER, "the server selected a compression method")
        val isRetry = serverRandom.contentEquals(HELLO_RETRY_REQUEST_RANDOM)
        if (isRetry && state == State.WAIT_SERVER_HELLO_AFTER_RETRY) fail(TlsAlert.UNEXPECTED_MESSAGE, "a second HelloRetryRequest")
        // RFC 8446 section 4.1.3: a server that negotiates TLS 1.3 never sets the downgrade sentinels.
        val tail = serverRandom.copyOfRange(24, 32)
        if (tail.contentEquals(DOWNGRADE_TLS12) || tail.contentEquals(DOWNGRADE_TLS11)) fail(TlsAlert.ILLEGAL_PARAMETER, "downgrade protection sentinel in ServerHello.random")
        val allowed = if (isRetry) setOf(EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_COOKIE) else setOf(EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE)
        exts.keys.firstOrNull { it !in allowed }?.let { fail(TlsAlert.UNSUPPORTED_EXTENSION, "extension $it is not allowed in a ${if (isRetry) "HelloRetryRequest" else "ServerHello"}") }

        return if (isRetry) helloRetryRequest(message, exts) else acceptServerHello(message, exts)
    }

    /** RFC 8446 section 4.1.4: restart with the group the server asked for and echo its cookie. */
    private fun helloRetryRequest(message: ByteArray, exts: Map<Int, ByteArray>): List<Outgoing> {
        val group = exts[EXT_KEY_SHARE]?.let { d ->
            if (d.size != 2) fail(TlsAlert.DECODE_ERROR, "malformed key_share in HelloRetryRequest")
            ((d[0].toInt() and 0xff) shl 8) or (d[1].toInt() and 0xff)
        }
        val cookieData = exts[EXT_COOKIE]?.let { d ->
            val cr = Reader(d, 0); val c = cr.bytes(cr.u16()); cr.expectEnd()
            if (c.isEmpty()) fail(TlsAlert.DECODE_ERROR, "empty cookie in HelloRetryRequest")
            c
        }
        if (group == null && cookieData == null) fail(TlsAlert.ILLEGAL_PARAMETER, "HelloRetryRequest that changes nothing")
        if (group != null) {
            if (group !in SUPPORTED_GROUPS) fail(TlsAlert.ILLEGAL_PARAMETER, "HelloRetryRequest selects group 0x${group.toString(16)}, which we did not offer")
            if (group == keyShare!!.group) fail(TlsAlert.ILLEGAL_PARAMETER, "HelloRetryRequest asks for the group we already sent a share for")
            keyShare = generateShare(group)
        }
        if (cookieData != null) cookie = cookieData

        // RFC 8446 section 4.4.1: the first ClientHello is replaced in the transcript by a synthetic message_hash message.
        val firstHash = Tls13Crypto.sha256(transcript.toByteArray())
        transcript.reset()
        transcript.write(handshakeMessage(HS_MESSAGE_HASH, firstHash))
        transcript.write(message)
        val second = buildClientHello()
        transcript.write(second)
        state = State.WAIT_SERVER_HELLO_AFTER_RETRY
        return listOf(Outgoing(second, underHandshakeKeys = false))
    }

    private fun acceptServerHello(message: ByteArray, exts: Map<Int, ByteArray>): List<Outgoing> {
        val data = exts[EXT_KEY_SHARE] ?: fail(TlsAlert.MISSING_EXTENSION, "ServerHello without key_share (we offer no PSK)")
        val kr = Reader(data, 0)
        val group = kr.u16(); val peerPoint = kr.bytes(kr.u16()); kr.expectEnd()
        val share = keyShare!!
        if (group != share.group) fail(TlsAlert.ILLEGAL_PARAMETER, "the server selected group 0x${group.toString(16)}, but we only sent a share for 0x${share.group.toString(16)}")

        val shared = try {
            val point = decodePoint(peerPoint, share.params)
            val peerKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, share.params))
            KeyAgreement.getInstance("ECDH").run { init(share.pair.private); doPhase(peerKey, true); generateSecret() }
        } catch (e: GeneralSecurityException) { fail(TlsAlert.ILLEGAL_PARAMETER, "invalid server key share: ${e.message}", e) }

        transcript.write(message)
        val ks = Tls13KeySchedule(shared, transcriptHash())
        schedule = ks
        handshakeSecrets = TrafficSecrets(ks.clientHandshakeTrafficSecret, ks.serverHandshakeTrafficSecret)
        state = State.WAIT_ENCRYPTED_EXTENSIONS
        return emptyList()
    }

    // ── Encrypted flight ─────────────────────────────────────────────────────

    private fun encryptedExtensions(message: ByteArray) {
        val r = Reader(message, 4)
        val exts = parseExtensions(r.sub(r.u16())); r.expectEnd()
        // RFC 8446 section 4.2: an extension we did not ask for is a protocol error, except the two a server may volunteer.
        exts.keys.firstOrNull { it !in ENCRYPTED_EXTENSIONS_ALLOWED }?.let { fail(TlsAlert.UNSUPPORTED_EXTENSION, "unsolicited extension $it in EncryptedExtensions") }
    }

    private fun certificate(message: ByteArray) {
        val r = Reader(message, 4)
        if (r.u8() != 0) fail(TlsAlert.ILLEGAL_PARAMETER, "non-empty certificate_request_context in a server Certificate")
        val list = r.sub(r.u24()); r.expectEnd()
        val chain = ArrayList<X509Certificate>()
        val factory = try { CertificateFactory.getInstance("X.509") } catch (e: GeneralSecurityException) { fail(TlsAlert.INTERNAL_ERROR, "no X.509 support: ${e.message}", e) }
        while (list.remaining() > 0) {
            val der = list.bytes(list.u24())
            if (der.isEmpty()) fail(TlsAlert.DECODE_ERROR, "empty certificate in the chain")
            parseExtensions(list.sub(list.u16())) // per-certificate extensions (OCSP, SCT) are checked for shape and ignored
            if (chain.size >= MAX_CHAIN) fail(TlsAlert.BAD_CERTIFICATE, "certificate chain too long")
            chain += try { factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate }
            catch (e: GeneralSecurityException) { fail(TlsAlert.BAD_CERTIFICATE, "unparseable certificate: ${e.message}", e) }
        }
        if (chain.isEmpty()) fail(TlsAlert.DECODE_ERROR, "the server sent no certificate")
        val leaf = chain[0]

        // X509TrustManager.checkServerTrusted wants a key-exchange name, not a key type: the JDK's end-entity checker throws
        // "Unknown authType: ECDSA" on a chain issued by a CA (a self-signed leaf skips that check, which is why only the real
        // edge showed it). TLS 1.3 always uses ECDHE; the certificate key only authenticates.
        val authType = when (leaf.publicKey.algorithm) {
            "EC" -> "ECDHE_ECDSA"
            "RSA" -> "ECDHE_RSA"
            else -> fail(TlsAlert.UNSUPPORTED_CERTIFICATE, "unsupported certificate key type ${leaf.publicKey.algorithm}")
        }
        // Chain first (who issued it), then name (whom it was issued to): neither implies the other. See TlsHostname.
        try {
            trust.checkServerTrusted(chain.toTypedArray(), authType)
            TlsHostname.verify(leaf, peerName)
        } catch (e: CertificateException) {
            fail(TlsAlert.BAD_CERTIFICATE, "server certificate rejected: ${e.message}", e)
        }
        this.leaf = leaf
    }

    private fun certificateVerify(message: ByteArray) {
        val r = Reader(message, 4)
        val scheme = r.u16()
        val signature = r.bytes(r.u16()); r.expectEnd()
        if (scheme !in TlsSignatures.OFFERED) fail(TlsAlert.ILLEGAL_PARAMETER, "the server signed with scheme 0x${scheme.toString(16)}, which we did not offer")
        // RFC 8446 section 4.4.3: 64 spaces, a context string, a zero byte, then the transcript hash up to Certificate.
        val signed = ByteArrayOutputStream().apply {
            repeat(64) { write(0x20) }
            write("TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII)); write(0)
            write(certificateHash!!)
        }.toByteArray()
        val ok = try {
            TlsSignatures.verify(scheme, leaf!!.publicKey, signed, signature)
        } catch (e: GeneralSecurityException) { fail(TlsAlert.ILLEGAL_PARAMETER, "CertificateVerify scheme 0x${scheme.toString(16)} cannot be used with the server's key: ${e.message}", e) }
        if (!ok) fail(TlsAlert.DECRYPT_ERROR, "the CertificateVerify signature is invalid")
    }

    private fun finished(message: ByteArray): List<Outgoing> {
        val ks = schedule!!
        if (message.size != 4 + Tls13Crypto.HASH_LENGTH) fail(TlsAlert.DECODE_ERROR, "Finished has the wrong length")
        val expected = Tls13Crypto.finishedVerifyData(ks.serverHandshakeTrafficSecret, transcriptHash()) // transcript through CertificateVerify
        // Constant time: the comparison must not leak how many leading bytes of a forged MAC were right.
        if (!MessageDigest.isEqual(expected, message.copyOfRange(4, message.size))) fail(TlsAlert.DECRYPT_ERROR, "the server Finished does not verify")
        transcript.write(message)

        val throughServerFinished = transcriptHash()
        // Our Finished covers the same transcript as the application secrets (RFC 8446 section 7.1: through the SERVER Finished).
        val clientFinished = handshakeMessage(HS_FINISHED, Tls13Crypto.finishedVerifyData(ks.clientHandshakeTrafficSecret, throughServerFinished))
        applicationSecrets = TrafficSecrets(ks.clientApplicationTrafficSecret(throughServerFinished), ks.serverApplicationTrafficSecret(throughServerFinished))
        state = State.CONNECTED
        return listOf(Outgoing(clientFinished, underHandshakeKeys = true))
    }

    private fun transcriptHash(): ByteArray = Tls13Crypto.sha256(transcript.toByteArray())

    // ── Key exchange ─────────────────────────────────────────────────────────

    private fun generateShare(group: Int): KeyShare {
        val curve = GROUP_NAMES[group] ?: throw IllegalArgumentException("unsupported group $group")
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve), random) }.generateKeyPair()
        val pub = pair.public as ECPublicKey
        val size = (pub.params.curve.field.fieldSize + 7) / 8
        val encoded = ByteArrayOutputStream().apply { write(4); write(fixed(pub.w.affineX, size)); write(fixed(pub.w.affineY, size)) }.toByteArray()
        return KeyShare(group, pair, pub.params, encoded)
    }

    /** Big-endian, left-padded or stripped of its sign byte to exactly [size] bytes. */
    private fun fixed(v: BigInteger, size: Int): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == size -> raw
            raw.size > size -> raw.copyOfRange(raw.size - size, raw.size)
            else -> ByteArray(size - raw.size) + raw
        }
    }

    /**
     * An uncompressed point from the peer, validated: right length, 0x04 prefix, both coordinates below the field prime and
     * on the curve. Uncompressed affine coordinates cannot encode the point at infinity, and the curves have cofactor 1, so
     * "on the curve" is also "in the right subgroup" (RFC 8446 section 4.2.8.2 requires this check).
     */
    private fun decodePoint(data: ByteArray, params: ECParameterSpec): ECPoint {
        val size = (params.curve.field.fieldSize + 7) / 8
        if (data.size != 1 + 2 * size || data[0].toInt() != 4) fail(TlsAlert.ILLEGAL_PARAMETER, "key share is not an uncompressed point of the right length")
        val x = BigInteger(1, data.copyOfRange(1, 1 + size))
        val y = BigInteger(1, data.copyOfRange(1 + size, data.size))
        val p = (params.curve.field as ECFieldFp).p
        if (x >= p || y >= p) fail(TlsAlert.ILLEGAL_PARAMETER, "key share coordinate out of range")
        val lhs = y.multiply(y).mod(p)
        val rhs = x.multiply(x).mod(p).multiply(x).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)
        if (lhs != rhs) fail(TlsAlert.ILLEGAL_PARAMETER, "key share is not a point on the curve")
        return ECPoint(x, y)
    }

    // ── Wire helpers ─────────────────────────────────────────────────────────

    private fun fail(alert: Int, message: String, cause: Throwable? = null): Nothing = throw TlsHandshakeException(alert, message, cause)

    /** Bounds-checked big-endian reader; running off the end is a decode_error rather than an IndexOutOfBounds. */
    private inner class Reader(private val data: ByteArray, start: Int, private val end: Int = data.size) {
        private var pos = start
        fun remaining() = end - pos
        private fun need(n: Int) { if (n < 0 || n > remaining()) fail(TlsAlert.DECODE_ERROR, "truncated or malformed handshake message") }
        fun u8(): Int { need(1); return data[pos++].toInt() and 0xff }
        fun u16(): Int { need(2); return (u8() shl 8) or u8() }
        fun u24(): Int { need(3); return (u8() shl 16) or (u8() shl 8) or u8() }
        fun u32(): Long { need(4); return (u16().toLong() shl 16) or u16().toLong() }
        fun bytes(n: Int): ByteArray { need(n); return data.copyOfRange(pos, pos + n).also { pos += n } }
        fun sub(n: Int): Reader { need(n); return Reader(data, pos, pos + n).also { pos += n } }
        fun expectEnd() { if (remaining() != 0) fail(TlsAlert.DECODE_ERROR, "trailing bytes after a handshake message body") }
        fun rest(): ByteArray = bytes(remaining())
    }

    /** Extension block -> type to data. A repeated type is illegal (RFC 8446 section 4.2). */
    private fun parseExtensions(r: Reader): Map<Int, ByteArray> {
        val map = LinkedHashMap<Int, ByteArray>()
        while (r.remaining() > 0) {
            val type = r.u16()
            val data = r.bytes(r.u16())
            if (map.put(type, data) != null) fail(TlsAlert.ILLEGAL_PARAMETER, "duplicate extension $type")
        }
        return map
    }

    companion object {
        private val EMPTY = ByteArray(0)
        private const val HS_CLIENT_HELLO = 1
        private const val HS_SERVER_HELLO = 2
        private const val HS_NEW_SESSION_TICKET = 4
        private const val HS_ENCRYPTED_EXTENSIONS = 8
        private const val HS_CERTIFICATE = 11
        private const val HS_CERTIFICATE_REQUEST = 13
        private const val HS_CERTIFICATE_VERIFY = 15
        private const val HS_FINISHED = 20
        private const val HS_MESSAGE_HASH = 254

        private const val EXT_SERVER_NAME = 0
        private const val EXT_SUPPORTED_GROUPS = 10
        private const val EXT_SIGNATURE_ALGORITHMS = 13
        private const val EXT_SUPPORTED_VERSIONS = 43
        private const val EXT_COOKIE = 44
        private const val EXT_KEY_SHARE = 51

        private const val CIPHER_TLS_AES_128_GCM_SHA256 = 0x1301
        private const val GROUP_SECP256R1 = 0x0017
        private val SUPPORTED_GROUPS = intArrayOf(0x0017, 0x0018, 0x0019)
        private val GROUP_NAMES = mapOf(0x0017 to "secp256r1", 0x0018 to "secp384r1", 0x0019 to "secp521r1")

        /** A server may volunteer server_name (acknowledging ours) and supported_groups in EncryptedExtensions; anything else we never asked for. */
        private val ENCRYPTED_EXTENSIONS_ALLOWED = setOf(EXT_SERVER_NAME, EXT_SUPPORTED_GROUPS)

        private const val MAX_CHAIN = 16

        /** RFC 8446 section 4.1.3: the fixed ServerHello.random value that marks a HelloRetryRequest (SHA-256 of "HelloRetryRequest"). */
        private val HELLO_RETRY_REQUEST_RANDOM = hex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
        private val DOWNGRADE_TLS12 = "DOWNGRD".toByteArray(Charsets.US_ASCII) + byteArrayOf(1)
        private val DOWNGRADE_TLS11 = "DOWNGRD".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)

        private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

        private fun handshakeMessage(type: Int, body: ByteArray): ByteArray =
            byteArrayOf(type.toByte(), (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body

        private fun ByteArrayOutputStream.u8(v: Int) = write(v)
        private fun ByteArrayOutputStream.u16(v: Int) { write(v ushr 8); write(v) }
        private fun ByteArrayOutputStream.extension(type: Int, body: ByteArray) { u16(type); u16(body.size); write(body) }
    }
}
