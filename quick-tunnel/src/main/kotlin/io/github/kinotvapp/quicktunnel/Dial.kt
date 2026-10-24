package io.github.kinotvapp.quicktunnel

import tech.kwik.core.QuicClientConnection
import tech.kwik.core.QuicStream
import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration
import java.util.function.Consumer
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

const val ALPN = "argotunnel"
const val EDGE_SNI = "quic.cftunnel.com"
const val H2_SNI = "h2.cftunnel.com"
const val HANDSHAKE_TIMEOUT_S = 10L
const val IDLE_TIMEOUT_S = 15L

/** Three Cloudflare-internal CAs that sign the edge cert. They are in no system trust store. */
private val edgeTrust: X509TrustManager by lazy {
    val pem = object {}.javaClass.getResourceAsStream("/cf-edge-roots.pem")!!.use { it.readBytes() }
    val certs = CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(pem))
    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
    certs.forEachIndexed { i, c -> ks.setCertificateEntry("cf$i", c) }
    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        .trustManagers.filterIsInstance<X509TrustManager>().first()
}

/** One QUIC handshake against one edge. SNI is the fixed name; the IP goes through `proxy`. */
fun dial(edge: EdgeAddr, onPeerStream: Consumer<QuicStream>, handshakeTimeoutS: Long = HANDSHAKE_TIMEOUT_S): QuicClientConnection {
    // Kwik finds its TLS key exchange with ServiceLoader, which reads the thread's context class loader.
    // On Android, pool threads (ForkJoinPool, executors) get the system loader, which cannot see the APK's
    // META-INF/services: the handshake then fails with "Unsupported named group(s)".
    EcParametersPolyfill.ensureInstalled()
    val thread = Thread.currentThread()
    val previous = thread.contextClassLoader
    thread.contextClassLoader = QuicClientConnection::class.java.classLoader
    try {
        return dialInThisThread(edge, onPeerStream, handshakeTimeoutS)
    } finally {
        thread.contextClassLoader = previous
    }
}

private fun dialInThisThread(edge: EdgeAddr, onPeerStream: Consumer<QuicStream>, handshakeTimeoutS: Long): QuicClientConnection {
    val conn = QuicClientConnection.newBuilder()
        .host(EDGE_SNI).port(edge.port).proxy(edge.ip.hostAddress)
        .applicationProtocol(ALPN).customTrustManager(edgeTrust)
        .maxOpenPeerInitiatedBidirectionalStreams(1000)
        .maxIdleTimeout(Duration.ofSeconds(IDLE_TIMEOUT_S))
        .connectTimeout(Duration.ofSeconds(handshakeTimeoutS))
        .build()
    conn.setPeerInitiatedStreamCallback(onPeerStream)
    conn.connect()
    conn.keepAlive(1)
    return conn
}

private val edgeTlsContext: SSLContext by lazy { SSLContext.getInstance("TLS").apply { init(null, arrayOf(edgeTrust), null) } }

/** Which TLS implementation carries the TCP transport. */
enum class TcpTls {
    /** The platform's TLS when it speaks 1.3 (Android 10+, any current JDK), otherwise the pure-Java one below. */
    AUTO,
    PLATFORM,
    /** Kwik's TLS 1.3 engine with our record layer ([Tls13Connection]). Works on every Android version. */
    PURE_JAVA,
}

/** An established TLS connection to the edge, whichever implementation is behind it. */
class TcpConnection(val input: java.io.InputStream, val output: java.io.OutputStream, private val closer: () -> Unit) : AutoCloseable {
    override fun close() = closer()
}

/** The edge's TCP endpoint only speaks TLS 1.3, which the platform's TLS gained in Android 10. */
fun platformTlsSupports13(): Boolean = runCatching { edgeTlsContext.supportedSSLParameters.protocols.contains("TLSv1.3") }.getOrDefault(false)

/**
 * TLS over TCP to the same port, for networks that drop UDP. Server name `h2.cftunnel.com`, no ALPN (cloudflared sends
 * none for this protocol), same pinned CAs. The edge then speaks HTTP/2 as the *client* on this connection.
 */
fun dialTcp(edge: EdgeAddr, timeoutS: Long = HANDSHAKE_TIMEOUT_S, tls: TcpTls = TcpTls.AUTO): TcpConnection {
    val usePlatform = when (tls) { TcpTls.PLATFORM -> true; TcpTls.PURE_JAVA -> false; TcpTls.AUTO -> platformTlsSupports13() }
    val plain = Socket()
    try {
        plain.connect(InetSocketAddress(edge.ip, edge.port), (timeoutS * 1000).toInt())
        plain.tcpNoDelay = true
        plain.keepAlive = true
        if (!usePlatform) {
            val c = Tls13Connection.connect(plain, H2_SNI, edgeTrust, (timeoutS * 1000).toInt())
            return TcpConnection(c.input, c.output) { c.close() }
        }
        plain.soTimeout = (timeoutS * 1000).toInt() // bounds the handshake only
        val socket = edgeTlsContext.socketFactory.createSocket(plain, H2_SNI, edge.port, true) as SSLSocket
        socket.startHandshake()
        socket.soTimeout = 0
        return TcpConnection(socket.inputStream, socket.outputStream) { runCatching { socket.close() } }
    } catch (e: Exception) {
        runCatching { plain.close() }
        throw e
    }
}
