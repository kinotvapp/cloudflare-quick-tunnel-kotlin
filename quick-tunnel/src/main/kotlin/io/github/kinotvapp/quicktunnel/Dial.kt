package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

const val H2_SNI = "h2.cftunnel.com"
const val HANDSHAKE_TIMEOUT_S = 10L

/** Three Cloudflare-internal CAs that sign the edge cert. They are in no system trust store. */
private val edgeTrust: X509TrustManager by lazy {
    val pem = object {}.javaClass.getResourceAsStream("/cf-edge-roots.pem")!!.use { it.readBytes() }
    val certs = CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(pem))
    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
    certs.forEachIndexed { i, c -> ks.setCertificateEntry("cf$i", c) }
    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        .trustManagers.filterIsInstance<X509TrustManager>().first()
}

private val edgeTlsContext: SSLContext by lazy { SSLContext.getInstance("TLS").apply { init(null, arrayOf(edgeTrust), null) } }

/** Which TLS implementation carries the TCP transport. */
enum class TcpTls {
    /** The platform's TLS when it speaks 1.3 (Android 10+, any current JDK), otherwise the pure-Java one below. */
    AUTO,
    PLATFORM,
    /** Our own TLS 1.3 handshake and record layer ([Tls13Connection]). Works on every Android version. */
    PURE_JAVA,
}

/** An established TLS connection to the edge, whichever implementation is behind it. */
class TcpConnection(val input: java.io.InputStream, val output: java.io.OutputStream, private val closer: () -> Unit) : AutoCloseable {
    override fun close() = closer()
}

/** The edge's TCP endpoint only speaks TLS 1.3, which the platform's TLS gained in Android 10. */
fun platformTlsSupports13(): Boolean = runCatching { edgeTlsContext.supportedSSLParameters.protocols.contains("TLSv1.3") }.getOrDefault(false)

/**
 * TLS 1.3 over TCP port 7844. Server name `h2.cftunnel.com`, no ALPN (cloudflared sends
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
