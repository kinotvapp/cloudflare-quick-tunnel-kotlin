package io.github.kinotvapp.quicktunnel

import tech.kwik.core.QuicClientConnection
import tech.kwik.core.QuicStream
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration
import java.util.function.Consumer
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

const val ALPN = "argotunnel"
const val EDGE_SNI = "quic.cftunnel.com"
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
fun dial(edge: EdgeAddr, onPeerStream: Consumer<QuicStream>): QuicClientConnection {
    // Kwik finds its TLS key exchange with ServiceLoader, which reads the thread's context class loader.
    // On Android, pool threads (ForkJoinPool, executors) get the system loader, which cannot see the APK's
    // META-INF/services: the handshake then fails with "Unsupported named group(s)".
    val thread = Thread.currentThread()
    val previous = thread.contextClassLoader
    thread.contextClassLoader = QuicClientConnection::class.java.classLoader
    try {
        return dialInThisThread(edge, onPeerStream)
    } finally {
        thread.contextClassLoader = previous
    }
}

private fun dialInThisThread(edge: EdgeAddr, onPeerStream: Consumer<QuicStream>): QuicClientConnection {
    val conn = QuicClientConnection.newBuilder()
        .host(EDGE_SNI).port(edge.port).proxy(edge.ip.hostAddress)
        .applicationProtocol(ALPN).customTrustManager(edgeTrust)
        .maxOpenPeerInitiatedBidirectionalStreams(1000)
        .maxIdleTimeout(Duration.ofSeconds(IDLE_TIMEOUT_S))
        .connectTimeout(Duration.ofSeconds(HANDSHAKE_TIMEOUT_S))
        .build()
    conn.setPeerInitiatedStreamCallback(onPeerStream)
    conn.connect()
    conn.keepAlive(1)
    return conn
}
