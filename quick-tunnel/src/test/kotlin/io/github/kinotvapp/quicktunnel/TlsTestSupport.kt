package io.github.kinotvapp.quicktunnel

import java.io.File
import java.net.InetAddress
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** A self-signed EC certificate for one name, made with the JDK's own keytool, plus the trust and server contexts for it. */
class TestIdentity(val name: String) {
    val keystore: KeyStore
    val trust: X509TrustManager
    val serverContext: SSLContext

    init {
        val dir = File.createTempFile("tls", "dir").also { it.delete(); it.mkdirs() }
        val p12 = File(dir, "id.p12")
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        val p = ProcessBuilder(
            keytool, "-genkeypair", "-alias", "srv", "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
            "-dname", "CN=$name", "-ext", "SAN=dns:$name", "-validity", "2", "-storetype", "PKCS12",
            "-keystore", p12.path, "-storepass", "changeit", "-keypass", "changeit",
        ).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        check(p.waitFor() == 0) { "keytool failed: $out" }
        keystore = KeyStore.getInstance("PKCS12").apply { p12.inputStream().use { load(it, "changeit".toCharArray()) } }
        val cert = keystore.getCertificate("srv") as X509Certificate
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("srv", cert) }
        trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }.trustManagers.filterIsInstance<X509TrustManager>().first()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keystore, "changeit".toCharArray()) }
        serverContext = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
        dir.deleteRecursively()
    }

    /** A TLS server on loopback; [protocols] limits what it will speak. Each accepted connection runs [handler] on its own thread. */
    fun server(protocols: Array<String> = arrayOf("TLSv1.3"), handler: (javax.net.ssl.SSLSocket) -> Unit): SSLServerSocket {
        val s = serverContext.serverSocketFactory.createServerSocket(0, 10, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        s.enabledProtocols = protocols
        Thread({
            while (!s.isClosed) {
                val c = try { s.accept() as javax.net.ssl.SSLSocket } catch (_: Exception) { break }
                Thread({ try { handler(c) } catch (_: Exception) { } finally { runCatching { c.close() } } }, "tls-test-conn").apply { isDaemon = true }.start()
            }
        }, "tls-test-accept").apply { isDaemon = true }.start()
        return s
    }
}
