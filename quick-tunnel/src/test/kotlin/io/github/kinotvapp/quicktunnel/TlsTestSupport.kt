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

/**
 * A self-signed certificate made with the JDK's own keytool, plus the trust and server contexts for it.
 * [san] is the keytool SAN spec (null = no subjectAltName at all); [keyAlg] is "EC" (on curve [group]) or "RSA" (2048 bits).
 */
class TestIdentity(val name: String, val san: String? = "dns:$name", val keyAlg: String = "EC", val group: String = "secp256r1") {
    val keystore: KeyStore
    val trust: X509TrustManager
    val serverContext: SSLContext
    val certificate: X509Certificate
    val privateKey: java.security.PrivateKey

    init {
        val dir = File.createTempFile("tls", "dir").also { it.delete(); it.mkdirs() }
        val p12 = File(dir, "id.p12")
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        val keyArgs = if (keyAlg == "RSA") listOf("-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA")
        else listOf("-keyalg", "EC", "-groupname", group, "-sigalg", when (group) { "secp384r1" -> "SHA384withECDSA"; "secp521r1" -> "SHA512withECDSA"; else -> "SHA256withECDSA" })
        val command = listOf(keytool, "-genkeypair", "-alias", "srv") + keyArgs + listOf("-dname", "CN=$name") +
            (if (san != null) listOf("-ext", "SAN=$san") else emptyList()) +
            listOf("-validity", "2", "-storetype", "PKCS12", "-keystore", p12.path, "-storepass", "changeit", "-keypass", "changeit")
        val p = ProcessBuilder(command).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        check(p.waitFor() == 0) { "keytool failed: $out" }
        keystore = KeyStore.getInstance("PKCS12").apply { p12.inputStream().use { load(it, "changeit".toCharArray()) } }
        val cert = keystore.getCertificate("srv") as X509Certificate
        certificate = cert
        privateKey = keystore.getKey("srv", "changeit".toCharArray()) as java.security.PrivateKey
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("srv", cert) }
        trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }.trustManagers.filterIsInstance<X509TrustManager>().first()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keystore, "changeit".toCharArray()) }
        serverContext = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
        dir.deleteRecursively()
    }

    /** A TLS server on loopback; [protocols] limits what it will speak. Each accepted connection runs [handler] on its own thread. */
    fun server(protocols: Array<String> = arrayOf("TLSv1.3"), handler: (javax.net.ssl.SSLSocket) -> Unit): SSLServerSocket =
        startTlsServer(serverContext, protocols, handler)
}

fun startTlsServer(context: SSLContext, protocols: Array<String>, handler: (javax.net.ssl.SSLSocket) -> Unit): SSLServerSocket {
    val s = context.serverSocketFactory.createServerSocket(0, 10, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
    s.enabledProtocols = protocols
    Thread({
        while (!s.isClosed) {
            val c = try { s.accept() as javax.net.ssl.SSLSocket } catch (_: Exception) { break }
            Thread({ try { handler(c) } catch (_: Exception) { } finally { runCatching { c.close() } } }, "tls-test-conn").apply { isDaemon = true }.start()
        }
    }, "tls-test-accept").apply { isDaemon = true }.start()
    return s
}

/**
 * A certificate AUTHORITY and a server certificate issued by it, like Cloudflare's setup: the client trusts only the CA, the
 * server sends [leaf] + the CA. A self-signed server certificate that is itself the trust anchor takes a shortcut inside the
 * JDK's trust manager, so only this kind of chain exercises the real path validation (and the authType it is given).
 */
class TestPki(val name: String, val caName: String = "Test CA") {
    val trust: X509TrustManager
    val serverContext: SSLContext

    init {
        val dir = File.createTempFile("pki", "dir").also { it.delete(); it.mkdirs() }
        fun keytool(vararg args: String) {
            val p = ProcessBuilder(listOf(File(System.getProperty("java.home"), "bin/keytool").path) + args).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "keytool ${args.toList()} failed: $out" }
        }
        val ca = File(dir, "ca.p12").path; val leaf = File(dir, "leaf.p12").path
        val common = arrayOf("-storetype", "PKCS12", "-storepass", "changeit")
        val ec = arrayOf("-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA")
        keytool("-genkeypair", "-alias", "ca", *ec, "-dname", "CN=$caName", "-ext", "bc:c", "-ext", "ku:c=keyCertSign,cRLSign", "-validity", "3", "-keystore", ca, "-keypass", "changeit", *common)
        keytool("-genkeypair", "-alias", "srv", *ec, "-dname", "CN=$name", "-validity", "3", "-keystore", leaf, "-keypass", "changeit", *common)
        keytool("-certreq", "-alias", "srv", "-keystore", leaf, "-file", File(dir, "leaf.csr").path, "-ext", "SAN=dns:$name", *common)
        keytool("-gencert", "-alias", "ca", "-keystore", ca, "-infile", File(dir, "leaf.csr").path, "-outfile", File(dir, "leaf.cer").path,
            "-ext", "SAN=dns:$name", "-ext", "ku:c=digitalSignature", "-ext", "eku=serverAuth", "-validity", "2", *common)
        keytool("-exportcert", "-alias", "ca", "-keystore", ca, "-file", File(dir, "ca.cer").path, *common)
        keytool("-importcert", "-alias", "ca", "-file", File(dir, "ca.cer").path, "-keystore", leaf, "-noprompt", *common)
        keytool("-importcert", "-alias", "srv", "-file", File(dir, "leaf.cer").path, "-keystore", leaf, "-noprompt", *common)

        val leafStore = KeyStore.getInstance("PKCS12").apply { File(leaf).inputStream().use { load(it, "changeit".toCharArray()) } }
        check(leafStore.getCertificateChain("srv").size == 2) { "the issued leaf should come with its CA" }
        val caCert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(File(dir, "ca.cer").inputStream()) as X509Certificate
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("ca", caCert) }
        trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }.trustManagers.filterIsInstance<X509TrustManager>().first()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(leafStore, "changeit".toCharArray()) }
        serverContext = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
        dir.deleteRecursively()
    }

    fun server(handler: (javax.net.ssl.SSLSocket) -> Unit) = startTlsServer(serverContext, arrayOf("TLSv1.3"), handler)
}
