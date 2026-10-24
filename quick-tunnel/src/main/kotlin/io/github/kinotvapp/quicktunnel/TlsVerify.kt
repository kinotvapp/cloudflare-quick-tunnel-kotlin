package io.github.kinotvapp.quicktunnel

import java.net.IDN
import java.net.InetAddress
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Locale

/**
 * Server identity checks that a certificate-chain validation does not do.
 *
 * Why this exists: a trust manager only answers "was this chain issued by a CA I trust". Cloudflare's Origin CA issues
 * certificates to any Cloudflare customer for their own domains, so pinning to it proves nothing about WHICH site we are
 * talking to. The name in the certificate has to be compared with the name we meant to reach (RFC 6125 section 6.4).
 */
internal object TlsHostname {
    /** True for an IPv4 or IPv6 literal. These are never sent as SNI (RFC 6066 section 3) and are matched against iPAddress SANs. */
    fun isIpLiteral(host: String): Boolean = host.contains(':') || IPV4.matches(host)

    /**
     * The name as it goes on the wire and into the comparison: one trailing dot removed, ASCII lower case, internationalized
     * names converted to their A-label form. Null when it cannot be a valid DNS name.
     */
    fun normalize(name: String): String? {
        var n = if (name.endsWith(".")) name.dropLast(1) else name
        if (n.isEmpty()) return null
        if (n.any { it.code > 0x7f }) n = try { IDN.toASCII(n, IDN.ALLOW_UNASSIGNED) } catch (_: IllegalArgumentException) { return null }
        n = n.lowercase(Locale.ROOT)
        if (n.startsWith(".") || n.contains("..")) return null
        return n
    }

    /**
     * RFC 6125 section 6.4: does the certificate name [pattern] cover [host]? Comparison is case-insensitive. A wildcard is
     * honoured only as the entire left-most label (`*.example.com`), stands for exactly one non-empty label, and needs at
     * least two labels after it so `*.com` matches nothing. `f*.example.com`, `a.*.example.com` and `*` are rejected.
     */
    fun matchesDnsName(pattern: String, host: String): Boolean {
        val p = normalize(pattern) ?: return false
        val h = normalize(host) ?: return false
        if (!p.contains('*')) return p == h
        if (!p.startsWith("*.")) return false
        val rest = p.substring(2)
        if (rest.contains('*') || !rest.contains('.')) return false
        val firstDot = h.indexOf('.')
        if (firstDot <= 0) return false // no left-most label to stand in for the wildcard (also: the bare parent domain)
        return h.substring(firstDot + 1) == rest
    }

    /**
     * Checks [host] against the subjectAltName entries of [leaf]: dNSName entries for names, iPAddress entries for literals.
     * The subject CN is deliberately never consulted, not even when there is no SAN: the Common Name was deprecated by
     * RFC 6125/9110 and falling back to it only widens what an attacker can get past us.
     */
    fun verify(leaf: X509Certificate, host: String) {
        val sans = try { leaf.subjectAlternativeNames } catch (e: GeneralSecurityException) {
            throw CertificateException("unreadable subjectAltName: ${e.message}", e)
        } ?: throw CertificateException("the server certificate has no subjectAltName, so it cannot be matched to $host")
        val ok = if (isIpLiteral(host)) {
            val wanted = literalBytes(host)
            wanted != null && sans.any { e -> (e[0] as? Int) == 7 && (e.getOrNull(1) as? String)?.let { literalBytes(it) }?.contentEquals(wanted) == true }
        } else {
            sans.any { e -> (e[0] as? Int) == 2 && (e.getOrNull(1) as? String)?.let { matchesDnsName(it, host) } == true }
        }
        if (!ok) throw CertificateException("the server certificate is not valid for $host")
    }

    private val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")

    /** Literal -> address bytes without any DNS lookup (only literals are ever passed to the resolver call). */
    private fun literalBytes(s: String): ByteArray? =
        if (isIpLiteral(s)) try { InetAddress.getByName(s.removePrefix("[").removeSuffix("]")).address } catch (_: Exception) { null } else null
}

/** CertificateVerify signature schemes (RFC 8446 section 4.2.3) and their verification with the JCA. */
internal object TlsSignatures {
    const val ECDSA_SECP256R1_SHA256 = 0x0403
    const val ECDSA_SECP384R1_SHA384 = 0x0503
    const val ECDSA_SECP521R1_SHA512 = 0x0603
    const val RSA_PSS_RSAE_SHA256 = 0x0804
    const val RSA_PSS_RSAE_SHA384 = 0x0805
    const val RSA_PSS_RSAE_SHA512 = 0x0806

    /** What the ClientHello offers; the server's pick must be one of these. */
    val OFFERED = intArrayOf(
        ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384, ECDSA_SECP521R1_SHA512,
        RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512,
    )

    /**
     * Verifies [signature] over [content] with [key] under [scheme]. Returns false for a bad signature; throws
     * [InvalidKeyException] when the key cannot be used with the scheme (wrong type or curve) and
     * [NoSuchAlgorithmException] when the platform has no way to verify the scheme.
     */
    fun verify(scheme: Int, key: PublicKey, content: ByteArray, signature: ByteArray): Boolean = when (scheme) {
        ECDSA_SECP256R1_SHA256 -> ecdsa(key, 256, "SHA256withECDSA", content, signature)
        ECDSA_SECP384R1_SHA384 -> ecdsa(key, 384, "SHA384withECDSA", content, signature)
        ECDSA_SECP521R1_SHA512 -> ecdsa(key, 521, "SHA512withECDSA", content, signature)
        RSA_PSS_RSAE_SHA256 -> pss(key, "SHA-256", "SHA256", 32, content, signature)
        RSA_PSS_RSAE_SHA384 -> pss(key, "SHA-384", "SHA384", 48, content, signature)
        RSA_PSS_RSAE_SHA512 -> pss(key, "SHA-512", "SHA512", 64, content, signature)
        else -> throw NoSuchAlgorithmException("unsupported signature scheme 0x${scheme.toString(16)}")
    }

    private fun ecdsa(key: PublicKey, bits: Int, algorithm: String, content: ByteArray, signature: ByteArray): Boolean {
        // The scheme fixes the curve: ecdsa_secp256r1_sha256 with a P-384 key is a protocol violation, not just a bad signature.
        if (key !is ECPublicKey || key.params.curve.field.fieldSize != bits) throw InvalidKeyException("key is not an EC P-$bits key")
        return try {
            Signature.getInstance(algorithm).run { initVerify(key); update(content); verify(signature) }
        } catch (_: SignatureException) { false }
    }

    private fun pss(key: PublicKey, digest: String, shortName: String, saltLength: Int, content: ByteArray, signature: ByteArray): Boolean {
        if (key !is RSAPublicKey) throw InvalidKeyException("key is not an RSA key")
        // RFC 8446: MGF1 with the same hash, salt as long as the hash output, trailer field 1.
        val spec = PSSParameterSpec(digest, "MGF1", MGF1ParameterSpec(digest), saltLength, 1)
        // The standard name first; Android before API 34 and some providers only know the "<hash>withRSA/PSS" spellings.
        val candidates = listOf("RSASSA-PSS", "${shortName}withRSA/PSS", "${shortName}withRSAandMGF1")
        var last: Exception? = null
        for (name in candidates) {
            val sig = try { Signature.getInstance(name) } catch (e: NoSuchAlgorithmException) { last = e; continue }
            try {
                // Providers whose algorithm name already fixes the digest may reject setParameter; their defaults are the same values.
                try { sig.setParameter(spec) } catch (e: GeneralSecurityException) { if (name == "RSASSA-PSS") { last = e; continue } }
                sig.initVerify(key); sig.update(content)
                return sig.verify(signature)
            } catch (_: SignatureException) {
                return false
            } catch (e: InvalidKeyException) {
                last = e
            } catch (e: RuntimeException) { // a provider that cannot do it surfaces as ProviderException on some platforms
                last = e
            }
        }
        throw NoSuchAlgorithmException("no provider can verify RSA-PSS ($shortName)", last)
    }
}
