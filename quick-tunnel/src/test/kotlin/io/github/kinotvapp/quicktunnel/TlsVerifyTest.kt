package io.github.kinotvapp.quicktunnel

import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.CertificateException
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TlsHostnameTest {
    private fun m(pattern: String, host: String) = TlsHostname.matchesDnsName(pattern, host)

    @Test fun `wildcard covers exactly one label`() {
        assertTrue(m("*.cftunnel.com", "h2.cftunnel.com"))
        assertFalse(m("*.cftunnel.com", "a.b.cftunnel.com"), "two labels")
        assertFalse(m("*.cftunnel.com", "cftunnel.com"), "the bare parent")
        assertFalse(m("*.cftunnel.com", ".cftunnel.com"), "an empty label")
        assertFalse(m("*.cftunnel.com", "h2.cftunnel.com.evil.com"))
        assertFalse(m("*.cftunnel.com", "h2xcftunnel.com"))
    }

    @Test fun `exact names and case`() {
        assertTrue(m("cftunnel.com", "cftunnel.com"))
        assertTrue(m("CfTunnel.COM", "cftunnel.com"))
        assertTrue(m("*.CFTUNNEL.com", "H2.CfTunnel.Com"))
        assertFalse(m("cftunnel.com", "h2.cftunnel.com"))
        assertFalse(m("h2.cftunnel.com", "cftunnel.com"))
    }

    @Test fun `a wildcard anywhere but the whole left-most label is rejected`() {
        assertFalse(m("h*.cftunnel.com", "h2.cftunnel.com"), "partial label")
        assertFalse(m("*2.cftunnel.com", "h2.cftunnel.com"), "partial label")
        assertFalse(m("h2.*.com", "h2.cftunnel.com"), "in the middle")
        assertFalse(m("a.*.cftunnel.com", "a.b.cftunnel.com"), "not left-most")
        assertFalse(m("*.*.cftunnel.com", "a.b.cftunnel.com"), "two wildcards")
        assertFalse(m("*", "localhost"), "bare star")
        assertFalse(m("*.com", "example.com"), "too broad: nothing but a TLD after it")
        assertFalse(m("**.cftunnel.com", "h2.cftunnel.com"))
    }

    @Test fun `a trailing dot is ignored on both sides`() {
        assertTrue(m("*.cftunnel.com", "h2.cftunnel.com."))
        assertTrue(m("cftunnel.com.", "cftunnel.com"))
        assertFalse(m("*.cftunnel.com", "h2..cftunnel.com"), "an empty label in the host")
        assertFalse(m("cftunnel.com", ""))
        assertFalse(m("", "cftunnel.com"))
    }

    @Test fun `SAN entries decide, the CN does not`() {
        val wildcard = TestIdentity("ignored-cn.example", san = "dns:*.cftunnel.com,dns:cftunnel.com")
        TlsHostname.verify(wildcard.certificate, "h2.cftunnel.com")
        TlsHostname.verify(wildcard.certificate, "cftunnel.com")
        TlsHostname.verify(wildcard.certificate, "H2.CFTUNNEL.COM.")
        assertFailsWith<CertificateException> { TlsHostname.verify(wildcard.certificate, "a.b.cftunnel.com") }
        assertFailsWith<CertificateException> { TlsHostname.verify(wildcard.certificate, "ignored-cn.example") } // the CN is not consulted
    }

    @Test fun `a certificate without a SAN matches nothing, not even its CN`() {
        val noSan = TestIdentity("h2.cftunnel.com", san = null)
        assertFailsWith<CertificateException> { TlsHostname.verify(noSan.certificate, "h2.cftunnel.com") }
    }

    @Test fun `IP literals match only iPAddress entries`() {
        val ip = TestIdentity("host.test", san = "ip:127.0.0.1,dns:host.test")
        TlsHostname.verify(ip.certificate, "127.0.0.1")
        assertFailsWith<CertificateException> { TlsHostname.verify(ip.certificate, "127.0.0.2") }
        val dnsOnly = TestIdentity("127.0.0.1", san = "dns:127.0.0.1")
        assertFailsWith<CertificateException> { TlsHostname.verify(dnsOnly.certificate, "127.0.0.1") } // a dNSName "127.0.0.1" is not an IP SAN
        assertTrue(TlsHostname.isIpLiteral("127.0.0.1")); assertTrue(TlsHostname.isIpLiteral("::1")); assertFalse(TlsHostname.isIpLiteral("1.2.3.cftunnel.com"))
    }
}

class TlsSignaturesTest {
    private val content = "TLS 1.3, server CertificateVerify content under test".toByteArray()

    private fun ecKeys(curve: String) = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
    private fun rsaKeys() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun ecdsaCase(curve: String, scheme: Int, algorithm: String) {
        val kp = ecKeys(curve)
        val sig = Signature.getInstance(algorithm).run { initSign(kp.private); update(content); sign() }
        assertTrue(TlsSignatures.verify(scheme, kp.public, content, sig), "valid $curve signature")
        assertFalse(TlsSignatures.verify(scheme, kp.public, content + 1, sig), "different content")
        val bad = sig.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFalse(TlsSignatures.verify(scheme, kp.public, content, bad), "last byte flipped")
        assertFalse(TlsSignatures.verify(scheme, kp.public, content, sig.copyOf(sig.size - 3)), "truncated")
        assertFalse(TlsSignatures.verify(scheme, kp.public, content, ByteArray(0)), "empty")
        assertFalse(TlsSignatures.verify(scheme, ecKeys(curve).public, content, sig), "another key")
    }

    @Test fun `ECDSA P-256`() = ecdsaCase("secp256r1", TlsSignatures.ECDSA_SECP256R1_SHA256, "SHA256withECDSA")
    @Test fun `ECDSA P-384`() = ecdsaCase("secp384r1", TlsSignatures.ECDSA_SECP384R1_SHA384, "SHA384withECDSA")
    @Test fun `ECDSA P-521`() = ecdsaCase("secp521r1", TlsSignatures.ECDSA_SECP521R1_SHA512, "SHA512withECDSA")

    @Test fun `an ECDSA scheme refuses a key on the wrong curve or of the wrong type`() {
        assertFailsWith<InvalidKeyException> { TlsSignatures.verify(TlsSignatures.ECDSA_SECP256R1_SHA256, ecKeys("secp384r1").public, content, ByteArray(70)) }
        assertFailsWith<InvalidKeyException> { TlsSignatures.verify(TlsSignatures.ECDSA_SECP384R1_SHA384, ecKeys("secp256r1").public, content, ByteArray(70)) }
        assertFailsWith<InvalidKeyException> { TlsSignatures.verify(TlsSignatures.ECDSA_SECP256R1_SHA256, rsaKeys().public, content, ByteArray(70)) }
    }

    private fun pssCase(scheme: Int, digest: String, salt: Int) {
        val kp = rsaKeys()
        val sig = Signature.getInstance("RSASSA-PSS").run {
            setParameter(PSSParameterSpec(digest, "MGF1", MGF1ParameterSpec(digest), salt, 1)); initSign(kp.private); update(content); sign()
        }
        assertTrue(TlsSignatures.verify(scheme, kp.public, content, sig), "valid RSA-PSS $digest signature")
        assertFalse(TlsSignatures.verify(scheme, kp.public, content + 1, sig), "different content")
        val bad = sig.copyOf().also { it[10] = (it[10].toInt() xor 0x40).toByte() }
        assertFalse(TlsSignatures.verify(scheme, kp.public, content, bad), "bit flipped")
        assertFalse(TlsSignatures.verify(scheme, kp.public, content, sig.copyOf(sig.size - 1)), "truncated")
        assertFalse(TlsSignatures.verify(scheme, rsaKeys().public, content, sig), "another key")
    }

    @Test fun `RSA-PSS SHA-256`() = pssCase(TlsSignatures.RSA_PSS_RSAE_SHA256, "SHA-256", 32)
    @Test fun `RSA-PSS SHA-384`() = pssCase(TlsSignatures.RSA_PSS_RSAE_SHA384, "SHA-384", 48)
    @Test fun `RSA-PSS SHA-512`() = pssCase(TlsSignatures.RSA_PSS_RSAE_SHA512, "SHA-512", 64)

    @Test fun `RSA-PSS rejects a signature made with another salt length or hash`() {
        val kp = rsaKeys()
        val wrongSalt = Signature.getInstance("RSASSA-PSS").run {
            setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1)); initSign(kp.private); update(content); sign()
        }
        assertFalse(TlsSignatures.verify(TlsSignatures.RSA_PSS_RSAE_SHA256, kp.public, content, wrongSalt))
        val sha256 = Signature.getInstance("RSASSA-PSS").run {
            setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)); initSign(kp.private); update(content); sign()
        }
        assertFalse(TlsSignatures.verify(TlsSignatures.RSA_PSS_RSAE_SHA384, kp.public, content, sha256))
    }

    @Test fun `an RSA-PSS scheme refuses an EC key`() {
        assertFailsWith<InvalidKeyException> { TlsSignatures.verify(TlsSignatures.RSA_PSS_RSAE_SHA256, ecKeys("secp256r1").public, content, ByteArray(256)) }
    }

    @Test fun `the offered list is what the ClientHello advertises`() {
        assertEquals(6, TlsSignatures.OFFERED.size)
    }
}
