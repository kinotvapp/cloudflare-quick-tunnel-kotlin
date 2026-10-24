package io.github.kinotvapp.quicktunnel

import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import javax.crypto.KeyAgreement
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AndroidCompatTest {
    private val polyfill get() = EcParametersPolyfill.provider()

    private fun viaPolyfill(name: String) = AlgorithmParameters.getInstance("EC", polyfill).apply { init(ECGenParameterSpec(name)) }.getParameterSpec(ECParameterSpec::class.java)
    private fun viaJdk(name: String) = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec(name)) }.getParameterSpec(ECParameterSpec::class.java)

    @Test fun `the polyfilled curves are identical to the JDK's for every TLS 1 3 curve`() {
        for (name in listOf("secp256r1", "secp384r1", "secp521r1")) {
            val mine = viaPolyfill(name); val jdk = viaJdk(name)
            assertEquals((jdk.curve.field as ECFieldFp).p, (mine.curve.field as ECFieldFp).p, "$name p")
            assertEquals(jdk.curve.a, mine.curve.a, "$name a"); assertEquals(jdk.curve.b, mine.curve.b, "$name b")
            assertEquals(jdk.generator, mine.generator, "$name G"); assertEquals(jdk.order, mine.order, "$name n"); assertEquals(jdk.cofactor, mine.cofactor, "$name h")
        }
    }

    @Test fun `keys generated on polyfilled parameters agree on a shared secret with the JDK`() {
        for (name in listOf("secp256r1", "secp384r1", "secp521r1")) {
            fun pair(spec: ECParameterSpec) = KeyPairGenerator.getInstance("EC").apply { initialize(spec) }.genKeyPair()
            val a = pair(viaPolyfill(name)); val b = pair(viaJdk(name))
            fun secret(priv: java.security.PrivateKey, pub: java.security.PublicKey) = KeyAgreement.getInstance("ECDH").apply { init(priv); doPhase(pub, true) }.generateSecret()
            assertContentEquals(secret(a.private, b.public), secret(b.private, a.public), name)
        }
    }

    @Test fun `common aliases resolve to the same curve`() {
        assertEquals(viaPolyfill("secp256r1").order, viaPolyfill("prime256v1").order)
        assertEquals(viaPolyfill("secp384r1").order, viaPolyfill("P-384").order)
    }

    @Test fun `unknown curves are rejected cleanly`() {
        assertFailsWith<java.security.spec.InvalidParameterSpecException> { AlgorithmParameters.getInstance("EC", polyfill).init(ECGenParameterSpec("secp192k1")) }
    }

    @Test fun `ensureInstalled is a no-op where the platform already has the algorithm`() {
        EcParametersPolyfill.ensureInstalled(); EcParametersPolyfill.ensureInstalled()
        assertEquals(null, java.security.Security.getProvider("QuickTunnelEC"), "the JDK has EC parameters, so no provider is added")
    }

    @Test fun `this JDK can speak TLS 1 3 so the HTTP2 transport is available`() {
        assertTrue(http2TransportAvailable())
    }
}
