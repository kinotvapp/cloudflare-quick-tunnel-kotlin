package io.github.kinotvapp.quicktunnel

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.AlgorithmParametersSpi
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import java.security.spec.InvalidParameterSpecException

/**
 * Kwik's TLS asks the platform for `AlgorithmParameters.getInstance("EC")` to turn a curve name into its parameters.
 * Android's providers do not offer that before Android 14, so every QUIC handshake died with "Missing support for EC
 * algorithm" on Android 7 to 13. This installs a tiny provider with the three NIST curves TLS 1.3 uses, only when the
 * platform lacks the algorithm.
 */
internal object EcParametersPolyfill {
    @Volatile private var checked = false

    @Synchronized fun ensureInstalled() {
        if (checked) return
        try {
            AlgorithmParameters.getInstance("EC")
        } catch (_: NoSuchAlgorithmException) {
            Security.addProvider(EcProvider())
        }
        checked = true
    }

    /** Test hook: the provider on its own, usable with `AlgorithmParameters.getInstance("EC", provider)`. */
    fun provider(): Provider = EcProvider()
}

private class EcProvider : Provider("QuickTunnelEC", 1.0, "AlgorithmParameters.EC for platforms that lack it") {
    init { put("AlgorithmParameters.EC", EcAlgorithmParameters::class.java.name) }
}

/** Public with a public constructor because the JCA instantiates it by name. R8 keeps it via META-INF/proguard. */
class EcAlgorithmParameters : AlgorithmParametersSpi() {
    private var spec: ECParameterSpec? = null

    override fun engineInit(paramSpec: AlgorithmParameterSpec) {
        spec = when (paramSpec) {
            is ECGenParameterSpec -> CURVES[normalize(paramSpec.name)] ?: throw InvalidParameterSpecException("unsupported curve ${paramSpec.name}")
            is ECParameterSpec -> paramSpec
            else -> throw InvalidParameterSpecException("expected ECGenParameterSpec or ECParameterSpec, got ${paramSpec.javaClass}")
        }
    }

    override fun engineInit(params: ByteArray) = throw java.io.IOException("encoded EC parameters are not supported")
    override fun engineInit(params: ByteArray, format: String?) = throw java.io.IOException("encoded EC parameters are not supported")

    @Suppress("UNCHECKED_CAST")
    override fun <T : AlgorithmParameterSpec> engineGetParameterSpec(paramSpec: Class<T>): T {
        val s = spec ?: throw InvalidParameterSpecException("not initialized")
        if (paramSpec.isAssignableFrom(ECParameterSpec::class.java)) return s as T
        throw InvalidParameterSpecException("unsupported spec ${paramSpec.name}")
    }

    override fun engineGetEncoded(): ByteArray = throw java.io.IOException("encoding is not supported")
    override fun engineGetEncoded(format: String?): ByteArray = throw java.io.IOException("encoding is not supported")
    override fun engineToString() = "EC ${spec?.curve?.field}"

    private companion object {
        private fun hex(s: String) = BigInteger(s, 16)

        private fun curve(p: String, a: String, b: String, gx: String, gy: String, n: String, h: Int) =
            ECParameterSpec(EllipticCurve(ECFieldFp(hex(p)), hex(a), hex(b)), ECPoint(hex(gx), hex(gy)), hex(n), h)

        /** NIST P-256, P-384 and P-521 (FIPS 186-4), checked against the JDK's own values by a unit test. */
        private val CURVES: Map<String, ECParameterSpec> = mapOf(
        "secp256r1" to curve(
            p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
            b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            h = 1,
        ),
        "secp384r1" to curve(
            p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            a = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
            b = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            gx = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            gy = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            n = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            h = 1,
        ),
        "secp521r1" to curve(
            p = "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            a = "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
            b = "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            gx = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
            gy = "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            n = "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            h = 1,
        ),
        )

        private val ALIASES = mapOf(
            "p-256" to "secp256r1", "nist p-256" to "secp256r1", "prime256v1" to "secp256r1",
            "p-384" to "secp384r1", "nist p-384" to "secp384r1",
            "p-521" to "secp521r1", "nist p-521" to "secp521r1",
        )

        private fun normalize(name: String) = name.lowercase().let { ALIASES[it] ?: it }
    }
}
