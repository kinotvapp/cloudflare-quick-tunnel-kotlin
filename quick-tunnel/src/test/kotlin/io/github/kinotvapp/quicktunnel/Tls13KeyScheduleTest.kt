package io.github.kinotvapp.quicktunnel

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** Hex values copied (by script, to avoid typos) from RFC 8448 section 3, "Simple 1-RTT Handshake". */
private object Rfc8448 {
    const val CLIENT_HELLO =
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
    const val SERVER_HELLO =
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
    const val ENCRYPTED_EXTENSIONS =
        "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000"
    const val CERTIFICATE =
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000"
    const val CERTIFICATE_VERIFY =
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3"
    const val SERVER_FINISHED =
        "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
    const val CLIENT_FINISHED_MSG =
        "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
    const val EARLY_SECRET =
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    const val DERIVED_FOR_HANDSHAKE =
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
    const val ECDHE =
        "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    const val HANDSHAKE_SECRET =
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
    const val HELLO_HASH =
        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    const val C_HS_TRAFFIC =
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
    const val S_HS_TRAFFIC =
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
    const val DERIVED_FOR_MASTER =
        "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"
    const val MASTER_SECRET =
        "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
    const val S_HS_KEY =
        "3fce516009c21727d0f2e4e86ee403bc"
    const val S_HS_IV =
        "5d313eb2671276ee13000b30"
    const val SERVER_FINISHED_KEY =
        "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
    const val SERVER_VERIFY_DATA =
        "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
    const val FINISHED_HASH =
        "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
    const val C_AP_TRAFFIC =
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
    const val S_AP_TRAFFIC =
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
    const val S_AP_KEY =
        "9f02283b6c9c07efc26bb9f2ac92e356"
    const val S_AP_IV =
        "cf782b88dd83549aadf1e984"
    const val C_HS_KEY =
        "dbfaa693d1762c5b666af5d950258d01"
    const val C_HS_IV =
        "5bd3c71b836e0b76bb73265f"
    const val CLIENT_FINISHED_KEY =
        "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"
    const val CLIENT_VERIFY_DATA =
        "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
    const val C_AP_KEY =
        "17422dda596ed5d9acd890e3c63f5051"
    const val C_AP_IV =
        "5b78923dee08579033e523d9"
}

private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
private fun assertHex(expected: String, actual: ByteArray, what: String) = assertEquals(expected, actual.toHex(), what)

/**
 * The key schedule and Finished computations checked byte for byte against RFC 8448 section 3. The trace uses x25519, which
 * this client does not offer, so the handshake cannot be replayed end to end; everything after the ECDHE shared secret does
 * not depend on the group, and that is what is asserted here.
 */
class Tls13KeyScheduleTest {
    private val emptyHash = Tls13Crypto.sha256(ByteArray(0))
    private val ch = hex(Rfc8448.CLIENT_HELLO)
    private val sh = hex(Rfc8448.SERVER_HELLO)
    private val ee = hex(Rfc8448.ENCRYPTED_EXTENSIONS)
    private val cert = hex(Rfc8448.CERTIFICATE)
    private val cv = hex(Rfc8448.CERTIFICATE_VERIFY)
    private val sfin = hex(Rfc8448.SERVER_FINISHED)
    private val schedule by lazy { Tls13KeySchedule(hex(Rfc8448.ECDHE), Tls13Crypto.sha256(ch + sh)) }

    private fun key(secret: ByteArray) = Tls13Crypto.expandLabel(secret, "key", ByteArray(0), 16)
    private fun iv(secret: ByteArray) = Tls13Crypto.expandLabel(secret, "iv", ByteArray(0), 12)

    @Test fun `the RFC messages are the lengths the RFC states`() {
        assertEquals(196, ch.size); assertEquals(90, sh.size); assertEquals(40, ee.size)
        assertEquals(445, cert.size); assertEquals(136, cv.size); assertEquals(36, sfin.size)
    }

    @Test fun `early secret and the derived secret before the handshake secret`() {
        assertHex(Rfc8448.EARLY_SECRET, schedule.earlySecret, "early secret")
        assertHex(Rfc8448.DERIVED_FOR_HANDSHAKE, Tls13Crypto.deriveSecret(schedule.earlySecret, "derived", emptyHash), "derived")
    }

    @Test fun `handshake secret and the handshake traffic secrets`() {
        assertHex(Rfc8448.HELLO_HASH, Tls13Crypto.sha256(ch + sh), "Hash(ClientHello..ServerHello)")
        assertHex(Rfc8448.HANDSHAKE_SECRET, schedule.handshakeSecret, "handshake secret")
        assertHex(Rfc8448.C_HS_TRAFFIC, schedule.clientHandshakeTrafficSecret, "client handshake traffic secret")
        assertHex(Rfc8448.S_HS_TRAFFIC, schedule.serverHandshakeTrafficSecret, "server handshake traffic secret")
    }

    @Test fun `handshake traffic keys and ivs`() {
        assertHex(Rfc8448.S_HS_KEY, key(schedule.serverHandshakeTrafficSecret), "server handshake key")
        assertHex(Rfc8448.S_HS_IV, iv(schedule.serverHandshakeTrafficSecret), "server handshake iv")
        assertHex(Rfc8448.C_HS_KEY, key(schedule.clientHandshakeTrafficSecret), "client handshake key")
        assertHex(Rfc8448.C_HS_IV, iv(schedule.clientHandshakeTrafficSecret), "client handshake iv")
    }

    @Test fun `master secret`() {
        assertHex(Rfc8448.DERIVED_FOR_MASTER, Tls13Crypto.deriveSecret(schedule.handshakeSecret, "derived", emptyHash), "derived for master")
        assertHex(Rfc8448.MASTER_SECRET, schedule.masterSecret, "master secret")
    }

    @Test fun `server Finished verify_data over the transcript through CertificateVerify`() {
        assertHex(Rfc8448.SERVER_FINISHED_KEY, Tls13Crypto.expandLabel(schedule.serverHandshakeTrafficSecret, "finished", ByteArray(0), 32), "server finished_key")
        val through = Tls13Crypto.sha256(ch + sh + ee + cert + cv)
        val verifyData = Tls13Crypto.finishedVerifyData(schedule.serverHandshakeTrafficSecret, through)
        assertHex(Rfc8448.SERVER_VERIFY_DATA, verifyData, "server verify_data")
        assertContentEquals(sfin.copyOfRange(4, 36), verifyData, "and it is the body of the Finished message in the trace")
    }

    @Test fun `application traffic secrets keys and ivs`() {
        val hash = Tls13Crypto.sha256(ch + sh + ee + cert + cv + sfin)
        assertHex(Rfc8448.FINISHED_HASH, hash, "Hash(ClientHello..server Finished)")
        val c = schedule.clientApplicationTrafficSecret(hash)
        val s = schedule.serverApplicationTrafficSecret(hash)
        assertHex(Rfc8448.C_AP_TRAFFIC, c, "client application traffic secret")
        assertHex(Rfc8448.S_AP_TRAFFIC, s, "server application traffic secret")
        assertHex(Rfc8448.S_AP_KEY, key(s), "server application key"); assertHex(Rfc8448.S_AP_IV, iv(s), "server application iv")
        assertHex(Rfc8448.C_AP_KEY, key(c), "client application key"); assertHex(Rfc8448.C_AP_IV, iv(c), "client application iv")
    }

    @Test fun `client Finished verify_data uses the transcript through the server Finished`() {
        assertHex(Rfc8448.CLIENT_FINISHED_KEY, Tls13Crypto.expandLabel(schedule.clientHandshakeTrafficSecret, "finished", ByteArray(0), 32), "client finished_key")
        val hash = Tls13Crypto.sha256(ch + sh + ee + cert + cv + sfin)
        val verifyData = Tls13Crypto.finishedVerifyData(schedule.clientHandshakeTrafficSecret, hash)
        assertHex(Rfc8448.CLIENT_VERIFY_DATA, verifyData, "client verify_data")
        assertContentEquals(hex(Rfc8448.CLIENT_FINISHED_MSG).copyOfRange(4, 36), verifyData)
    }

    /** RFC 5869 appendix A.1 (the basic SHA-256 case): checks Extract and Expand on their own. */
    @Test fun `HKDF matches RFC 5869 test case 1`() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = ByteArray(13) { it.toByte() }
        val info = ByteArray(10) { (0xf0 + it).toByte() }
        val prk = Tls13Crypto.extract(salt, ikm)
        assertHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk, "PRK")
        assertHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", Tls13Crypto.expand(prk, info, 42), "OKM")
    }

    @Test fun `Expand-Label can produce more than one hash block`() {
        val out = Tls13Crypto.expandLabel(ByteArray(32) { 1 }, "test", ByteArray(0), 80)
        assertEquals(80, out.size)
        assertEquals(false, out.copyOf(32).contentEquals(out.copyOfRange(32, 64)), "blocks differ (the counter byte advances)")
    }
}
