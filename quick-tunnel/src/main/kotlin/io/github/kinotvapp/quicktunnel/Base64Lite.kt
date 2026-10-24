package io.github.kinotvapp.quicktunnel

/** Base64 without java.util.Base64 (missing before Android 8). Decoding accepts padded and unpadded input. */
internal object Base64Lite {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private val REVERSE = IntArray(128) { -1 }.also { r -> ALPHABET.forEachIndexed { i, c -> r[c.code] = i } }

    fun encode(data: ByteArray, padded: Boolean): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xff
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xff else -1
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xff else -1
            sb.append(ALPHABET[b0 ushr 2])
            sb.append(ALPHABET[((b0 and 3) shl 4) or (if (b1 >= 0) b1 ushr 4 else 0)])
            if (b1 >= 0) sb.append(ALPHABET[((b1 and 15) shl 2) or (if (b2 >= 0) b2 ushr 6 else 0)]) else if (padded) sb.append('=')
            if (b2 >= 0) sb.append(ALPHABET[b2 and 63]) else if (padded) sb.append('=')
            i += 3
        }
        return sb.toString()
    }

    fun decode(text: String): ByteArray {
        val s = text.trimEnd('=')
        val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
        var buffer = 0; var bits = 0
        for (c in s) {
            val v = if (c.code < 128) REVERSE[c.code] else -1
            require(v >= 0) { "invalid base64 character '$c'" }
            buffer = (buffer shl 6) or v; bits += 6
            if (bits >= 8) { bits -= 8; out.write((buffer ushr bits) and 0xff) }
        }
        return out.toByteArray()
    }
}
