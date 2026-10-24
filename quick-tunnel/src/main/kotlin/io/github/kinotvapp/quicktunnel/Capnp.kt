package io.github.kinotvapp.quicktunnel

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Minimal single-segment Cap'n Proto writer: just what the argotunnel edge needs. */
class CapnpBuilder {
    private var buf: ByteBuffer = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN)
    private var words = 1 // word 0 is the root pointer

    private fun alloc(n: Int): Int {
        val need = (words + n) * 8
        if (need > buf.capacity()) {
            val bigger = ByteBuffer.allocate(maxOf(need, buf.capacity() * 2)).order(ByteOrder.LITTLE_ENDIAN)
            bigger.put(buf.array(), 0, words * 8)
            buf = bigger
        }
        val at = words
        words += n
        return at
    }

    private fun putPtr(ptrWord: Int, target: Int, lo2: Int, hi: Int) {
        buf.putInt(ptrWord * 8, ((target - (ptrWord + 1)) shl 2) or lo2)
        buf.putInt(ptrWord * 8 + 4, hi)
    }

    /** Struct pointer stored in word [ptrWord]; returns the struct's first word. */
    fun struct(ptrWord: Int, dataWords: Int, ptrCount: Int): Int {
        val t = alloc(dataWords + ptrCount)
        putPtr(ptrWord, t, 0, dataWords or (ptrCount shl 16))
        return t
    }

    fun root(dataWords: Int, ptrCount: Int) = struct(0, dataWords, ptrCount)

    fun u8(structWord: Int, byteOff: Int, v: Int) { buf.put(structWord * 8 + byteOff, v.toByte()) }
    fun u16(structWord: Int, byteOff: Int, v: Int) { buf.putShort(structWord * 8 + byteOff, v.toShort()) }
    fun u32(structWord: Int, byteOff: Int, v: Int) { buf.putInt(structWord * 8 + byteOff, v) }
    fun u64(structWord: Int, byteOff: Int, v: Long) { buf.putLong(structWord * 8 + byteOff, v) }
    fun bit(structWord: Int, bitOff: Int, v: Boolean) {
        val i = structWord * 8 + bitOff / 8
        val m = 1 shl (bitOff % 8)
        buf.put(i, (if (v) buf.get(i).toInt() or m else buf.get(i).toInt() and m.inv()).toByte())
    }

    private fun bytes(ptrWord: Int, b: ByteArray) {
        val t = alloc((b.size + 7) / 8)
        System.arraycopy(b, 0, buf.array(), t * 8, b.size)
        putPtr(ptrWord, t, 1, 2 or (b.size shl 3))
    }

    fun data(ptrWord: Int, b: ByteArray) = bytes(ptrWord, b)
    fun text(ptrWord: Int, s: String) = bytes(ptrWord, s.toByteArray(Charsets.UTF_8) + 0)

    fun textList(ptrWord: Int, items: List<String>) {
        val t = alloc(items.size)
        putPtr(ptrWord, t, 1, 6 or (items.size shl 3))
        items.forEachIndexed { i, s -> text(t + i, s) }
    }

    /** Composite struct list; returns the word of element 0. */
    fun structList(ptrWord: Int, n: Int, dataWords: Int, ptrCount: Int): Int {
        val total = n * (dataWords + ptrCount)
        val t = alloc(1 + total)
        putPtr(ptrWord, t, 1, 7 or (total shl 3))
        buf.putInt(t * 8, n shl 2)
        buf.putInt(t * 8 + 4, dataWords or (ptrCount shl 16))
        return t + 1
    }

    fun capPtr(ptrWord: Int, index: Int) {
        buf.putInt(ptrWord * 8, 3)
        buf.putInt(ptrWord * 8 + 4, index)
    }

    /** Stream framing: one segment. */
    fun frame(): ByteArray {
        val out = ByteBuffer.allocate(8 + words * 8).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt(0).putInt(words)
        out.put(buf.array(), 0, words * 8)
        return out.array()
    }
}

class CapnpMessage(val segs: List<ByteBuffer>) {
    fun root(): StructR? = resolve(0, 0)?.takeIf { it.type == 0 }?.let { StructR(this, it.seg, it.word, it.dw, it.pc) }

    class Resolved(val type: Int, val seg: Int, val word: Int, val dw: Int, val pc: Int, val elem: Int, val count: Int)

    /** Follows the pointer stored at (seg, ptrWord), including single far pointers. */
    fun resolve(seg: Int, ptrWord: Int): Resolved? {
        val b = segs[seg]
        val at = ptrWord * 8
        if (at + 8 > b.limit()) return null
        val lo = b.getInt(at)
        val hi = b.getInt(at + 4)
        if (lo == 0 && hi == 0) return null
        val offset = lo shr 2
        return when (lo and 3) {
            0 -> Resolved(0, seg, ptrWord + 1 + offset, hi and 0xffff, hi ushr 16, 0, 0)
            1 -> Resolved(1, seg, ptrWord + 1 + offset, 0, 0, hi and 7, hi ushr 3)
            2 -> {
                require((lo ushr 2) and 1 == 0) { "double-far pointers not supported" }
                resolve(hi, lo ushr 3)
            }
            else -> Resolved(3, seg, 0, 0, 0, 0, hi) // capability pointer; count = cap table index
        }
    }

    companion object {
        fun read(inp: InputStream): CapnpMessage {
            val head = ByteArray(4).also { inp.readFully(it) }
            val count = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).int + 1
            // header = 1 u32 (count-1) + count u32 sizes, padded to a whole word; the first u32 is already read
            val sizes = ByteArray(((count + 2) / 2) * 8 - 4).also { inp.readFully(it) }
            val sb = ByteBuffer.wrap(sizes).order(ByteOrder.LITTLE_ENDIAN)
            val segs = (0 until count).map {
                val n = sb.getInt(it * 4)
                val bytes = ByteArray(n * 8).also { a -> inp.readFully(a) }
                ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            }
            return CapnpMessage(segs)
        }
    }
}

fun InputStream.readFully(b: ByteArray) {
    var n = 0
    while (n < b.size) {
        val r = read(b, n, b.size - n)
        if (r < 0) throw java.io.EOFException("stream closed after $n of ${b.size} bytes")
        n += r
    }
}

class StructR(val msg: CapnpMessage, val seg: Int, val word: Int, val dw: Int, val pc: Int) {
    private val b get() = msg.segs[seg]
    fun u8(off: Int) = if (off + 1 <= dw * 8) b.get(word * 8 + off).toInt() and 0xff else 0
    fun u16(off: Int) = if (off + 2 <= dw * 8) b.getShort(word * 8 + off).toInt() and 0xffff else 0
    fun u32(off: Int) = if (off + 4 <= dw * 8) b.getInt(word * 8 + off) else 0
    fun u64(off: Int) = if (off + 8 <= dw * 8) b.getLong(word * 8 + off) else 0L
    fun bit(bitOff: Int) = bitOff / 8 < dw * 8 && (b.get(word * 8 + bitOff / 8).toInt() shr (bitOff % 8)) and 1 == 1

    private fun ptr(i: Int) = if (i < pc) msg.resolve(seg, word + dw + i) else null

    fun struct(i: Int): StructR? = ptr(i)?.takeIf { it.type == 0 }?.let { StructR(msg, it.seg, it.word, it.dw, it.pc) }
    fun capIndex(i: Int): Int? = ptr(i)?.takeIf { it.type == 3 }?.count

    fun data(i: Int): ByteArray? = ptr(i)?.takeIf { it.type == 1 && it.elem == 2 }?.let {
        ByteArray(it.count).also { a -> msg.segs[it.seg].duplicate().also { d -> (d as java.nio.Buffer).position(it.word * 8) }.get(a) }
    }

    fun text(i: Int): String? = data(i)?.let { if (it.isNotEmpty()) String(it, 0, it.size - 1, Charsets.UTF_8) else "" }

    fun structList(i: Int): List<StructR> {
        val p = ptr(i)?.takeIf { it.type == 1 && it.elem == 7 } ?: return emptyList()
        val tagHi = msg.segs[p.seg].getInt(p.word * 8 + 4)
        val n = msg.segs[p.seg].getInt(p.word * 8) ushr 2
        val edw = tagHi and 0xffff
        val epc = tagHi ushr 16
        return (0 until n).map { StructR(msg, p.seg, p.word + 1 + it * (edw + epc), edw, epc) }
    }

    fun textList(i: Int): List<String> {
        val p = ptr(i)?.takeIf { it.type == 1 && it.elem == 6 } ?: return emptyList()
        return (0 until p.count).map { n ->
            val e = msg.resolve(p.seg, p.word + n)?.takeIf { it.type == 1 && it.elem == 2 }
            if (e == null) "" else ByteArray(e.count).also { a -> msg.segs[e.seg].duplicate().also { d -> (d as java.nio.Buffer).position(e.word * 8) }.get(a) }
                .let { if (it.isNotEmpty()) String(it, 0, it.size - 1, Charsets.UTF_8) else "" }
        }
    }
}
