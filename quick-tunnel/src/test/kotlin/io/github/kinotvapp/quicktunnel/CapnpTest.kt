package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CapnpTest {
    private fun read(b: CapnpBuilder) = CapnpMessage.read(ByteArrayInputStream(b.frame())).root()!!

    @Test fun `scalars land at the documented offsets`() {
        val r = read(CapnpBuilder().apply { val s = root(2, 0); u8(s, 0, 0xAB); u16(s, 2, 0xBEEF); u32(s, 4, -2); u64(s, 8, 0x1122334455667788L); bit(s, 3, true) })
        assertEquals(0xAB or 0x08, r.u8(0)); assertEquals(0xBEEF, r.u16(2)); assertEquals(-2, r.u32(4)); assertEquals(0x1122334455667788L, r.u64(8))
        assertTrue(r.bit(3))
    }

    @Test fun `reading past the data section yields zero like Cap'n Proto defaults`() {
        val r = read(CapnpBuilder().apply { root(1, 0) })
        assertEquals(0, r.u32(12)); assertEquals(0L, r.u64(8)); assertEquals(false, r.bit(200))
    }

    @Test fun `text data text lists and nested structs round trip`() {
        val r = read(CapnpBuilder().apply {
            val s = root(0, 4)
            text(s, "héllo"); data(s + 1, byteArrayOf(1, 2, 3)); textList(s + 2, listOf("a", "bb", ""))
            val inner = struct(s + 3, 1, 0); u32(inner, 0, 42)
        })
        assertEquals("héllo", r.text(0)); assertContentEquals(byteArrayOf(1, 2, 3), r.data(1)); assertEquals(listOf("a", "bb", ""), r.textList(2))
        assertEquals(42, r.struct(3)!!.u32(0))
    }

    @Test fun `null pointers read as null`() {
        val r = read(CapnpBuilder().apply { root(0, 2) })
        assertNull(r.text(0)); assertNull(r.struct(1)); assertEquals(emptyList(), r.structList(0)); assertNull(r.text(5))
    }

    @Test fun `struct lists keep element order and layout`() {
        val r = read(CapnpBuilder().apply {
            val s = root(0, 1); val l = structList(s, 3, 1, 1)
            for (i in 0..2) { u32(l + i * 2, 0, i * 10); text(l + i * 2 + 1, "e$i") }
        })
        assertEquals(listOf(0, 10, 20), r.structList(0).map { it.u32(0) }); assertEquals(listOf("e0", "e1", "e2"), r.structList(0).map { it.text(0) })
    }

    @Test fun `the builder grows past its initial buffer`() {
        val big = ByteArray(50_000) { it.toByte() }
        assertContentEquals(big, read(CapnpBuilder().apply { data(root(0, 1), big) }).data(0))
    }

    @Test fun `single far pointers are followed into another segment`() {
        // segment 0: [root ptr -> far(seg1 word0)]; segment 1: [landing pad: struct ptr offset 0, 1 data word][data word = 7]
        val seg0 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).apply { putInt(0, (0 shl 3) or 2); putInt(4, 1) }
        val seg1 = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply { putInt(0, 0 shl 2); putInt(4, 1); putInt(8, 7) }
        assertEquals(7, CapnpMessage(listOf(seg0, seg1)).root()!!.u32(0))
    }

    @Test fun `multi segment frames are parsed`() {
        val f = ByteBuffer.allocate(16 + 8 + 8).order(ByteOrder.LITTLE_ENDIAN).apply { putInt(1); putInt(1); putInt(1); putInt(0) /*pad*/; putLong(0); putLong(0) }
        assertEquals(2, CapnpMessage.read(ByteArrayInputStream(f.array())).segs.size)
    }
}
