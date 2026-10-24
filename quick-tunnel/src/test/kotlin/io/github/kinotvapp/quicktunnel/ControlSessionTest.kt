package io.github.kinotvapp.quicktunnel

import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** What the edge sees of one registerConnection call. */
class SeenCall(val question: Int, val target: Int, val iface: Long, val method: Int, val params: StructR?)

/** A scripted edge on the far side of two pipes: answers Bootstrap and Calls the way cloudflared's edge does. */
class FakeEdge(private val respond: (SeenCall, CapnpBuilder) -> Boolean) {
    private val c2e = PipedOutputStream(); private val e2c = PipedOutputStream()
    private val edgeIn = PipedInputStream(c2e, 1 shl 16); private val clientIn = PipedInputStream(e2c, 1 shl 16)
    val clientOut get() = c2e
    val clientInput get() = clientIn
    val calls = CopyOnWriteArrayList<SeenCall>()
    val returnsFromClient = CopyOnWriteArrayList<StructR>()
    val exportId = 7

    private fun send(b: CapnpBuilder) { e2c.write(b.frame()); e2c.flush() }

    fun returnBootstrap(q: Int) = CapnpBuilder().apply {
        val m = root(1, 1); u16(m, 0, 3); val ret = struct(m + 1, 2, 1); u32(ret, 0, q); u16(ret, 6, 0)
        val payload = struct(ret + 2, 0, 2); capPtr(payload, 0)
        val cap = structList(payload + 1, 1, 1, 1); u16(cap, 0, 1); u32(cap, 4, exportId)
    }

    private val loop = thread(isDaemon = true) {
        try {
            while (true) {
                val root = CapnpMessage.read(edgeIn).root() ?: break
                val body = root.struct(0)
                when (root.u16(0)) {
                    8 -> send(returnBootstrap(body!!.u32(0)))
                    2 -> {
                        val c = SeenCall(body!!.u32(0), body.struct(0)!!.u32(0), body.u64(8), body.u16(4), body.struct(1)?.struct(0))
                        calls += c
                        if (!respond(c, CapnpBuilder())) continue
                    }
                    3 -> returnsFromClient += body!!
                }
            }
        } catch (_: Exception) { /* pipe closed */ }
    }

    fun reply(b: CapnpBuilder) = send(b)
    fun askClientBootstrap(q: Int) = send(CapnpBuilder().apply { val m = root(1, 1); u16(m, 0, 8); val b = struct(m + 1, 1, 1); u32(b, 0, q) })
    fun callClient(q: Int, target: Int) = send(CapnpBuilder().apply {
        val m = root(1, 1); u16(m, 0, 2); val c = struct(m + 1, 3, 3); u32(c, 0, q); struct(c + 3, 1, 1).also { u32(it, 0, target) }; struct(c + 4, 0, 2)
    })
    fun closeFromEdge() = e2c.close()
}

fun detailsReturn(q: Int, uuid: UUID, location: String, managed: Boolean) = CapnpBuilder().apply {
    val m = root(1, 1); u16(m, 0, 3); val ret = struct(m + 1, 2, 1); u32(ret, 0, q); u16(ret, 6, 0)
    val payload = struct(ret + 2, 0, 2); val results = struct(payload, 0, 1)
    val resp = struct(results, 1, 1); u16(resp, 0, 1)
    val det = struct(resp + 1, 1, 2); data(det + 1, uuid.toBytes()); text(det + 2, location); bit(det, 0, managed)
}

fun errorReturn(q: Int, cause: String) = CapnpBuilder().apply {
    val m = root(1, 1); u16(m, 0, 3); val ret = struct(m + 1, 2, 1); u32(ret, 0, q); u16(ret, 6, 0)
    val payload = struct(ret + 2, 0, 2); val results = struct(payload, 0, 1)
    val resp = struct(results, 1, 1); u16(resp, 0, 0)
    val err = struct(resp + 1, 2, 1); text(err + 2, cause)
}

fun exceptionReturn(q: Int, reason: String) = CapnpBuilder().apply {
    val m = root(1, 1); u16(m, 0, 3); val ret = struct(m + 1, 2, 1); u32(ret, 0, q); u16(ret, 6, 1)
    val ex = struct(ret + 2, 1, 3); text(ex + 1, reason)
}

class ControlSessionTest {
    private val closers = mutableListOf<() -> Unit>()
    @AfterTest fun cleanup() = closers.forEach { runCatching(it) }

    private fun session(edge: FakeEdge, onClosed: (Throwable) -> Unit = {}) = ControlSession(edge.clientInput, edge.clientOut, onClosed).also { closers += { edge.closeFromEdge() } }

    private val tunnelId = UUID.fromString("8f6d3c2a-1111-4d2e-9b9b-aaaaaaaaaaaa")
    private val secret = ByteArray(32) { (it + 1).toByte() }

    @Test fun `registerConnection sends the fields the edge reads and parses the details`() {
        val edgeUuid = UUID.randomUUID()
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(detailsReturn(c.question, edgeUuid, "bog04", managed = true)); true }
        val d = session(edge).register("deadbeef", secret, tunnelId, connIndex = 2, version = "test/1", replaceExisting = true)
        assertEquals(edgeUuid, d.uuid); assertEquals("bog04", d.location); assertTrue(d.remotelyManaged)

        val call = edge.calls.single()
        assertEquals(edge.exportId, call.target, "the call targets the capability the edge exported")
        assertEquals(0xf71695ec7fe85497UL.toLong(), call.iface); assertEquals(0, call.method)
        val p = call.params!!
        assertEquals(2, p.u8(0), "connIndex")
        assertEquals("deadbeef", p.struct(0)!!.text(0)); assertContentEquals(secret, p.struct(0)!!.data(1))
        assertEquals(tunnelId, fromBytes(p.data(1)!!))
        val o = p.struct(2)!!
        assertTrue(o.bit(0), "replaceExisting"); assertEquals(0, o.u8(1)); assertEquals(0, o.u8(2))
        val client = o.struct(0)!!
        assertEquals(16, client.data(0)!!.size)
        assertEquals(listOf("allow_remote_config", "serialized_headers", "support_datagram_v2", "support_quic_eof", "management_logs"), client.textList(1))
        assertEquals("test/1", client.text(2)); assertTrue(client.text(3)!!.startsWith("jvm-"))
    }

    @Test fun `replaceExisting defaults to false on the wire`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(detailsReturn(c.question, UUID.randomUUID(), "x", false)); true }
        session(edge).register("t", secret, tunnelId, 0, "v")
        assertEquals(false, edge.calls.single().params!!.struct(2)!!.bit(0))
    }

    @Test fun `the duplicate-connection refusal gets its own type`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(errorReturn(c.question, DUPLICATE_CONNECTION_ERROR)); true }
        assertFailsWith<TunnelException.DuplicateConnection> { session(edge).register("t", secret, tunnelId, 0, "v") }
    }

    @Test fun `any other refusal carries the edge's cause`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(errorReturn(c.question, "bad credentials")); true }
        val e = assertFailsWith<TunnelException.Register> { session(edge).register("t", secret, tunnelId, 0, "v") }
        assertTrue("bad credentials" in e.message!!)
    }

    @Test fun `an RPC exception from the edge is a Register failure`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(exceptionReturn(c.question, "boom")); true }
        val e = assertFailsWith<TunnelException.Register> { session(edge).register("t", secret, tunnelId, 0, "v") }
        assertTrue("boom" in e.message!!)
    }

    @Test fun `the edge's own Bootstrap gets an export so it does not mark the tunnel offline`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(detailsReturn(c.question, UUID.randomUUID(), "x", false)); true }
        val s = session(edge)
        edge.askClientBootstrap(9)
        s.register("t", secret, tunnelId, 0, "v")
        val ret = edge.returnsFromClient.first { it.u32(0) == 9 }
        assertEquals(0, ret.u16(6), "results, not exception")
        assertEquals(1, ret.struct(0)!!.structList(1).single().u16(0), "senderHosted")
    }

    @Test fun `calls the edge makes on our stub fail as unimplemented instead of hanging`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(detailsReturn(c.question, UUID.randomUUID(), "x", false)); true }
        session(edge).register("t", secret, tunnelId, 0, "v")
        edge.callClient(21, 0)
        val deadline = System.currentTimeMillis() + 3000
        while (edge.returnsFromClient.none { it.u32(0) == 21 } && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertEquals(1, edge.returnsFromClient.first { it.u32(0) == 21 }.u16(6), "exception")
    }

    @Test fun `unregister calls method 1 on the same capability`() {
        lateinit var edge: FakeEdge
        edge = FakeEdge { c, _ -> edge.reply(if (c.method == 0) detailsReturn(c.question, UUID.randomUUID(), "x", false) else CapnpBuilder().apply {
            val m = root(1, 1); u16(m, 0, 3); val ret = struct(m + 1, 2, 1); u32(ret, 0, c.question); struct(ret + 2, 0, 2)
        }); true }
        val s = session(edge)
        s.register("t", secret, tunnelId, 0, "v"); s.unregister()
        assertEquals(listOf(0, 1), edge.calls.map { it.method }); assertEquals(edge.exportId, edge.calls[1].target)
    }

    @Test fun `unregister before registering is a no-op`() {
        val edge = FakeEdge { _, _ -> true }
        session(edge).unregister()
        assertEquals(0, edge.calls.size)
    }

    @Test fun `closing the stream from the edge notifies the owner`() {
        val closed = CompletableFuture<Throwable>()
        val edge = FakeEdge { _, _ -> true }
        session(edge) { closed.complete(it) }
        edge.closeFromEdge()
        assertTrue(closed.get(3, TimeUnit.SECONDS) != null)
    }

    @Test fun `a register that never gets answered times out instead of hanging`() {
        // The edge reads the Call and stays silent; awaitReturn has a 15s budget, so only check the cheaper path:
        val edge = FakeEdge { _, _ -> false }
        val s = session(edge)
        edge.closeFromEdge() // reader dies, the pending call is failed immediately
        assertFailsWith<Exception> { s.register("t", secret, tunnelId, 0, "v") }
    }
}
