package io.github.kinotvapp.quicktunnel

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TransportTest {
    private val open = mutableListOf<AutoCloseable>()
    @AfterTest fun cleanup() = open.forEach { runCatching { it.close() } }

    @Test fun `transport order follows the policy and the learned preference`() {
        assertEquals(listOf(Transport.QUIC, Transport.HTTP2), transportOrder(TransportPolicy.AUTO, preferHttp2 = false))
        assertEquals(listOf(Transport.HTTP2, Transport.QUIC), transportOrder(TransportPolicy.AUTO, preferHttp2 = true))
        assertEquals(listOf(Transport.QUIC), transportOrder(TransportPolicy.QUIC_ONLY, preferHttp2 = true))
        assertEquals(listOf(Transport.HTTP2), transportOrder(TransportPolicy.HTTP2_ONLY, preferHttp2 = false))
    }

    // ── connectCycle policy, with fake dialers ───────────────────────────────

    private val tunnel = QuickTunnel(UUID.randomUUID(), "t.trycloudflare.com", "tag", ByteArray(32))
    private val edges = (1..6).map { EdgeAddr(InetAddress.getByName("198.41.192.$it"), 7844) }
    private fun stubLink(t: Transport) = Link(t, ControlSession(ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream()), "loc", {}, {})

    private class Recorder : TunnelListener {
        val fallbacks = CopyOnWriteArrayList<String>()
        override fun onTransportFallback(connIndex: Int, reason: String) { fallbacks += reason }
    }

    private class Dialers(val quicWorks: Boolean = false, val h2Works: Boolean = true, val quicError: Exception = IOException("handshake timed out")) {
        val calls = CopyOnWriteArrayList<Transport>()
        val map: Map<Transport, EdgeDialer> = mapOf(
            Transport.QUIC to { _, _, _ -> calls += Transport.QUIC; if (quicWorks) Link(Transport.QUIC, ControlSession(ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream()), "q", {}, {}) else throw quicError },
            Transport.HTTP2 to { _, _, _ -> calls += Transport.HTTP2; if (h2Works) Link(Transport.HTTP2, ControlSession(ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream()), "h", {}, {}) else throw IOException("tls failed") },
        )
    }

    private fun runtime(policy: TransportPolicy, d: Dialers, listener: TunnelListener = Recorder(), now: () -> Long = System::currentTimeMillis): QuickTunnelHandle.Runtime {
        val cfg = QuickTunnelManager(1, transport = policy, listener = listener, registry = EdgeRegistry(discover = { edges }))
        return QuickTunnelHandle.Runtime(cfg, tunnel, EdgeRegistry(discover = { edges }), d.map, now).also { open += AutoCloseable { it.shutdown() } }
    }

    @Test fun `AUTO uses QUIC when it works and never touches TCP`() {
        val d = Dialers(quicWorks = true); val rt = runtime(TransportPolicy.AUTO, d)
        assertEquals(Transport.QUIC, rt.connectCycle(0, false).transport); assertEquals(listOf(Transport.QUIC), d.calls)
    }

    @Test fun `AUTO falls back to HTTP2 after trying only two QUIC edges and reports why`() {
        val d = Dialers(quicWorks = false); val rec = Recorder(); val rt = runtime(TransportPolicy.AUTO, d, rec)
        val link = rt.connectCycle(0, false)
        assertEquals(Transport.HTTP2, link.transport)
        assertEquals(listOf(Transport.QUIC, Transport.QUIC, Transport.HTTP2), d.calls, "2 QUIC edges, then HTTP2 works on its first edge")
        assertEquals(1, rec.fallbacks.size); assertTrue("handshake timed out" in rec.fallbacks[0], rec.fallbacks[0])
    }

    @Test fun `after a fallback HTTP2 goes first until the preference expires`() {
        var now = 1_000L
        val d = Dialers(quicWorks = false); val rt = runtime(TransportPolicy.AUTO, d, now = { now })
        rt.connectCycle(0, false); d.calls.clear()
        rt.connectCycle(0, true)
        assertEquals(listOf(Transport.HTTP2), d.calls, "no QUIC timeout is paid again")
        now += PREFER_HTTP2_MS + 1; d.calls.clear()
        rt.connectCycle(0, true)
        assertEquals(Transport.QUIC, d.calls.first(), "QUIC is retried once the preference expires")
    }

    @Test fun `AUTO tries up to five HTTP2 edges`() {
        val d = Dialers(quicWorks = false, h2Works = false); val rt = runtime(TransportPolicy.AUTO, d)
        val e = assertFailsWith<TunnelException.QuicDial> { rt.connectCycle(0, false) }
        assertEquals(2, d.calls.count { it == Transport.QUIC }); assertEquals(MAX_EDGES_PER_CYCLE, d.calls.count { it == Transport.HTTP2 })
        assertTrue(e.transient && "HTTP2" in e.message!!, e.message)
    }

    @Test fun `QUIC_ONLY never falls back`() {
        val d = Dialers(quicWorks = false); val rt = runtime(TransportPolicy.QUIC_ONLY, d)
        assertFailsWith<TunnelException.QuicDial> { rt.connectCycle(0, false) }
        assertTrue(d.calls.none { it == Transport.HTTP2 }); assertEquals(MAX_EDGES_PER_CYCLE, d.calls.size)
    }

    @Test fun `HTTP2_ONLY never touches QUIC`() {
        val d = Dialers(quicWorks = true); val rt = runtime(TransportPolicy.HTTP2_ONLY, d)
        assertEquals(Transport.HTTP2, rt.connectCycle(0, false).transport); assertEquals(listOf(Transport.HTTP2), d.calls)
    }

    @Test fun `a refusal from the edge is final and is not retried on another transport`() {
        val d = Dialers(quicWorks = false, quicError = TunnelException.Register("bad credentials")); val rt = runtime(TransportPolicy.AUTO, d)
        assertFailsWith<TunnelException.Register> { rt.connectCycle(0, false) }
        assertEquals(listOf(Transport.QUIC), d.calls)
    }

    // ── the real HTTP/2 registration path, over a loopback socket ───────────

    private fun h2Fixture(controlWaitS: Long = 10): Triple<QuickTunnelHandle.Runtime, java.net.Socket, MiniH2Client> {
        val (serverSide, clientSide) = socketPair()
        val cfg = QuickTunnelManager(1, transport = TransportPolicy.HTTP2_ONLY)
        val rt = QuickTunnelHandle.Runtime(cfg, tunnel, EdgeRegistry(discover = { edges }), h2ControlWaitS = controlWaitS).also { open += AutoCloseable { it.shutdown() } }
        open += AutoCloseable { serverSide.close() }
        val client = MiniH2Client(clientSide).also { open += it }
        return Triple(rt, serverSide, client)
    }

    private fun controlHeaders() = listOf(H2Headers.UPGRADE to H2Headers.CONTROL_STREAM)

    @Test fun `registerConnection runs over the control stream the edge opens`() {
        val (rt, server, client) = h2Fixture()
        val future = CompletableFuture<Link>()
        thread(isDaemon = true) { try { future.complete(rt.h2LinkOver(server.getInputStream(), server.getOutputStream(), connIndex = 1, replace = true) { server.close() }) } catch (e: Throwable) { future.completeExceptionally(e) } }

        val st = client.openStreaming("POST", "/", controlHeaders())
        lateinit var peer: RpcPeer
        peer = RpcPeer(client.inputOf(st), client.outputOf(st)) { c, p ->
            p.reply(if (c.method == 0) detailsReturn(c.question, UUID.randomUUID(), "bog04", false) else CapnpBuilder().apply {
                val m = root(1, 1); u16(m, 0, 3); val ret = struct(m + 1, 2, 1); u32(ret, 0, c.question); struct(ret + 2, 0, 2)
            }); true
        }
        val link = future.get(10, TimeUnit.SECONDS)
        assertEquals(Transport.HTTP2, link.transport); assertEquals("bog04", link.location)
        assertEquals(200, st.status, "the control stream is answered with 200 before any RPC bytes")
        val call = peer.calls.single()
        assertEquals(0xf71695ec7fe85497UL.toLong(), call.iface)
        assertEquals(1, call.params!!.u8(0), "connIndex"); assertTrue(call.params!!.struct(2)!!.bit(0), "replaceExisting")
        assertEquals(tunnel.id, fromBytes(call.params!!.data(1)!!))

        // Graceful close: unregisterConnection first, then the connection goes away.
        val closer = thread(isDaemon = true) { link.closeGracefully() }
        val deadline = System.currentTimeMillis() + 5000
        while (peer.calls.size < 2 && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertEquals(listOf(0, 1), peer.calls.map { it.method })
        closer.join(10_000)
    }

    @Test fun `the edge never opening a control stream fails the cycle with a clear error`() {
        val (rt, server, _) = h2Fixture(controlWaitS = 1)
        val e = assertFailsWith<TunnelException.Register> { rt.h2LinkOver(server.getInputStream(), server.getOutputStream(), 0, false) { } }
        assertTrue("control stream" in e.message!!, e.message)
    }

    @Test fun `a refusal on the control stream surfaces as the same typed error`() {
        val (rt, server, client) = h2Fixture()
        val future = CompletableFuture<Link>()
        thread(isDaemon = true) { try { future.complete(rt.h2LinkOver(server.getInputStream(), server.getOutputStream(), 0, false) { }) } catch (e: Throwable) { future.completeExceptionally(e) } }
        val st = client.openStreaming("POST", "/", controlHeaders())
        RpcPeer(client.inputOf(st), client.outputOf(st)) { c, p -> p.reply(errorReturn(c.question, DUPLICATE_CONNECTION_ERROR)); true }
        val e = assertFailsWith<java.util.concurrent.ExecutionException> { future.get(10, TimeUnit.SECONDS) }
        assertTrue(e.cause is TunnelException.DuplicateConnection, e.cause.toString())
    }

    @Test fun `losing the TCP connection marks the link lost`() {
        val (rt, server, client) = h2Fixture()
        val future = CompletableFuture<Link>()
        thread(isDaemon = true) { try { future.complete(rt.h2LinkOver(server.getInputStream(), server.getOutputStream(), 0, false) { }) } catch (e: Throwable) { future.completeExceptionally(e) } }
        val st = client.openStreaming("POST", "/", controlHeaders())
        RpcPeer(client.inputOf(st), client.outputOf(st)) { c, p -> p.reply(detailsReturn(c.question, UUID.randomUUID(), "x", false)); true }
        val link = future.get(10, TimeUnit.SECONDS)
        client.close()
        assertNotNull(link.lost.get(10, TimeUnit.SECONDS))
    }

    // ── reconnect backoff vs. the network coming back ────────────────────────

    private class Events : TunnelListener {
        val reconnecting = CopyOnWriteArrayList<Pair<Int, Long>>()
        override fun onReconnecting(connIndex: Int, attempt: Int, delayMs: Long) { reconnecting += attempt to delayMs }
    }

    @Test fun `reconnectNow cuts a backoff short instead of waiting it out`() {
        val tries = java.util.concurrent.atomic.AtomicInteger()
        val failing: EdgeDialer = { _, _, _ -> tries.incrementAndGet(); throw IOException("network is unreachable") }
        val events = Events()
        val cfg = QuickTunnelManager(1, transport = TransportPolicy.QUIC_ONLY, listener = events, registry = EdgeRegistry(discover = { edges }))
        val rt = QuickTunnelHandle.Runtime(cfg, tunnel, EdgeRegistry(discover = { edges }), mapOf(Transport.QUIC to failing)).also { open += AutoCloseable { it.shutdown() } }
        rt.startReactor(0, null, firstTryImmediately = true)

        // Wait until it is sleeping in a multi-second backoff.
        val end = System.currentTimeMillis() + 15_000
        while (events.reconnecting.none { it.second >= 4_000 } && System.currentTimeMillis() < end) Thread.sleep(20)
        assertTrue(events.reconnecting.any { it.second >= 4_000 }, "never reached a long backoff: ${events.reconnecting}")
        val before = tries.get()

        rt.reconnectNow()
        val deadline = System.currentTimeMillis() + 1_500
        while (tries.get() == before && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertTrue(tries.get() > before, "the reactor kept sleeping its backoff after the network came back")
        // ...and the backoff curve starts over rather than continuing from where it was.
        val after = events.reconnecting.last()
        assertEquals(1_000L, after.second, "next delay after a kick is the first step of the curve: $after")
    }

    @Test fun `shutdown wakes reactors that are sleeping in a backoff`() {
        val failing: EdgeDialer = { _, _, _ -> throw IOException("down") }
        val events = Events()
        val cfg = QuickTunnelManager(1, transport = TransportPolicy.QUIC_ONLY, listener = events, registry = EdgeRegistry(discover = { edges }))
        val rt = QuickTunnelHandle.Runtime(cfg, tunnel, EdgeRegistry(discover = { edges }), mapOf(Transport.QUIC to failing))
        rt.startReactor(0, null, firstTryImmediately = true)
        val end = System.currentTimeMillis() + 15_000
        while (events.reconnecting.none { it.second >= 4_000 } && System.currentTimeMillis() < end) Thread.sleep(20)
        val t0 = System.currentTimeMillis()
        rt.shutdown()
        assertTrue(System.currentTimeMillis() - t0 < 2_000, "shutdown must not wait for the backoff to elapse")
    }

    // ── lifetime and request limits ──────────────────────────────────────────

    private class LimitEvents : TunnelListener {
        val limits = CopyOnWriteArrayList<TunnelLimit>()
        override fun onLimitReached(limit: TunnelLimit) { limits += limit }
    }

    private fun limitRuntime(events: LimitEvents, maxLifetimeMs: Long = 0, maxRequests: Long = 0): QuickTunnelHandle.Runtime {
        val reg = EdgeRegistry(discover = { edges })
        val cfg = QuickTunnelManager(1, listener = events, maxLifetimeMs = maxLifetimeMs, maxRequests = maxRequests, registry = reg)
        val rt = QuickTunnelHandle.Runtime(cfg, tunnel, reg, emptyMap())
        rt.startLimits()
        open += AutoCloseable { rt.shutdown() }
        return rt
    }

    private fun serveOne(rt: QuickTunnelHandle.Runtime) = serve(QuicSink(ByteArrayOutputStream()), rt.metrics) { }

    @Test fun `maxRequests closes the tunnel when the last allowed request finishes`() {
        val events = LimitEvents(); val rt = limitRuntime(events, maxRequests = 3)
        serveOne(rt); serveOne(rt)
        assertTrue(events.limits.isEmpty(), "two of three: still open")
        serveOne(rt)
        assertEquals(listOf(TunnelLimit.REQUESTS), events.limits)
    }

    @Test fun `a failed request still counts as served`() {
        val events = LimitEvents(); val rt = limitRuntime(events, maxRequests = 1)
        serve(QuicSink(ByteArrayOutputStream()), rt.metrics) { error("origin exploded") }
        assertEquals(listOf(TunnelLimit.REQUESTS), events.limits)
    }

    @Test fun `the limit callback fires once even if more requests keep arriving`() {
        val events = LimitEvents(); val rt = limitRuntime(events, maxRequests = 1)
        repeat(5) { serveOne(rt) }
        assertEquals(1, events.limits.size)
    }

    @Test fun `no limits means no callback`() {
        val events = LimitEvents(); val rt = limitRuntime(events)
        repeat(20) { serveOne(rt) }
        Thread.sleep(200)
        assertTrue(events.limits.isEmpty())
    }

    @Test fun `maxLifetimeMs closes the tunnel after that long`() {
        val events = LimitEvents(); val t0 = System.currentTimeMillis()
        limitRuntime(events, maxLifetimeMs = 300)
        val end = t0 + 5_000
        while (events.limits.isEmpty() && System.currentTimeMillis() < end) Thread.sleep(10)
        assertEquals(listOf(TunnelLimit.LIFETIME), events.limits)
        assertTrue(System.currentTimeMillis() - t0 in 250..3_000)
    }

    @Test fun `closing earlier cancels the lifetime timer`() {
        val events = LimitEvents(); val rt = limitRuntime(events, maxLifetimeMs = 400)
        rt.shutdown()
        Thread.sleep(800)
        assertTrue(events.limits.isEmpty(), "a tunnel closed by hand must not report a limit afterwards")
    }

    @Test fun `closing from inside the limit callback does not deadlock`() {
        val closed = CompletableFuture<Unit>()
        lateinit var rt: QuickTunnelHandle.Runtime
        val listener = object : TunnelListener { override fun onLimitReached(limit: TunnelLimit) { rt.shutdown(); closed.complete(Unit) } }
        val reg = EdgeRegistry(discover = { edges })
        rt = QuickTunnelHandle.Runtime(QuickTunnelManager(1, listener = listener, maxRequests = 1, registry = reg), tunnel, reg, emptyMap())
        rt.startLimits()
        serveOne(rt)
        closed.get(5, TimeUnit.SECONDS)
    }
}
