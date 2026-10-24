package io.github.kinotvapp.quicktunnel

import java.net.ServerSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue

class PoolTest {
    private fun origin() = FakeOrigin { _, _, _, _, out -> out.respond("200 OK", ByteArray(0)); true }

    @Test fun `released sockets come back last-in first-out`() {
        origin().use { o ->
            val pool = LocalPool(o.port)
            val a = pool.acquire(); val b = pool.acquire(); assertFalse(a.reused)
            pool.release(a); pool.release(b)
            assertSame(b.socket, pool.acquire().socket); assertSame(a.socket, pool.acquire().socket)
            pool.close()
        }
    }

    @Test fun `idle sockets older than the ttl are dropped`() {
        origin().use { o ->
            var now = 0L
            val pool = LocalPool(o.port, idleTtlMs = 30_000, now = { now })
            val a = pool.acquire(); pool.release(a)
            now = 30_001
            val b = pool.acquire()
            assertFalse(b.reused); assertNotSame(a.socket, b.socket); assertTrue(a.socket.isClosed)
            pool.close()
        }
    }

    @Test fun `the idle list is capped`() {
        origin().use { o ->
            val pool = LocalPool(o.port, maxIdle = 2)
            val leases = List(4) { pool.acquire() }
            leases.forEach { pool.release(it) }
            assertEquals(2, pool.idleCount()); assertEquals(2, leases.count { it.socket.isClosed })
            pool.close()
        }
    }

    @Test fun `a socket the origin closed is detected and skipped`() {
        origin().use { o ->
            val pool = LocalPool(o.port)
            val a = pool.acquire(); pool.release(a)
            o.closeClients(); Thread.sleep(100)
            val b = pool.acquire()
            assertFalse(b.reused); assertNotSame(a.socket, b.socket)
            pool.close()
        }
    }

    @Test fun `close drops idle sockets and refuses new ones`() {
        origin().use { o ->
            val pool = LocalPool(o.port)
            val a = pool.acquire(); pool.release(a); pool.close()
            assertTrue(a.socket.isClosed); assertEquals(0, pool.idleCount())
            val b = pool.acquire(); pool.release(b); assertTrue(b.socket.isClosed)
        }
    }

    @Test fun `connecting to a closed port fails fast`() {
        val port = ServerSocket(0).use { it.localPort }
        assertFailsWith<java.io.IOException> { LocalPool(port).acquire() }
    }

    @Test fun `the pool connects to its own port not port zero`() {
        // Regression: inside Socket().apply { connect(.., port) } the name `port` resolved to Socket.getPort() == 0.
        origin().use { o -> val l = LocalPool(o.port).acquire(); assertEquals(o.port, l.socket.port); l.discard() }
    }
}
