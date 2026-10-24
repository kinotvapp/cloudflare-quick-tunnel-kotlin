package io.github.kinotvapp.quicktunnel

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConfigTest {
    @Test fun `HA connections are clamped to 1 through 4`() {
        assertEquals(1, QuickTunnelManager(1, haConnections = 0).haConnections)
        assertEquals(4, QuickTunnelManager(1, haConnections = 99).haConnections)
        assertEquals(DEFAULT_HA_CONNECTIONS, QuickTunnelManager(1).haConnections)
    }

    @Test fun `defaults match the Rust crate except the reconnect cap`() {
        val m = QuickTunnelManager(8080)
        assertEquals(DEFAULT_SERVICE_URL, m.serviceUrl); assertEquals(DEFAULT_USER_AGENT, m.userAgent)
        assertEquals(IpVersionFilter.AUTO, m.ipVersion); assertEquals(Int.MAX_VALUE, m.maxReconnectAttempts)
    }

    @Test fun `duplicate sentinel matches cloudflared byte for byte`() {
        assertEquals("edge already has connection registered for the given connection identifier", DUPLICATE_CONNECTION_ERROR)
    }

    @Test fun `only network class failures are transient`() {
        assertTrue(TunnelException.Api("x").transient); assertTrue(TunnelException.Discovery("x").transient); assertTrue(TunnelException.EdgeDial(1, "x").transient)
        assertTrue(TunnelException.ApiNonJson(503, "").transient); assertFalse(TunnelException.ApiNonJson(429, "").transient)
        assertFalse(TunnelException.ApiBusiness(emptyList()).transient); assertFalse(TunnelException.Register("x").transient)
    }

    @Test fun `the handle is closeable`() {
        assertTrue(AutoCloseable::class.java.isAssignableFrom(QuickTunnelHandle::class.java))
    }
}
