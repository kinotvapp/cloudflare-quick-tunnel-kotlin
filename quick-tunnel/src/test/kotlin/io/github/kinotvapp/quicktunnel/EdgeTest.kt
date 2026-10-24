package io.github.kinotvapp.quicktunnel

import org.xbill.DNS.AAAARecord
import org.xbill.DNS.ARecord
import org.xbill.DNS.DClass
import org.xbill.DNS.Name
import org.xbill.DNS.SRVRecord
import org.xbill.DNS.Type
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class EdgeTest {
    private fun edge(ip: String) = EdgeAddr(InetAddress.getByName(ip), 7844)

    @Test fun `registry serves the cache until the ttl expires`() {
        var now = 0L; var calls = 0
        val reg = EdgeRegistry(ttlMs = 1000, discover = { calls++; listOf(edge("198.41.192.1"), edge("198.41.192.2")) }, now = { now })
        assertEquals(2, reg.get(IpVersionFilter.AUTO).size); reg.get(IpVersionFilter.AUTO); assertEquals(1, calls)
        now = 1500; reg.get(IpVersionFilter.AUTO); assertEquals(2, calls)
    }

    @Test fun `registry refetches on another filter or after invalidate`() {
        var calls = 0
        val reg = EdgeRegistry(discover = { calls++; listOf(edge("198.41.192.1")) })
        reg.get(IpVersionFilter.AUTO); reg.get(IpVersionFilter.V4_ONLY); assertEquals(2, calls)
        reg.invalidate(); reg.get(IpVersionFilter.V4_ONLY); assertEquals(3, calls)
    }

    @Test fun `registry keeps IPv4 edges ahead of IPv6 on every call`() {
        val all = listOf("2606:4700:a0::1", "198.41.192.1", "2606:4700:a0::2", "198.41.192.2", "198.41.192.3").map { edge(it) }
        val reg = EdgeRegistry(discover = { all })
        repeat(20) { val got = reg.get(IpVersionFilter.AUTO); assertTrue(got.take(3).all { it.isV4 } && got.drop(3).none { it.isV4 }, got.toString()) }
    }

    @Test fun `registry returns every edge in some order`() {
        val all = (1..8).map { edge("198.41.192.$it") }
        val got = EdgeRegistry(discover = { all }).get(IpVersionFilter.AUTO)
        assertEquals(all.map { it.toString() }.toSet(), got.map { it.toString() }.toSet())
    }

    private fun fakeDns(): DnsTransport {
        val srvHost = Name.fromString("region1.v2.argotunnel.com.")
        return DnsTransport { name, type ->
            when {
                name == SRV_NAME -> listOf(SRVRecord(Name.fromString(SRV_NAME), DClass.IN, 60, 1, 1, 7844, srvHost))
                name == "region1.v2.argotunnel.com." && type == Type.A -> listOf(ARecord(srvHost, DClass.IN, 60, InetAddress.getByName("198.41.192.7")))
                name == "region1.v2.argotunnel.com." && type == Type.AAAA -> listOf(AAAARecord(srvHost, DClass.IN, 60, InetAddress.getByName("2606:4700:a0::1")))
                else -> emptyList()
            }
        }
    }

    @Test fun `discovery resolves SRV targets and puts IPv4 first`() {
        val edges = discoverEdges(IpVersionFilter.AUTO, listOf(fakeDns()))
        assertEquals(listOf("198.41.192.7", "2606:4700:a0:0:0:0:0:1"), edges.map { it.ip.hostAddress }); assertEquals(7844, edges[0].port)
    }

    @Test fun `ip version filter drops the other family`() {
        assertTrue(discoverEdges(IpVersionFilter.V4_ONLY, listOf(fakeDns())).all { it.isV4 })
        assertTrue(discoverEdges(IpVersionFilter.V6_ONLY, listOf(fakeDns())).none { it.isV4 })
    }

    @Test fun `discovery falls through broken transports to the next one`() {
        val broken = DnsTransport { _, _ -> throw java.io.IOException("intercepted") }
        val empty = DnsTransport { _, _ -> emptyList() }
        assertEquals(2, discoverEdges(IpVersionFilter.AUTO, listOf(broken, empty, fakeDns())).size)
    }

    @Test fun `discovery fails with a typed error when every transport fails`() {
        val e = assertFailsWith<TunnelException.Discovery> { discoverEdges(IpVersionFilter.AUTO, listOf(DnsTransport { _, _ -> emptyList() })) }
        assertTrue(e.transient)
    }
}
