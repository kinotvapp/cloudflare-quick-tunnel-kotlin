package io.github.kinotvapp.quicktunnel

import org.xbill.DNS.AAAARecord
import org.xbill.DNS.ARecord
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.SRVRecord
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.Type
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

const val SRV_NAME = "_v2-origintunneld._tcp.argotunnel.com."
const val DOT_SERVER_NAME = "cloudflare-dns.com"
const val DOT_SERVER_ADDR = "1.1.1.1"
const val DOT_PORT = 853
const val DNS_TIMEOUT_MS = 5_000
const val DEFAULT_EDGE_CACHE_TTL_MS = 3_600_000L

enum class IpVersionFilter { AUTO, V4_ONLY, V6_ONLY }

class EdgeAddr(val ip: InetAddress, val port: Int) {
    val isV4 get() = ip.address.size == 4
    fun matches(f: IpVersionFilter) = when (f) { IpVersionFilter.AUTO -> true; IpVersionFilter.V4_ONLY -> isV4; IpVersionFilter.V6_ONLY -> !isV4 }
    override fun toString() = "${ip.hostAddress}:$port"
}

/** Anything that can answer one DNS question. Android has no SRV API, so we ask resolvers directly. */
fun interface DnsTransport { fun query(name: String, type: Int): List<Record> }

class PlainDns(private val server: String, private val tcp: Boolean) : DnsTransport {
    override fun query(name: String, type: Int): List<Record> {
        val r = SimpleResolver(server).apply { setTCP(tcp); timeout = java.time.Duration.ofMillis(DNS_TIMEOUT_MS.toLong()) }
        return r.send(Message.newQuery(Record.newRecord(Name.fromString(name), type, DClass.IN))).getSection(Section.ANSWER)
    }
}

/** DNS-over-TLS (RFC 7858), for networks that intercept plain port-53 traffic. */
class DotDns(private val ip: String = DOT_SERVER_ADDR, private val serverName: String = DOT_SERVER_NAME, private val port: Int = DOT_PORT) : DnsTransport {
    override fun query(name: String, type: Int): List<Record> {
        val wire = Message.newQuery(Record.newRecord(Name.fromString(name), type, DClass.IN)).toWire()
        val plain = Socket().apply { connect(InetSocketAddress(ip, port), DNS_TIMEOUT_MS); soTimeout = DNS_TIMEOUT_MS }
        plain.use {
            // SNI and certificate name come from serverName, the address from ip.
            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain, serverName, port, true) as SSLSocket
            tls.sslParameters = SSLParameters().apply { endpointIdentificationAlgorithm = "HTTPS" }
            tls.startHandshake()
            val out = DataOutputStream(tls.outputStream); out.writeShort(wire.size); out.write(wire); out.flush()
            val inp = DataInputStream(tls.inputStream)
            val reply = ByteArray(inp.readUnsignedShort()).also { inp.readFully(it) }
            return Message(reply).getSection(Section.ANSWER)
        }
    }
}

val DEFAULT_DNS_CHAIN: List<DnsTransport> = listOf(
    PlainDns("1.1.1.1", false), PlainDns("1.1.1.1", true), PlainDns("1.0.0.1", false), PlainDns("8.8.8.8", false), DotDns(),
)

/** SRV -> A/AAAA through the same transport (system DNS may be the thing that is broken). */
internal fun resolveVia(dns: DnsTransport, filter: IpVersionFilter): List<EdgeAddr> =
    dns.query(SRV_NAME, Type.SRV).filterIsInstance<SRVRecord>().flatMap { rec ->
        val host = rec.target.toString()
        val ips = buildList {
            if (filter != IpVersionFilter.V6_ONLY) runCatching { dns.query(host, Type.A) }.getOrDefault(emptyList()).filterIsInstance<ARecord>().forEach { add(it.address) }
            if (filter != IpVersionFilter.V4_ONLY) runCatching { dns.query(host, Type.AAAA) }.getOrDefault(emptyList()).filterIsInstance<AAAARecord>().forEach { add(it.address) }
        }
        ips.map { EdgeAddr(it, rec.port) }
    }.filter { it.matches(filter) }

/** First transport in the chain that yields edges wins. IPv4 first inside AUTO, shuffled inside each family. */
fun discoverEdges(filter: IpVersionFilter = IpVersionFilter.AUTO, chain: List<DnsTransport> = DEFAULT_DNS_CHAIN): List<EdgeAddr> {
    var last: Exception? = null
    for (dns in chain) {
        try {
            val edges = resolveVia(dns, filter)
            if (edges.isNotEmpty()) return edges.partition { it.isV4 }.let { (v4, v6) -> v4.shuffled() + v6.shuffled() }
            last = TunnelException.Discovery("no edges from $dns")
        } catch (e: Exception) {
            last = e
        }
    }
    throw TunnelException.Discovery("every resolver failed; last: $last", last)
}

/** In-memory cache so repeated reconnects do not hammer DNS; each call gets a fresh shuffle. */
class EdgeRegistry(
    private val ttlMs: Long = DEFAULT_EDGE_CACHE_TTL_MS,
    private val discover: (IpVersionFilter) -> List<EdgeAddr> = { discoverEdges(it) },
    private val now: () -> Long = System::currentTimeMillis,
) {
    private class Cached(val edges: List<EdgeAddr>, val expiresAt: Long, val filter: IpVersionFilter)
    private var cached: Cached? = null

    @Synchronized fun get(filter: IpVersionFilter): List<EdgeAddr> {
        cached?.takeIf { it.filter == filter && it.expiresAt > now() }?.let { return it.edges.shuffled() }
        val edges = discover(filter)
        cached = Cached(edges, now() + ttlMs, filter)
        return edges.shuffled()
    }

    /** Call when every cached edge failed: the pool may have changed. */
    @Synchronized fun invalidate() { cached = null }
}
