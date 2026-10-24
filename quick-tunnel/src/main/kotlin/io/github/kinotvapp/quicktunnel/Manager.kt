package io.github.kinotvapp.quicktunnel

import java.io.IOException
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.concurrent.thread

const val CLIENT_VERSION = "kino-quick-tunnel/0.2"
const val DEFAULT_HA_CONNECTIONS = 2
const val MAX_HA_CONNECTIONS = 4
const val MAX_EDGES_PER_CYCLE = 5
const val DEFAULT_FIRST_CONNECT_TIMEOUT_MS = 30_000L
const val UNREGISTER_GRACE_S = 5L

/** In AUTO, QUIC gets a short try (2 edges, 4 s each) so a network that drops UDP falls back quickly. */
const val AUTO_QUIC_EDGES = 2
const val AUTO_QUIC_HANDSHAKE_S = 4L

/** After QUIC failed and HTTP/2 worked, go straight to HTTP/2 for this long before trying QUIC again. */
const val PREFER_HTTP2_MS = 10 * 60_000L
const val H2_CONTROL_WAIT_S = 10L
const val H2_DRAIN_MS = 30_000L

/** Mirror of the Rust curve: 1s, 2s, 4s, 8s, 16s, then 30s. */
fun backoffMillis(attempt: Int): Long = (1L shl (attempt - 1).coerceIn(0, 5)).coerceAtMost(30) * 1000

enum class Transport { QUIC, HTTP2 }

enum class TransportPolicy {
    /** QUIC (UDP 7844) first, HTTP/2 over TCP 7844 when QUIC cannot connect. */
    AUTO,
    QUIC_ONLY,
    HTTP2_ONLY,
}

/** The order in which transports are tried for one connection cycle. */
internal fun transportOrder(policy: TransportPolicy, preferHttp2: Boolean): List<Transport> = when (policy) {
    TransportPolicy.QUIC_ONLY -> listOf(Transport.QUIC)
    TransportPolicy.HTTP2_ONLY -> listOf(Transport.HTTP2)
    TransportPolicy.AUTO -> if (preferHttp2) listOf(Transport.HTTP2, Transport.QUIC) else listOf(Transport.QUIC, Transport.HTTP2)
}

interface TunnelListener {
    fun onRegistered(connIndex: Int, location: String) {}
    /** Which transport the connection registered over (called right after [onRegistered]). */
    fun onTransport(connIndex: Int, transport: Transport) {}
    /** QUIC could not connect and HTTP/2 over TCP took over. [reason] is the last QUIC error. */
    fun onTransportFallback(connIndex: Int, reason: String) {}
    fun onLost(connIndex: Int, reason: String) {}
    fun onReconnecting(connIndex: Int, attempt: Int, delayMs: Long) {}
    fun onReconnectFailed(connIndex: Int, attempt: Int, error: TunnelException) {}
    fun onGaveUp(connIndex: Int, attempts: Int) {}
    /** [QuickTunnelManager.maxLifetimeMs] or [QuickTunnelManager.maxRequests] was reached; the tunnel is being closed. */
    fun onLimitReached(limit: TunnelLimit) {}
}

enum class TunnelLimit { LIFETIME, REQUESTS }

/** One registered connection to the edge, over either transport. */
internal class Link(
    val transport: Transport,
    val control: ControlSession,
    val location: String,
    private val closeNow: () -> Unit,
    private val closeDraining: () -> Unit,
) {
    /** Completes when the control stream ends or the transport reports the connection gone. */
    val lost = CompletableFuture<String>()
    fun close() = closeNow()
    /** Tells the edge to stop routing here, then closes. */
    fun closeGracefully() { control.unregister(); closeDraining() }
}

internal typealias EdgeDialer = (edge: EdgeAddr, connIndex: Int, replaceExisting: Boolean) -> Link

class QuickTunnelHandle internal constructor(
    val url: String,
    val location: String,
    private val runtime: Runtime,
) : AutoCloseable {
    val metrics get() = runtime.metrics

    /** Transport each connection index is currently registered over. */
    val transports: Map<Int, Transport> get() = runtime.transports()

    /**
     * Call when the device network changes or comes back. Closes every connection so each one reconnects, and cuts short
     * any reconnect backoff in progress: after being offline for a minute the next retry would otherwise be up to 30 s away.
     */
    fun reconnectNow() = runtime.reconnectNow()

    /** Test hook: drop a single connection. */
    fun dropConnection(connIndex: Int) = runtime.drop(connIndex, "dropped by caller")

    /** Unregisters from the edge and closes everything. Safe to call twice. */
    fun shutdown() = runtime.shutdown()

    override fun close() = shutdown()

    internal class Runtime(
        val config: QuickTunnelManager,
        val tunnel: QuickTunnel,
        val registry: EdgeRegistry,
        dialOverrides: Map<Transport, EdgeDialer> = emptyMap(),
        private val now: () -> Long = System::currentTimeMillis,
        private val h2ControlWaitS: Long = H2_CONTROL_WAIT_S,
    ) {
        val metrics = TunnelMetrics()
        private val pool = LocalPool(config.localPort)
        private val stopped = AtomicBoolean(false)
        private val stopSignal = CompletableFuture<Unit>()
        private val links = ConcurrentHashMap<Int, Link>()
        private val reactors = CopyOnWriteArrayList<Thread>()
        private val streamPool = Executors.newCachedThreadPool { r -> Thread(r, "cfqt-stream").apply { isDaemon = true } }
        @Volatile private var preferHttp2Until = 0L
        private val dialers: Map<Transport, EdgeDialer> = mapOf(Transport.QUIC to ::dialQuicLink, Transport.HTTP2 to ::dialHttp2Link) + dialOverrides

        fun transports(): Map<Int, Transport> = links.mapValues { it.value.transport }

        private val kickLock = ReentrantLock()
        private val kicked = kickLock.newCondition()
        private var kickGeneration = 0

        private enum class Wake { ELAPSED, KICKED, STOPPED }

        /** Wakes every reactor that is sleeping in a reconnect backoff. */
        fun kick() = kickLock.withLock { kickGeneration++; kicked.signalAll() }

        fun reconnectNow() { dropAll("reconnect requested"); kick() }

        /** Sleeps up to [ms], or less if the network came back ([kick]) or we are shutting down. */
        private fun sleepOrWake(ms: Long): Wake = kickLock.withLock {
            val generation = kickGeneration
            var left = TimeUnit.MILLISECONDS.toNanos(ms)
            while (left > 0) {
                if (stopped.get()) return Wake.STOPPED
                if (kickGeneration != generation) return Wake.KICKED
                left = kicked.awaitNanos(left)
            }
            if (stopped.get()) Wake.STOPPED else Wake.ELAPSED
        }

        /** discover -> dial (QUIC, then HTTP/2 per policy) -> register. */
        fun connectCycle(connIndex: Int, replaceExisting: Boolean): Link {
            val edges = registry.get(config.ipVersion)
            val order = transportOrder(config.transport, preferHttp2 = now() < preferHttp2Until)
            val errors = LinkedHashSet<String>() // one entry per distinct failure, so the first cause is not hidden by the last
            var quicError: String? = null
            for (transport in order) {
                val tryEdges = if (transport == Transport.QUIC && order.size > 1) edges.take(AUTO_QUIC_EDGES) else edges.take(MAX_EDGES_PER_CYCLE)
                for (edge in tryEdges) {
                    if (stopped.get()) throw TunnelException.Shutdown()
                    try {
                        val link = dialers.getValue(transport)(edge, connIndex, replaceExisting)
                        if (transport == Transport.HTTP2 && quicError != null) {
                            preferHttp2Until = now() + PREFER_HTTP2_MS
                            config.listener.onTransportFallback(connIndex, quicError)
                        }
                        return link
                    } catch (e: TunnelException.Register) {
                        throw e // the edge refused us: another address or transport will not change that
                    } catch (e: Exception) {
                        val reason = "$transport $edge: ${e.javaClass.simpleName}: ${e.message}"
                        errors += reason
                        if (transport == Transport.QUIC) quicError = reason
                    }
                }
            }
            registry.invalidate() // every cached edge failed: the pool may have changed
            throw TunnelException.QuicDial(edges.size, errors.take(6).joinToString(" | ").ifEmpty { "no edges" })
        }

        private fun dialQuicLink(edge: EdgeAddr, connIndex: Int, replace: Boolean): Link {
            val handshakeS = if (config.transport == TransportPolicy.AUTO) AUTO_QUIC_HANDSHAKE_S else HANDSHAKE_TIMEOUT_S
            val conn = dial(edge, { s -> streamPool.execute { proxyStream(s, config.localPort, pool, metrics) } }, handshakeS)
            var link: Link? = null
            try {
                val control = ControlSession(conn.createStream(true)) { e -> link?.lost?.complete("control stream ended: ${e.message}") }
                val details = control.register(tunnel.accountTag, tunnel.secret, tunnel.id, connIndex, CLIENT_VERSION, replace)
                link = Link(Transport.QUIC, control, details.location, { runCatching { conn.close() } }, { runCatching { conn.closeAndWait(Duration.ofSeconds(UNREGISTER_GRACE_S)) } })
                conn.setConnectionListener { link.lost.complete("QUIC connection closed") }
                return link
            } catch (e: Exception) {
                runCatching { conn.close() }
                throw e
            }
        }

        private fun dialHttp2Link(edge: EdgeAddr, connIndex: Int, replace: Boolean): Link {
            val connection = dialTcp(edge, tls = config.tcpTls)
            return h2LinkOver(connection.input, connection.output, connIndex, replace) { runCatching { connection.close() } }
        }

        /** Everything after the TCP+TLS connection exists; split out so it can run over in-memory streams in tests. */
        internal fun h2LinkOver(input: java.io.InputStream, output: java.io.OutputStream, connIndex: Int, replace: Boolean, closeTransport: () -> Unit): Link {
            val ctx = H2Context(config.localPort, pool, metrics)
            var link: Link? = null
            val connection = Http2Connection(input, output, streamPool, onRequest = { req -> routeH2(req, ctx) }, onClosed = { cause ->
                link?.lost?.complete("HTTP/2 connection closed${cause?.let { ": ${it.message}" } ?: ""}")
                ctx.release.complete(Unit)
                ctx.control.completeExceptionally(cause ?: IOException("HTTP/2 connection closed"))
                closeTransport()
            })
            connection.start()
            try {
                val controlReq = try {
                    ctx.control.get(h2ControlWaitS, TimeUnit.SECONDS)
                } catch (e: TimeoutException) {
                    throw TunnelException.Register("the edge did not open the control stream within ${h2ControlWaitS}s")
                } catch (e: java.util.concurrent.ExecutionException) {
                    throw e.cause ?: e
                }
                controlReq.response.sendHeaders(200, emptyList())
                val control = ControlSession(controlReq.body, controlReq.response.body) { e -> link?.lost?.complete("control stream ended: ${e.message}") }
                val details = control.register(tunnel.accountTag, tunnel.secret, tunnel.id, connIndex, CLIENT_VERSION, replace)
                link = Link(
                    Transport.HTTP2, control, details.location,
                    closeNow = { ctx.release.complete(Unit); connection.close(0) },
                    // Requests already running finish before the socket goes away, like cloudflared's activeRequestsWG.Wait().
                    closeDraining = { ctx.release.complete(Unit); connection.close(H2_DRAIN_MS) },
                )
                return link
            } catch (e: Exception) {
                runCatching { connection.close(0) }
                throw e
            }
        }

        fun startReactor(connIndex: Int, initial: Link?, firstTryImmediately: Boolean) {
            reactors += thread(isDaemon = true, name = "cfqt-reactor-$connIndex") { reactor(connIndex, initial, firstTryImmediately) }
        }

        private fun announce(connIndex: Int, link: Link) {
            config.listener.onRegistered(connIndex, link.location)
            config.listener.onTransport(connIndex, link.transport)
        }

        private fun reactor(connIndex: Int, initial: Link?, firstTryImmediately: Boolean) {
            var immediate = firstTryImmediately // only the very first attempt skips the delay
            var link = initial
            var replace = false
            var attempt = 0
            if (link != null) { links[connIndex] = link; announce(connIndex, link) }
            while (!stopped.get()) {
                if (link == null) {
                    attempt++
                    if (attempt > config.maxReconnectAttempts) { config.listener.onGaveUp(connIndex, attempt - 1); return }
                    val delay = if (immediate && attempt == 1 && !replace) 0L else backoffMillis(attempt)
                    immediate = false
                    if (delay > 0) {
                        config.listener.onReconnecting(connIndex, attempt, delay)
                        when (sleepOrWake(delay)) {
                            Wake.STOPPED -> return
                            Wake.KICKED -> attempt = 0 // the network is back: try right now (a free try), and restart the backoff curve
                            Wake.ELAPSED -> {}
                        }
                    }
                    link = try {
                        connectCycle(connIndex, replace)
                    } catch (e: TunnelException) {
                        if (e is TunnelException.DuplicateConnection) replace = true
                        config.listener.onReconnectFailed(connIndex, attempt, e)
                        continue
                    } catch (e: Exception) {
                        config.listener.onReconnectFailed(connIndex, attempt, TunnelException.Internal(e.toString(), e))
                        continue
                    }
                    if (replace) metrics.reconnects.incrementAndGet()
                    attempt = 0
                    links[connIndex] = link
                    announce(connIndex, link)
                }
                val reason = CompletableFuture.anyOf(link.lost, stopSignal).get()
                if (stopped.get()) { link.closeGracefully(); return }
                links.remove(connIndex)
                link.close()
                config.listener.onLost(connIndex, reason.toString())
                link = null
                replace = true // the edge may still hold the dead registration for this index
            }
            link?.closeGracefully()
        }

        private val limitFired = AtomicBoolean(false)

        /** Called when [QuickTunnelManager.maxLifetimeMs] or [QuickTunnelManager.maxRequests] is reached. Closes on its own thread. */
        fun limitReached(limit: TunnelLimit) {
            if (!limitFired.compareAndSet(false, true) || stopped.get()) return
            config.listener.onLimitReached(limit)
            thread(isDaemon = true, name = "cfqt-limit-close") { shutdown() } // a reactor or stream thread must not join itself
        }

        /** Starts the lifetime timer and the request counter configured on the manager. */
        fun startLimits() {
            if (config.maxRequests > 0) {
                metrics.onCompleted = { if (metrics.completed.get() >= config.maxRequests) limitReached(TunnelLimit.REQUESTS) }
            }
            if (config.maxLifetimeMs > 0) {
                thread(isDaemon = true, name = "cfqt-lifetime") {
                    try { stopSignal.get(config.maxLifetimeMs, TimeUnit.MILLISECONDS) } catch (_: TimeoutException) { limitReached(TunnelLimit.LIFETIME) }
                }
            }
        }

        fun drop(connIndex: Int, reason: String) { links[connIndex]?.let { it.lost.complete(reason); it.close() } }
        fun dropAll(reason: String) = links.keys.forEach { drop(it, reason) }

        fun shutdown() {
            if (!stopped.compareAndSet(false, true)) return
            stopSignal.complete(Unit)
            kick() // wake reactors that are sleeping in a backoff
            reactors.forEach { it.join((UNREGISTER_GRACE_S + 5) * 1000) }
            streamPool.shutdownNow()
            pool.close()
        }
    }
}

/**
 * Entry point. All options have the Rust crate's defaults except [maxReconnectAttempts] (the crate gives up after 10, but
 * a phone that was offline for a few minutes should come back on its own) and [transport] (the crate has no HTTP/2).
 */
class QuickTunnelManager(
    val localPort: Int,
    haConnections: Int = DEFAULT_HA_CONNECTIONS,
    val serviceUrl: String = DEFAULT_SERVICE_URL,
    val userAgent: String = DEFAULT_USER_AGENT,
    /** Bounds the first connect cycle (discovery + dial + register); later reconnects are not bounded. */
    val firstConnectTimeoutMs: Long = DEFAULT_FIRST_CONNECT_TIMEOUT_MS,
    val ipVersion: IpVersionFilter = IpVersionFilter.AUTO,
    val transport: TransportPolicy = TransportPolicy.AUTO,
    /** Which TLS carries the TCP transport; the default picks the platform's when it can do TLS 1.3. */
    val tcpTls: TcpTls = TcpTls.AUTO,
    val listener: TunnelListener = object : TunnelListener {},
    val maxReconnectAttempts: Int = Int.MAX_VALUE,
    /** Close the tunnel this long after [start] returns. 0 = no limit. [TunnelListener.onLimitReached] fires first. */
    val maxLifetimeMs: Long = 0,
    /** Close the tunnel once this many edge-opened requests have been served (a request counts when it finishes). 0 = no limit. */
    val maxRequests: Long = 0,
    private val registry: EdgeRegistry = EdgeRegistry(),
) {
    val haConnections: Int = haConnections.coerceIn(1, MAX_HA_CONNECTIONS)

    /** Blocks until the first connection is registered, so the URL is already live when it returns. */
    fun start(): QuickTunnelHandle {
        val tunnel = requestTunnel(serviceUrl, userAgent)
        val rt = QuickTunnelHandle.Runtime(this, tunnel, registry)
        val result = CompletableFuture<Link>()
        thread(isDaemon = true, name = "cfqt-first-connect") {
            try { result.complete(rt.connectCycle(0, replaceExisting = false)) } catch (e: Throwable) { result.completeExceptionally(e) }
        }
        val first = try {
            result.get(firstConnectTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            rt.shutdown(); throw TunnelException.QuicDial(1, "first connect cycle timed out after ${firstConnectTimeoutMs}ms")
        } catch (e: java.util.concurrent.ExecutionException) {
            rt.shutdown(); throw (e.cause as? TunnelException ?: TunnelException.Internal(e.cause.toString(), e.cause))
        }
        rt.startReactor(0, first, firstTryImmediately = false)
        for (idx in 1 until haConnections) rt.startReactor(idx, null, firstTryImmediately = true)
        rt.startLimits()
        return QuickTunnelHandle(tunnel.url, first.location, rt)
    }
}
