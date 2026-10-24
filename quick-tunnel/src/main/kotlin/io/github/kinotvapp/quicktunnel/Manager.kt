package io.github.kinotvapp.quicktunnel

import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

const val CLIENT_VERSION = "kino-quick-tunnel/0.1"
const val DEFAULT_HA_CONNECTIONS = 2
const val MAX_HA_CONNECTIONS = 4
const val MAX_EDGES_PER_CYCLE = 5
const val DEFAULT_FIRST_CONNECT_TIMEOUT_MS = 30_000L
const val UNREGISTER_GRACE_S = 5L

/** Mirror of the Rust curve: 1s, 2s, 4s, 8s, 16s, then 30s. */
fun backoffMillis(attempt: Int): Long = (1L shl (attempt - 1).coerceIn(0, 5)).coerceAtMost(30) * 1000

interface TunnelListener {
    fun onRegistered(connIndex: Int, location: String) {}
    fun onLost(connIndex: Int, reason: String) {}
    fun onReconnecting(connIndex: Int, attempt: Int, delayMs: Long) {}
    fun onReconnectFailed(connIndex: Int, attempt: Int, error: TunnelException) {}
    fun onGaveUp(connIndex: Int, attempts: Int) {}
}

/** One registered QUIC connection to the edge. */
internal class Link(val conn: tech.kwik.core.QuicClientConnection, val control: ControlSession, val location: String) {
    /** Completes when the control stream ends or QUIC reports the connection gone. */
    val lost = CompletableFuture<String>()
}

class QuickTunnelHandle internal constructor(
    val url: String,
    val location: String,
    private val runtime: Runtime,
) : AutoCloseable {
    val metrics get() = runtime.metrics

    /** Close every QUIC connection so each reactor reconnects now (call when the device network changes). */
    fun reconnectNow() = runtime.dropAll("reconnect requested")

    /** Test hook: drop a single connection. */
    fun dropConnection(connIndex: Int) = runtime.drop(connIndex, "dropped by caller")

    /** Unregisters from the edge and closes everything. Safe to call twice. */
    fun shutdown() = runtime.shutdown()

    override fun close() = shutdown()

    internal class Runtime(
        val config: QuickTunnelManager,
        val tunnel: QuickTunnel,
        val registry: EdgeRegistry,
    ) {
        val metrics = TunnelMetrics()
        private val pool = LocalPool(config.localPort)
        private val stopped = AtomicBoolean(false)
        private val stopSignal = CompletableFuture<Unit>()
        private val links = ConcurrentHashMap<Int, Link>()
        private val reactors = CopyOnWriteArrayList<Thread>()
        private val streamPool = Executors.newCachedThreadPool { r -> Thread(r, "cfqt-stream").apply { isDaemon = true } }

        /** discover -> dial (up to 5 edges) -> register. */
        fun connectCycle(connIndex: Int, replaceExisting: Boolean): Link {
            val edges = registry.get(config.ipVersion).take(MAX_EDGES_PER_CYCLE)
            var last = "no edges"
            for (edge in edges) {
                if (stopped.get()) throw TunnelException.Shutdown()
                val conn = try {
                    dial(edge) { s -> streamPool.execute { proxyStream(s, config.localPort, pool, metrics) } }
                } catch (e: Exception) { last = "$edge: ${e.message}"; continue }
                var link: Link? = null
                try {
                    val control = ControlSession(conn.createStream(true)) { e -> link?.lost?.complete("control stream ended: ${e.message}") }
                    val details = control.register(tunnel.accountTag, tunnel.secret, tunnel.id, connIndex, CLIENT_VERSION, replaceExisting)
                    link = Link(conn, control, details.location)
                    conn.setConnectionListener { link.lost.complete("QUIC connection closed") }
                    return link
                } catch (e: Exception) {
                    runCatching { conn.close() }
                    // A refusal from the edge is not about this edge address: retrying other edges will not help.
                    if (e is TunnelException.Register) throw e
                    last = "$edge: ${e.message}"
                }
            }
            registry.invalidate() // every cached edge failed: the pool may have changed
            throw TunnelException.QuicDial(edges.size, last)
        }

        fun startReactor(connIndex: Int, initial: Link?, firstTryImmediately: Boolean) {
            reactors += thread(isDaemon = true, name = "cfqt-reactor-$connIndex") { reactor(connIndex, initial, firstTryImmediately) }
        }

        private fun reactor(connIndex: Int, initial: Link?, firstTryImmediately: Boolean) {
            var link = initial
            var replace = false
            var attempt = 0
            if (link != null) { links[connIndex] = link; config.listener.onRegistered(connIndex, link.location) }
            while (!stopped.get()) {
                if (link == null) {
                    attempt++
                    if (attempt > config.maxReconnectAttempts) { config.listener.onGaveUp(connIndex, attempt - 1); return }
                    val delay = if (attempt == 1 && firstTryImmediately && !replace) 0L else backoffMillis(attempt)
                    if (delay > 0) {
                        config.listener.onReconnecting(connIndex, attempt, delay)
                        if (waitStop(delay)) return
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
                    config.listener.onRegistered(connIndex, link.location)
                }
                val reason = CompletableFuture.anyOf(link.lost, stopSignal).get()
                if (stopped.get()) { closeGracefully(link); return }
                links.remove(connIndex)
                runCatching { link.conn.close() }
                config.listener.onLost(connIndex, reason.toString())
                link = null
                replace = true // the edge may still hold the dead registration for this index
            }
            link?.let { closeGracefully(it) }
        }

        private fun waitStop(ms: Long): Boolean = try { stopSignal.get(ms, TimeUnit.MILLISECONDS); true } catch (_: TimeoutException) { false }

        private fun closeGracefully(link: Link) {
            // Telling the edge first stops it routing requests to a connection we are about to close.
            link.control.unregister()
            runCatching { link.conn.closeAndWait(Duration.ofSeconds(UNREGISTER_GRACE_S)) }
        }

        fun drop(connIndex: Int, reason: String) { links[connIndex]?.let { it.lost.complete(reason); runCatching { it.conn.close() } } }
        fun dropAll(reason: String) = links.keys.forEach { drop(it, reason) }

        fun shutdown() {
            if (!stopped.compareAndSet(false, true)) return
            stopSignal.complete(Unit)
            reactors.forEach { it.join((UNREGISTER_GRACE_S + 5) * 1000) }
            streamPool.shutdownNow()
            pool.close()
        }
    }
}

/**
 * Entry point. All options have the Rust crate's defaults except [maxReconnectAttempts]: the crate gives up
 * after 10, but a phone that was offline for a few minutes should come back on its own.
 */
class QuickTunnelManager(
    val localPort: Int,
    haConnections: Int = DEFAULT_HA_CONNECTIONS,
    val serviceUrl: String = DEFAULT_SERVICE_URL,
    val userAgent: String = DEFAULT_USER_AGENT,
    /** Bounds the first connect cycle (discovery + dial + register); later reconnects are not bounded. */
    val firstConnectTimeoutMs: Long = DEFAULT_FIRST_CONNECT_TIMEOUT_MS,
    val ipVersion: IpVersionFilter = IpVersionFilter.AUTO,
    val listener: TunnelListener = object : TunnelListener {},
    val maxReconnectAttempts: Int = Int.MAX_VALUE,
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
        return QuickTunnelHandle(tunnel.url, first.location, rt)
    }
}
