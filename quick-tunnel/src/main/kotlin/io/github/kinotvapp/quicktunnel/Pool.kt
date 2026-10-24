package io.github.kinotvapp.quicktunnel

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

const val DEFAULT_IDLE_TTL_MS = 30_000L
const val DEFAULT_MAX_IDLE = 16
const val LOCAL_CONNECT_TIMEOUT_MS = 5_000

class Lease(val socket: Socket, val reused: Boolean) {
    val input get() = socket.getInputStream()
    val output get() = socket.getOutputStream()
    fun discard() { runCatching { socket.close() } }
}

/**
 * LIFO cache of idle keep-alive sockets to 127.0.0.1:<port>. Most servers close idle connections
 * after ~30s, so entries older than the TTL are dropped instead of tried.
 */
class LocalPool(
    private val localPort: Int,
    private val idleTtlMs: Long = DEFAULT_IDLE_TTL_MS,
    private val maxIdle: Int = DEFAULT_MAX_IDLE,
    private val connectTimeoutMs: Int = LOCAL_CONNECT_TIMEOUT_MS,
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
) {
    private class Idle(val socket: Socket, val since: Long)
    private val idle = ArrayDeque<Idle>()
    private var closed = false

    /** A live idle socket if there is one, otherwise a new connection. Throws like Socket.connect. */
    fun acquire(): Lease {
        while (true) {
            val candidate = synchronized(this) { idle.removeLastOrNull() } ?: break
            if (now() - candidate.since > idleTtlMs || !looksAlive(candidate.socket)) { runCatching { candidate.socket.close() }; continue }
            return Lease(candidate.socket, reused = true)
        }
        return acquireFresh()
    }

    // Not `Socket().apply { connect(.. port ..) }`: inside apply, `port` would resolve to Socket.getPort() (0).
    fun acquireFresh(): Lease {
        val socket = Socket()
        socket.tcpNoDelay = true
        try {
            socket.connect(InetSocketAddress("127.0.0.1", localPort), connectTimeoutMs)
        } catch (e: IOException) {
            runCatching { socket.close() }
            throw e
        }
        return Lease(socket, reused = false)
    }

    fun release(lease: Lease) {
        val keep = synchronized(this) { !closed && idle.size < maxIdle && !lease.socket.isClosed }
        if (!keep) { lease.discard(); return }
        synchronized(this) { idle.addLast(Idle(lease.socket, now())) }
    }

    fun idleCount() = synchronized(this) { idle.size }

    fun close() {
        val all = synchronized(this) { closed = true; idle.toList().also { idle.clear() } }
        all.forEach { runCatching { it.socket.close() } }
    }

    /** An idle HTTP socket must have nothing to read: EOF means the server closed it, bytes mean garbage. */
    private fun looksAlive(s: Socket): Boolean = try {
        s.soTimeout = 1
        s.getInputStream().read()
        false
    } catch (_: SocketTimeoutException) {
        s.soTimeout = 0
        true
    } catch (_: IOException) {
        false
    }
}
