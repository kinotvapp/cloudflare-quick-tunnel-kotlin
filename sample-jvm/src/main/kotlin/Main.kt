package io.github.kinotvapp.quicktunnel.sample

import io.github.kinotvapp.quicktunnel.*

/** Usage: sample <localPort> [max-requests=N] [max-seconds=S] [chaos] [quic|http2] [purejava]  — chaos drops connection 0 at 25s and every connection at 55s. */
fun main(args: Array<String>) {
    val port = args.firstOrNull()?.toInt() ?: 8080
    val chaos = "chaos" in args
    val policy = when { "http2" in args -> TransportPolicy.HTTP2_ONLY; "quic" in args -> TransportPolicy.QUIC_ONLY; else -> TransportPolicy.AUTO }
    val t0 = System.currentTimeMillis()
    fun log(m: String) = println("[%5.1fs] %s".format((System.currentTimeMillis() - t0) / 1000.0, m))
    val handle = QuickTunnelManager(port, transport = policy,
        maxRequests = args.firstOrNull { it.startsWith("max-requests=") }?.substringAfter('=')?.toLong() ?: 0,
        maxLifetimeMs = (args.firstOrNull { it.startsWith("max-seconds=") }?.substringAfter('=')?.toLong() ?: 0) * 1000, tcpTls = if ("purejava" in args) TcpTls.PURE_JAVA else TcpTls.AUTO, listener = object : TunnelListener {
        override fun onRegistered(connIndex: Int, location: String) = log("registered conn=$connIndex location=$location")
        override fun onTransport(connIndex: Int, transport: Transport) = log("conn=$connIndex transport=$transport")
        override fun onTransportFallback(connIndex: Int, reason: String) = log("QUIC unavailable, using HTTP/2 over TCP ($reason)")
        override fun onLimitReached(limit: TunnelLimit) = log("LIMIT REACHED: $limit, closing")
        override fun onLost(connIndex: Int, reason: String) = log("LOST conn=$connIndex ($reason)")
        override fun onReconnecting(connIndex: Int, attempt: Int, delayMs: Long) = log("reconnecting conn=$connIndex attempt=$attempt in ${delayMs}ms")
        override fun onReconnectFailed(connIndex: Int, attempt: Int, error: TunnelException) = log("reconnect FAILED conn=$connIndex attempt=$attempt: ${error.message}")
    }).start()
    log("PUBLIC URL: ${handle.url}")
    if (chaos) {
        Thread.sleep(25_000); log("chaos: dropping conn 0"); handle.dropConnection(0)
        Thread.sleep(30_000); log("chaos: dropping ALL (network change)"); handle.reconnectNow()
        Thread.sleep(40_000)
    } else Thread.sleep(300_000)
    log("shutting down"); handle.shutdown(); log("metrics: ${handle.metrics}")
}
