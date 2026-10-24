package io.github.kinotvapp.quicktunnel.sample

import io.github.kinotvapp.quicktunnel.*

/** Usage: cli <localPort> [chaos]  — chaos drops connection 0 at 25s and every connection at 55s. */
fun main(args: Array<String>) {
    val port = args.firstOrNull()?.toInt() ?: 8080
    val chaos = args.getOrNull(1) == "chaos"
    val t0 = System.currentTimeMillis()
    fun log(m: String) = println("[%5.1fs] %s".format((System.currentTimeMillis() - t0) / 1000.0, m))
    val handle = QuickTunnelManager(port, listener = object : TunnelListener {
        override fun onRegistered(connIndex: Int, location: String) = log("registered conn=$connIndex location=$location")
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
