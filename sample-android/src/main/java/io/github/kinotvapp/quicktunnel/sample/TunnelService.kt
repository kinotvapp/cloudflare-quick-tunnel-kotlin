package io.github.kinotvapp.quicktunnel.sample

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.util.Log
import io.github.kinotvapp.quicktunnel.QuickTunnelHandle
import io.github.kinotvapp.quicktunnel.QuickTunnelManager
import io.github.kinotvapp.quicktunnel.platformTlsSupports13
import io.github.kinotvapp.quicktunnel.TunnelListener
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

private const val TAG = "QT"
private const val PORT = 8080

class TunnelService : Service() {
    @Volatile private var handle: QuickTunnelHandle? = null
    private var server: ServerSocket? = null
    private var firstCallback = true
    private val netCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "network available: $network (first=$firstCallback)")
            if (firstCallback) { firstCallback = false; return }
            handle?.reconnectNow()
        }
        override fun onLost(network: Network) { Log.i(TAG, "network lost: $network") }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") { stop(); return START_NOT_STICKY }
        if (handle != null || server != null) return START_STICKY
        Log.i(TAG, "platform TLS speaks 1.3: ${platformTlsSupports13()}")
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("qt", "Tunnel", NotificationManager.IMPORTANCE_LOW))
            Notification.Builder(this, "qt")
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        startForeground(1, builder.setContentTitle("Tunnel running").setSmallIcon(android.R.drawable.stat_notify_sync).build())
        getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(netCallback)
        startLocalServer()
        thread(name = "qt-start") {
            try {
                val t0 = System.currentTimeMillis()
                handle = QuickTunnelManager(PORT, listener = object : TunnelListener {
                    override fun onRegistered(connIndex: Int, location: String) { Log.i(TAG, "registered conn=$connIndex location=$location") }
                    override fun onLimitReached(limit: io.github.kinotvapp.quicktunnel.TunnelLimit) { Log.i(TAG, "limit reached: $limit") }
                    override fun onLost(connIndex: Int, reason: String) { Log.w(TAG, "LOST conn=$connIndex ($reason)") }
                    override fun onReconnecting(connIndex: Int, attempt: Int, delayMs: Long) { Log.i(TAG, "reconnecting conn=$connIndex attempt=$attempt in ${delayMs}ms") }
                    override fun onReconnectFailed(connIndex: Int, attempt: Int, error: io.github.kinotvapp.quicktunnel.TunnelException) { Log.w(TAG, "reconnect FAILED conn=$connIndex attempt=$attempt: ${error.message}") }
                }).start()
                Log.i(TAG, "PUBLIC URL: ${handle!!.url} (up in ${System.currentTimeMillis() - t0} ms)")
            } catch (e: Throwable) {
                Log.e(TAG, "start failed", e)
            }
        }
        return START_STICKY
    }

    private fun startLocalServer() {
        val s = ServerSocket(PORT, 50, InetAddress.getByName("127.0.0.1")); server = s
        thread(isDaemon = true, name = "qt-origin") {
            while (!s.isClosed) {
                val c = try { s.accept() } catch (_: Exception) { return@thread }
                thread(isDaemon = true) {
                    c.use {
                        val r = it.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                        val first = r.readLine() ?: return@thread
                        var length = 0; var chunked = false
                        while (true) {
                            val h = r.readLine().orEmpty()
                            if (h.isEmpty()) break
                            if (h.startsWith("content-length:", true)) length = h.substringAfter(':').trim().toIntOrNull() ?: 0
                            if (h.startsWith("transfer-encoding:", true) && h.contains("chunked", true)) chunked = true
                        }
                        // Read the whole request body before answering: closing a socket with unread data resets it, and the
                        // proxy would then report a 502 for a perfectly good upload.
                        if (chunked) {
                            while (true) { val n = r.readLine()?.substringBefore(';')?.trim()?.toIntOrNull(16) ?: break; if (n == 0) { r.readLine(); break }; var left = n; while (left > 0) { val k = r.skip(left.toLong()).toInt(); if (k <= 0) break; left -= k }; r.readLine() }
                        } else { var left = length.toLong(); while (left > 0) { val k = r.skip(left); if (k <= 0) break; left -= k } }
                        val body = "hello from ART ${android.os.Build.MODEL} api${android.os.Build.VERSION.SDK_INT} $first\n".toByteArray()
                        it.getOutputStream().apply { write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray()); write(body); flush() }
                    }
                }
            }
        }
    }

    private fun stop() {
        thread { handle?.shutdown(); Log.i(TAG, "shutdown done metrics=${handle?.metrics}"); handle = null }
        runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(netCallback) }
        server?.close(); server = null
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }

    override fun onDestroy() { Log.i(TAG, "service destroyed"); super.onDestroy() }
}
