package io.github.kinotvapp.quicktunnel

import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Interface ids from tunnelrpc.capnp. */
val REGISTRATION_SERVER_ID = 0xf71695ec7fe85497UL.toLong()

class RegistrationDetails(val uuid: UUID, val location: String, val remotelyManaged: Boolean)

/**
 * Hand-rolled two-party Cap'n Proto RPC over the control stream. Only what the edge needs:
 * Bootstrap + Call (registerConnection / unregisterConnection) as client, and a stub bootstrap
 * as server so the edge's liveness probe does not mark the tunnel offline (HTTP 530).
 */
class ControlSession(private val inp: InputStream, private val out: OutputStream, private val onClosed: (Throwable) -> Unit = {}) {
    private val pending = ConcurrentHashMap<Int, CompletableFuture<StructR>>()
    private var nextQuestion = 0

    @Volatile var alive = true

    init {
        thread(isDaemon = true, name = "cfqt-rpc-read") {
            try {
                while (true) dispatch(CapnpMessage.read(inp))
            } catch (e: Exception) {
                alive = false
                pending.values.forEach { it.completeExceptionally(e) }
                onClosed(e)
            }
        }
    }

    private fun send(frame: ByteArray) = synchronized(out) { out.write(frame); out.flush() }

    private fun dispatch(msg: CapnpMessage) {
        val m = msg.root() ?: return
        val body = m.struct(0)
        when (m.u16(0)) {
            8 -> { // edge asks for OUR bootstrap: hand out an empty export
                val q = body!!.u32(0)
                send(CapnpBuilder().apply {
                    val message = root(1, 1); u16(message, 0, 3)
                    val ret = struct(message + 1, 2, 1); u32(ret, 0, q); u16(ret, 6, 0)
                    val payload = struct(ret + 2, 0, 2)
                    capPtr(payload, 0)
                    val cap = structList(payload + 1, 1, 1, 1); u16(cap, 0, 1); u32(cap, 4, 0)
                }.frame())
            }
            2 -> { // call on our stub export: unimplemented
                val q = body!!.u32(0)
                send(CapnpBuilder().apply {
                    val message = root(1, 1); u16(message, 0, 3)
                    val ret = struct(message + 1, 2, 1); u32(ret, 0, q); u16(ret, 6, 1)
                    val ex = struct(ret + 2, 1, 3); text(ex + 1, "unimplemented"); u16(ex, 4, 3)
                }.frame())
            }
            3 -> pending.remove(body!!.u32(0))?.complete(body)
            1 -> onClosed(IllegalStateException("edge aborted RPC: ${body?.struct(0)?.text(0)}"))
            else -> {} // Finish, Release, Resolve, ...: nothing to do
        }
    }

    private fun call(question: Int, target: Int, iface: Long, method: Int, params: (CapnpBuilder, Int) -> Unit): CompletableFuture<StructR> {
        val f = CompletableFuture<StructR>()
        pending[question] = f
        send(CapnpBuilder().apply {
            val message = root(1, 1); u16(message, 0, 2)
            val call = struct(message + 1, 3, 3)
            u32(call, 0, question); u16(call, 4, method); u64(call, 8, iface)
            val t = struct(call + 3, 1, 1); u32(t, 0, target) // MessageTarget.importedCap
            val payload = struct(call + 4, 0, 2)
            params(this, payload) // fills payload.content (ptr 0)
        }.frame())
        return f
    }

    private fun awaitReturn(f: CompletableFuture<StructR>, what: String): StructR {
        val ret = f.get(15, TimeUnit.SECONDS)
        if (ret.u16(6) == 1) throw TunnelException.Register("$what: ${ret.struct(0)?.text(0)}")
        return ret
    }

    /** Bootstrap the remote RegistrationServer; returns its export id. */
    private fun bootstrap(): Int {
        val q = nextQuestion++
        val f = CompletableFuture<StructR>()
        pending[q] = f
        send(CapnpBuilder().apply {
            val message = root(1, 1); u16(message, 0, 8)
            val b = struct(message + 1, 1, 1); u32(b, 0, q)
        }.frame())
        val ret = awaitReturn(f, "bootstrap")
        val desc = ret.struct(0)!!.structList(1).first()
        if (desc.u16(0) != 1) throw TunnelException.Register("bootstrap cap is not senderHosted: ${desc.u16(0)}")
        return desc.u32(4)
    }

    private var exportId = -1

    fun register(accountTag: String, secret: ByteArray, tunnelId: UUID, connIndex: Int, version: String, replaceExisting: Boolean = false): RegistrationDetails {
        exportId = bootstrap()
        val ret = awaitReturn(call(nextQuestion++, exportId, REGISTRATION_SERVER_ID, 0) { b, payload ->
            val p = b.struct(payload, 1, 3) // registerConnection params
            b.u8(p, 0, connIndex)
            val auth = b.struct(p + 1, 0, 2); b.text(auth, accountTag); b.data(auth + 1, secret)
            b.data(p + 2, tunnelId.toBytes())
            val opts = b.struct(p + 3, 1, 2) // ConnectionOptions: replaceExisting bit0, compressionQuality u8@1, numPreviousAttempts u8@2
            b.bit(opts, 0, replaceExisting)
            val client = b.struct(opts + 1, 0, 4)
            b.data(client, UUID.randomUUID().toBytes())
            b.textList(client + 1, listOf("allow_remote_config", "serialized_headers", "support_datagram_v2", "support_quic_eof", "management_logs"))
            b.text(client + 2, version)
            b.text(client + 3, "jvm-" + System.getProperty("os.arch"))
            b.data(opts + 2, ByteArray(0))
        }, "registerConnection")
        // results -> ConnectionResponse { union { error(0) | connectionDetails(1) } }
        val response = ret.struct(0)!!.struct(0)!!.struct(0)!!
        val inner = response.struct(0)
        if (response.u16(0) == 0) {
            val cause = inner?.text(0) ?: "<missing cause>"
            throw if (cause == DUPLICATE_CONNECTION_ERROR) TunnelException.DuplicateConnection(cause) else TunnelException.Register(cause)
        }
        return RegistrationDetails(
            fromBytes(inner!!.data(0)!!),
            inner.text(1) ?: "",
            inner.bit(0),
        )
    }

    fun unregister() {
        if (!alive || exportId < 0) return
        runCatching {
            call(nextQuestion++, exportId, REGISTRATION_SERVER_ID, 1) { _, _ -> }.get(5, TimeUnit.SECONDS)
        }
    }
}

fun UUID.toBytes(): ByteArray = java.nio.ByteBuffer.allocate(16).putLong(mostSignificantBits).putLong(leastSignificantBits).array()
fun fromBytes(b: ByteArray): UUID = java.nio.ByteBuffer.wrap(b).let { UUID(it.long, it.long) }
