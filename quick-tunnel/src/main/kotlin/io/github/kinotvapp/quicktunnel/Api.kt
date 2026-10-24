package io.github.kinotvapp.quicktunnel

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64
import java.util.UUID

const val DEFAULT_SERVICE_URL = "https://api.trycloudflare.com"
const val DEFAULT_USER_AGENT = "cloudflared/2024.12.0" // mimic cloudflared so the edge does not trip a novelty filter
const val DEFAULT_HTTP_TIMEOUT_MS = 15_000
const val MAX_API_RETRIES = 3

/** What the QUIC + RPC dance needs; the same credentials are reused on every connection. */
class QuickTunnel(val id: UUID, val hostname: String, val accountTag: String, val secret: ByteArray) {
    val url get() = if (hostname.startsWith("https://")) hostname else "https://$hostname"
}

/** POST /tunnel. Retries network errors and 5xx (1s, 2s, 4s); never 4xx or business errors. */
fun requestTunnel(
    serviceUrl: String = DEFAULT_SERVICE_URL,
    userAgent: String = DEFAULT_USER_AGENT,
    timeoutMs: Int = DEFAULT_HTTP_TIMEOUT_MS,
    sleep: (Long) -> Unit = Thread::sleep,
): QuickTunnel {
    var backoff = 1_000L
    var last: TunnelException? = null
    for (attempt in 0..MAX_API_RETRIES) {
        try {
            return tryOnce(serviceUrl.trimEnd('/') + "/tunnel", userAgent, timeoutMs)
        } catch (e: TunnelException) {
            if (!e.transient || attempt == MAX_API_RETRIES) throw e
            last = e
            sleep(backoff)
            backoff *= 2
        }
    }
    throw last ?: TunnelException.Internal("request_tunnel: retry loop fell through without an error")
}

private fun tryOnce(url: String, userAgent: String, timeoutMs: Int): QuickTunnel {
    val c = URL(url).openConnection() as HttpURLConnection
    val status: Int
    val body: String
    try {
        c.requestMethod = "POST"
        c.connectTimeout = timeoutMs; c.readTimeout = timeoutMs
        c.setRequestProperty("Content-Type", "application/json")
        c.setRequestProperty("User-Agent", userAgent)
        c.doOutput = true; c.setFixedLengthStreamingMode(0)
        status = c.responseCode
        body = String((if (status in 200..399) c.inputStream else c.errorStream)?.use { it.readBytes() } ?: ByteArray(0))
    } catch (e: java.io.IOException) {
        throw TunnelException.Api("POST /tunnel: $e", e)
    } finally {
        c.disconnect()
    }
    val first = body.firstOrNull { !it.isWhitespace() }
    if (first != '{' && first != '[') throw TunnelException.ApiNonJson(status, body.take(200))
    val root = try { Json.parseToJsonElement(body).jsonObject } catch (e: Exception) { throw TunnelException.Internal("malformed JSON from /tunnel: $e", e) }
    if (root["success"]?.jsonPrimitive?.boolean != true) {
        val errors = (root["errors"] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
            .map { ApiError(it["code"]?.jsonPrimitive?.int ?: 0, it["message"]?.jsonPrimitive?.content ?: "") }
        throw TunnelException.ApiBusiness(errors)
    }
    val r = root["result"]?.jsonObject ?: throw TunnelException.Internal("POST /tunnel returned success=true but no `result` body")
    fun str(k: String) = r[k]?.jsonPrimitive?.content ?: throw TunnelException.Internal("missing '$k' in /tunnel result")
    val id = try { UUID.fromString(str("id")) } catch (e: IllegalArgumentException) { throw TunnelException.Internal("tunnel.id is not a uuid", e) }
    return QuickTunnel(id, str("hostname"), str("account_tag"), Base64.getDecoder().decode(str("secret")))
}

private fun JsonArray?.orEmpty(): List<kotlinx.serialization.json.JsonElement> = this?.toList() ?: emptyList()
