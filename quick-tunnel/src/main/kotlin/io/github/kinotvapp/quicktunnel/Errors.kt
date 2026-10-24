package io.github.kinotvapp.quicktunnel

/** Business error inside a `success = false` API body. */
data class ApiError(val code: Int, val message: String)

/** One variant per failure mode a caller can act on separately. */
sealed class TunnelException(message: String, val transient: Boolean = false, cause: Throwable? = null) : Exception(message, cause) {
    /** The POST /tunnel request itself failed (network, timeout, 5xx). */
    class Api(message: String, cause: Throwable? = null) : TunnelException(message, transient = true, cause = cause)

    class ApiBusiness(val errors: List<ApiError>) : TunnelException("quick-tunnel API returned business errors: $errors")

    /** Usually an HTML page when the API rate limits; the snippet makes the reason readable. */
    class ApiNonJson(val status: Int, val bodySnippet: String) :
        TunnelException("quick-tunnel API responded non-JSON ($status): $bodySnippet", transient = status in 500..599)

    class Discovery(message: String, cause: Throwable? = null) : TunnelException("edge discovery failed: $message", transient = true, cause = cause)

    class EdgeDial(val attempts: Int, val last: String) : TunnelException("edge connect failed after $attempts attempt(s); last: $last", transient = true)

    open class Register(message: String) : TunnelException("RegisterConnection failed: $message")

    /** The edge still holds a registration for this conn_index; retry with replace_existing = true. */
    class DuplicateConnection(message: String) : Register(message)

    class PermanentFailure(val attempts: Int) : TunnelException("connection lost; giving up after $attempts attempts")

    class Shutdown : TunnelException("shutdown requested")

    class Internal(message: String, cause: Throwable? = null) : TunnelException("internal invariant violated: $message", cause = cause)
}

/** Exact text from cloudflared's connection/control.go. If upstream rephrases it, tests fail loudly. */
const val DUPLICATE_CONNECTION_ERROR = "edge already has connection registered for the given connection identifier"
