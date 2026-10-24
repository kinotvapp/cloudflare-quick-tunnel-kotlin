# cloudflare-quick-tunnel-kotlin

Pure Kotlin/JVM client for [Cloudflare quick tunnels](https://try.cloudflare.com/) (`https://<random>.trycloudflare.com`).
It speaks QUIC + Cap'n Proto RPC to Cloudflare's `argotunnel` edge directly: **no `cloudflared` binary, no native
library, no JNI**. It runs on a desktop JVM and on Android.

```kotlin
val tunnel = QuickTunnelManager(localPort = 8080).start()   // blocks until the URL is live
println(tunnel.url)                                          // https://<random>.trycloudflare.com
// ... serve something on 127.0.0.1:8080 ...
tunnel.close()                                               // unregisters from the edge
```

> Unofficial. Not affiliated with or endorsed by Cloudflare. Quick tunnels are meant for development and testing,
> come with no uptime guarantee, and the edge protocol is not a public API: it can change without notice.

## Status

Working end to end: a request to the public URL reaches a server on the device and the response comes back.

| Where | What was verified |
|---|---|
| JDK 17, macOS | Full flow over **both transports**, HA failover, reconnect, 20 MB download and 5 MB upload with identical checksums, WebSocket echo over HTTP/2 |
| **Android 7.0 emulator (API 24, arm64)** | Full flow over QUIC, 30/30 requests answered; mobile data off for 40 s and on again: both connections re-register within 1 s of the network returning. `minSdk 24` with core library desugaring |
| Android 14 emulator (API 34, arm64) | Full flow; switching Wi-Fi off and on: ~4 s and ~2 s outages, both connections re-register on their own; R8-minified release build |
| Samsung S24+ (Android 16) | Full flow with the app in the background (foreground service): tunnel up in 4.6 s, 30/30 requests answered, no reconnects needed |

## Limitations

- **Not done yet: the TCP fallback on Android 7 to 9.** The library itself works on Android 7+ over QUIC; the HTTP/2-over-TCP
  fallback currently uses the platform's TLS, which only speaks 1.3 from Android 10. That is a gap in this implementation, not
  in Android 7: Kwik's own pure-Java TLS 1.3 could carry it (see [Android notes](#android-notes)).
- **If both UDP and TCP to port 7844 are blocked, there is no fallback.** The tunnel needs outbound access to the edge on
  that port: UDP for QUIC, or TCP for the HTTP/2 transport (see [Transports](#transports)). Networks that only allow
  80/443 are out.
- The HTTP/2 transport does not carry raw TCP streams (cloudflared's warp-routing); HTTP and WebSocket work.
- Quick tunnels are anonymous and rate-limited; named tunnels (Cloudflare account + token) are out of scope.
- No UDP/ICMP proxying (`datagram` v2/v3).

Not verified: Android 8 to 13 (only 7.0, 14 and 16 were run; the polyfill and desugaring paths are the same for 8 to 13), a network that really blocks UDP 7844 (the fallback decision is covered by unit tests, and the HTTP/2 transport was verified on its own against the real edge), IPv6-only networks, long runs (hours), doze mode.
138 unit tests run without network access (`./gradlew :quick-tunnel:test`).

## What it does

- `POST /tunnel` against the quick-tunnel API with retries (1 s, 2 s, 4 s on network errors and 5xx).
- Edge discovery through DNS SRV (`_v2-origintunneld._tcp.argotunnel.com`) with a UDP, TCP and DNS-over-TLS
  fallback chain, a one-hour cache, and an IPv4/IPv6 filter.
- QUIC handshake against the edge (ALPN `argotunnel`, SNI `quic.cftunnel.com`, Cloudflare's internal CAs pinned), with an
  automatic fallback to HTTP/2 over TCP when UDP is blocked.
- `registerConnection` over a hand-written Cap'n Proto RPC client, including the stub bootstrap the edge needs to
  consider the tunnel alive. No Cap'n Proto compiler or runtime dependency.
- High availability: 2 connections by default (up to 4) on distinct `conn_index` values, so one dropped connection
  does not interrupt traffic.
- Reconnect with backoff (1, 2, 4, 8, 16, then 30 s) and `replace_existing`; `handle.reconnectNow()` for network changes.
- HTTP/1.1 reverse proxy to `127.0.0.1:<port>`: keep-alive socket pool (30 s idle, 16 max), chunked decoding,
  WebSocket upgrades, raw TCP streams, `502`/`504` when the local server is down.
- Graceful shutdown (`unregisterConnection`), metrics (`streams`, `bytesIn`, `bytesOut`, `reconnects`), typed errors,
  `AutoCloseable`.

## Transports

| | Wire | Needs |
|---|---|---|
| **QUIC** | QUIC + TLS 1.3, ALPN `argotunnel`, SNI `quic.cftunnel.com` | outbound **UDP** 7844 |
| **HTTP/2** | TLS over **TCP** 7844, SNI `h2.cftunnel.com`, then the edge speaks HTTP/2 to us (we are the server on that connection, as in `cloudflared --protocol http2`) | outbound **TCP** 7844 |

`TransportPolicy.AUTO` (the default) tries QUIC on two edges with a 4 s handshake each, then HTTP/2 on up to five. When
that happens `TunnelListener.onTransportFallback` fires, and the next reconnections go straight to HTTP/2 for 10 minutes
before QUIC is tried again, so a blocked network does not cost a timeout on every reconnect. `QUIC_ONLY` and `HTTP2_ONLY`
force one of them. `handle.transports` tells which one each connection is using.

The HTTP/2 transport is a small server written for this library (`Http2.kt`): SETTINGS, HEADERS/CONTINUATION, DATA,
flow control in both directions, PING, RST_STREAM, GOAWAY. HPACK decoding uses `com.twitter:hpack`.

## Usage

```kotlin
val manager = QuickTunnelManager(
    localPort = 8080,
    haConnections = 2,                          // 1..4
    transport = TransportPolicy.AUTO,           // or QUIC_ONLY / HTTP2_ONLY
    ipVersion = IpVersionFilter.AUTO,           // or V4_ONLY / V6_ONLY
    firstConnectTimeoutMs = 30_000,
    maxReconnectAttempts = Int.MAX_VALUE,       // the Rust crate stops after 10; a phone should keep trying
    listener = object : TunnelListener {
        override fun onRegistered(connIndex: Int, location: String) = println("conn $connIndex on $location")
        override fun onLost(connIndex: Int, reason: String) = println("lost $connIndex: $reason")
    },
)
manager.start().use { tunnel -> /* tunnel.url, tunnel.metrics */ }
```

Errors are subclasses of `TunnelException` (`Api`, `ApiBusiness`, `ApiNonJson`, `Discovery`, `QuicDial`, `Register`,
`DuplicateConnection`, ...), each with a `transient` flag.

## Android notes

See [`sample-android`](sample-android) for a working foreground service. What it taught:

- **Keep it in a foreground service.** The process is otherwise killed in the background.
- **Call `handle.reconnectNow()` when the default network changes** (`ConnectivityManager.registerDefaultNetworkCallback`).
  The QUIC sockets are bound to the old interface and would otherwise wait for the idle timeout (15 s).
- **Android 7 to 13 lack `AlgorithmParameters.getInstance("EC")`**, which Kwik's TLS uses for every handshake. The library installs a
  tiny JCA provider with the three NIST curves when the platform does not have it (`EcParametersPolyfill`, checked against the
  JDK's values by a unit test). Without it, QUIC fails on those versions with "Missing support for EC algorithm".
- **The HTTP/2 fallback currently needs Android 10+.** The edge's TCP endpoint only accepts TLS 1.3, and the platform's TLS
  gained it in Android 10. On Android 7 to 9 `AUTO` skips HTTP/2 and QUIC (UDP 7844) is what runs; `HTTP2_ONLY` fails with a
  clear message. Everything else works on Android 7+.
- **Call `reconnectNow()` when the network returns.** Besides closing the connections it wakes reactors sleeping in a reconnect
  backoff, so a phone that was offline for a minute is back in about a second instead of waiting out a 30 s retry.
- **Do not run the handshake on pool threads without fixing the class loader.** Kwik finds its TLS key exchange with
  `ServiceLoader`, which reads the thread's context class loader. On Android, `ForkJoinPool` threads get the system
  loader, which cannot see the APK's `META-INF/services`, and the handshake fails with `Unsupported named group(s)`.
  `dial()` sets the right loader itself; keep that if you refactor.
- **APIs newer than Android's.** The library is compiled with `-Xjdk-release=11`, which rejects Java 12+ calls such as
  `ByteBuffer.get(int, byte[])` (Java 13) that crash older Android versions with `NoSuchMethodError`. Java 9 to 11 APIs
  are not checked: The sample uses `minSdk 24` with core library desugaring (`java.time`) and works on Android 7.0.
- R8 works with the three-line `proguard-rules.pro` in the sample. The whole sample app, tunnel included, is
  about 235 KB as a release APK.

## Repository layout

| Path | |
|---|---|
| `quick-tunnel/` | The library (`io.github.kinotvapp.quicktunnel`) and its tests |
| `sample-jvm/` | Command-line example; `./gradlew :sample-jvm:run --args="8080 chaos"` drops connections on purpose |
| `sample-android/` | Foreground-service app that serves a page and exposes it through a tunnel |
| `docs/protocol.md` | The wire details that cost time to find |

## Building

```
./gradlew :quick-tunnel:test
./gradlew :sample-jvm:installDist
./gradlew :sample-android:assembleDebug     # needs the Android SDK (local.properties: sdk.dir=...)
```

## Credits and licenses

The design follows [`cloudflare-quick-tunnel-rs`](https://github.com/lordmacu/cloudflare-quick-tunnel-rs), the Rust
implementation of the same idea, and the protocol comes from Cloudflare's open-source
[`cloudflared`](https://github.com/cloudflare/cloudflared) (Apache-2.0).

This project is dual-licensed under **MIT OR Apache-2.0** ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).

**Heads up: Kwik and its TLS stack agent15 are LGPL-3.0.** This library only depends on them (it does not copy their
code), which is fine for publishing. If you ship an application that bundles them, for example one Android APK, the
LGPL obligations apply to that distribution. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
