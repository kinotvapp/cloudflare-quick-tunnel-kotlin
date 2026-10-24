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
| JDK 17, macOS | Full flow over **both transports**, HA failover, reconnect, 20 MB download and 5 MB upload with identical checksums, WebSocket echo over HTTP/2. The pure-Java TLS with our own handshake also against the real edge: up in 4.6 s, five 20 MB downloads and a 5 MB upload intact |
| **Android 7.0 emulator (API 24, arm64)** | QUIC: full flow, 30/30 requests answered; mobile data off for 40 s and on again, both connections re-register within 1 s of the network returning. **With UDP 7844 dropped by iptables:** `AUTO` falls back to HTTP/2 over TCP with the pure-Java TLS 1.3, tunnel up in 4.7 s, 40/40 requests and 20 in parallel. `minSdk 24` with core library desugaring **Re-run with our own TLS (release + R8, UDP dropped):** up in 6.4 s over HTTP/2, 40/40 requests, 20 in parallel, 150 KB uploads |
| Android 14 emulator (API 34, arm64) | Full flow; switching Wi-Fi off and on: ~4 s and ~2 s outages, both connections re-register on their own; R8-minified release build |
| Samsung S24+ (Android 16) | Full flow with the app in the background (foreground service): tunnel up in 4.6 s, 30/30 requests answered, no reconnects needed |
| Samsung S24+ (Android 16), HTTP/2 only | The **platform-TLS** path on a real device: tunnel up in 5.0 s over HTTP/2 alone, 40/40 requests and 20 in parallel |
| **Android 7.0 emulator limited to 1 GB RAM, 2 cores** (heap growth limit 48 MB) | 3-minute tunnels: a GET every 2 s plus a 150 KB upload every ~16 s, all answered (64 GET + 8 uploads each). **QUIC:** peak RSS 101 MB (mostly shared system pages), own memory (PSS) at most 24 MB, Java heap at most 7 MB, native heap 5 MB, 35 threads, 4 s of CPU. **HTTP/2 + our own TLS (UDP blocked):** PSS at most 22.5 MB, Java heap 5.9 MB, 30 threads, 4 s of CPU (5 s with the previous TLS). Two earlier runs of the HTTP/2 case read 18 and 21 s of CPU while the Mac was busy compiling and could not be reproduced on a quiet machine. No low-memory kills. The host CPU is much faster than a TV box, so read the CPU figure as a floor |
| Limits | `maxRequests` and `maxLifetimeMs` close the tunnel against the real edge (the next request gets 530), and are covered by unit tests, including closing from inside the callback |

## Limitations

- **If both UDP and TCP to port 7844 are blocked, there is no fallback.** The tunnel needs outbound access to the edge on
  that port: UDP for QUIC, or TCP for the HTTP/2 transport (see [Transports](#transports)). Networks that only allow
  80/443 are out.
- The HTTP/2 transport does not carry raw TCP streams (cloudflared's warp-routing); HTTP and WebSocket work.
- Quick tunnels are anonymous and rate-limited; named tunnels (Cloudflare account + token) are out of scope.
- No UDP/ICMP proxying (`datagram` v2/v3).

Not verified: Android 8 to 13 and real devices below Android 14 (only 7.0 (emulator), 14 (emulator) and 16 (device) were run; the platform-TLS path ran on a JDK and on Android 16 only; the polyfill and desugaring paths are the same for 8 to 13), a network that *silently drops* UDP 7844 (the tests used a sandbox and iptables, which refuse immediately; a silent drop takes the 4 s handshake timeout per QUIC edge instead, which unit tests cover), IPv6-only networks, long runs (hours), doze mode.
239 unit tests run without network access (`./gradlew :quick-tunnel:test`).

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

**TLS for the TCP transport.** The edge's TCP endpoint only accepts TLS 1.3, which the platform gained in Android 10. So
`TcpTls.AUTO` uses the platform's TLS where it speaks 1.3 (Android 10+, any current JDK) and otherwise a pure-Java TLS 1.3
client of our own (`Tls13.kt`, `TlsHandshake.kt`, `TlsVerify.kt`): a handshake state machine written from RFC 8446 and checked
against the RFC 8448 traces, plus a TLS record layer (AES-128-GCM, key updates, close_notify). It verifies the certificate chain
through the trust manager, **and** the server name (the Cloudflare Origin CA issues certificates to any customer, so a valid
chain alone proves nothing), the CertificateVerify signature and the Finished MAC. It is checked against the JDK's TLS server and
against the real edge, and it is what makes the TCP fallback work on Android 7 to 9. `PURE_JAVA` forces it anywhere. It does
not use Kwik or agent15.

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
    maxLifetimeMs = 180_000,                    // close the tunnel 3 minutes after start() returns (0 = no limit)
    maxRequests = 1,                            // ...or once this many requests have been served (0 = no limit)
    listener = object : TunnelListener {
        override fun onRegistered(connIndex: Int, location: String) = println("conn $connIndex on $location")
        override fun onLost(connIndex: Int, reason: String) = println("lost $connIndex: $reason")
        override fun onLimitReached(limit: TunnelLimit) = println("closing: $limit")   // LIFETIME or REQUESTS
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
- **Android 7 to 13 lack `AlgorithmParameters.getInstance("EC")`**, which Kwik's TLS (and our own TLS, for the curve parameters) uses for every handshake. The library installs a
  tiny JCA provider with the three NIST curves when the platform does not have it (`EcParametersPolyfill`, checked against the
  JDK's values by a unit test). Without it, QUIC fails on those versions with "Missing support for EC algorithm".
- **The TCP fallback runs on Android 7+ too.** The platform's TLS has no 1.3 before Android 10, and the edge's TCP endpoint
  requires it, so on those versions the library uses its own pure-Java TLS 1.3 (see [Transports](#transports)).
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
  about 350 KB as a release APK (R8, unsigned), which includes the HTTP/2 transport and the pure-Java TLS.

## Network destinations

Everything the library talks to, for allowlists and firewalls:

| What | Where | Port |
|---|---|---|
| Ask for a tunnel | `https://api.trycloudflare.com/tunnel` (system trust store) | TCP 443 |
| Edge discovery (SRV) and edge addresses | DNS queries for `_v2-origintunneld._tcp.argotunnel.com` and its targets (`regionN.v2.argotunnel.com`), sent **by the library itself** to public resolvers because Android has no SRV API: `1.1.1.1` (UDP 53, then TCP 53), `1.0.0.1` (UDP 53), `8.8.8.8` (UDP 53), and finally DNS-over-TLS to `1.1.1.1` (TCP 853, name `cloudflare-dns.com`). The first resolver that answers wins; normally only `1.1.1.1` over UDP 53 is used. | UDP/TCP 53, TCP 853 |
| The tunnel itself | Cloudflare edge addresses returned by that lookup (seen so far in `198.41.192.0/24`, `198.41.200.0/24`, `2606:4700:a0::/48` and `2606:4700:a8::/48`) | **UDP 7844** (QUIC) or **TCP 7844** (HTTP/2) |
| Names used only as TLS server names, never resolved | `quic.cftunnel.com`, `h2.cftunnel.com` | - |
| What visitors use | `https://<random>.trycloudflare.com`: this is the *other* device's traffic, not the app's | - |

`QUIC_ONLY` needs UDP 7844 only, `HTTP2_ONLY` TCP 7844 only. The default `AUTO` may use both.

## Requirements and size

- **minSdk 24.** Below Android 8 (API 26) the app needs **core library desugaring** (`desugar_jdk_libs`, AGP 7.4+): both Kwik and
  dnsjava use `java.time`, which Android 7 lacks. Without it the tunnel fails on Android 7 with
  `NoClassDefFoundError: java.time.Duration` (checked on the API 24 emulator; the failure is in the DNS step, before any Kwik
  code, so removing Kwik alone would not remove the need). Android 8+ needs nothing extra.
- **Size added to a release APK after R8, dex only (there is no native code).** Measured on the sample app against an empty app
  (1 KB of dex); the figures include the sample's own few KB:

  | | `classes.dex` | sample release APK |
  |---|---|---|
  | With QUIC (Kwik + agent15 in the build), no desugaring | 523 KB | 268 KB |
  | With QUIC, with desugaring (needed below Android 8) | 720 KB | 357 KB |
  | **HTTP/2 only, no Kwik/agent15**, no desugaring | **340 KB** | **178 KB** |
  | **HTTP/2 only, no Kwik/agent15**, with desugaring | **529 KB** | **264 KB** |

  The "HTTP/2 only" rows come from a scratch build with the QUIC code and Kwik removed; that configuration is **not shipped as a
  build option yet** (see [Credits and licenses](#credits-and-licenses)). Desugaring adds ~190 KB of `j$.*` classes, and here it is
  mostly dnsjava's `java.time` use that needs it.
- R8 rules: `sample-android/proguard-rules.pro` (`-dontwarn` for classes dnsjava and Kotlin serialization reference but never use).

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

**Heads up: Kwik and its TLS stack agent15 are LGPL-3.0.** They are used by the QUIC transport only. This library only depends on
them (it does not copy their code), which is fine for publishing. If you ship an application that bundles them, for example one
Android APK, the LGPL obligations apply to that distribution. The TCP/HTTP/2 transport, including its TLS 1.3, does not use
them, so a build without QUIC has no LGPL code; that configuration is not offered as a build option yet. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
