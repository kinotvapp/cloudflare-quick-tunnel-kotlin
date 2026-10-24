# cloudflare-quick-tunnel-kotlin

Pure Kotlin/JVM client for [Cloudflare quick tunnels](https://try.cloudflare.com/) (`https://<random>.trycloudflare.com`).
It speaks Cap'n Proto RPC and HTTP/2 over TLS 1.3 (TCP port 7844) to Cloudflare's `argotunnel` edge directly: **no
`cloudflared` binary, no native library, no JNI, and no LGPL dependency**. It runs on a desktop JVM and on Android 7+.

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
| JDK 17, macOS | Full flow against the real edge with the platform TLS: up in 4.6 s, 20 parallel downloads of 300 KB with identical checksums. Earlier builds also: 20 MB downloads and a 5 MB upload intact with our own TLS, HA failover, reconnect, WebSocket echo |
| **Android 7.0 emulator (API 24, arm64, 1 GB RAM)** | Release build with R8, our own pure-Java TLS 1.3 (the platform has none): tunnel up in 4.3 to 4.9 s, 40/40 GET and 8/8 uploads of 150 KB answered, then again 30/30 and 6/6 with the EC polyfill removed. Own memory (PSS) 19 MB right after the run |
| Earlier builds, before the QUIC code was removed (HTTP/2 path unchanged) | Android 7.0 3-minute runs with a GET every 2 s and a 150 KB upload every ~16 s, all answered, PSS at most 22.5 MB, 4 s of CPU; mobile data off for 40 s and on again, both connections re-register within 1 s; Android 14 emulator Wi-Fi off/on; Samsung S24+ (Android 16) in the background as a foreground service and with the platform TLS, 40/40 requests and 20 in parallel |
| Limits | `maxRequests` and `maxLifetimeMs` close the tunnel against the real edge (the next request gets 530), and are covered by unit tests, including closing from inside the callback |

## Limitations

- **The tunnel needs outbound TCP to port 7844.** Networks that only allow 80/443 are out. There is no QUIC (UDP) transport
  any more: it needed Kwik, which is LGPL-3.0 (see [Credits and licenses](#credits-and-licenses)); the last version that has it
  is commit `3b93d99`.
- The transport does not carry raw TCP streams (cloudflared's warp-routing); HTTP and WebSocket work.
- Quick tunnels are anonymous and rate-limited; named tunnels (Cloudflare account + token) are out of scope.
- No UDP/ICMP proxying (`datagram` v2/v3).

Not verified: Android 8 to 13 and real devices below Android 14 (only 7.0 (emulator), 14 (emulator, earlier build) and 16 (device, earlier build) were run; the platform-TLS path ran on a JDK and on Android 16 only), IPv6-only networks, long runs (hours), doze mode.
226 unit tests run without network access (`./gradlew :quick-tunnel:test`). `./gradlew check` also fails if a Kwik or agent15 artifact ever reaches the runtime classpath (`verifyNoLgpl`).

## What it does

- `POST /tunnel` against the quick-tunnel API with retries (1 s, 2 s, 4 s on network errors and 5xx).
- Edge discovery through DNS SRV (`_v2-origintunneld._tcp.argotunnel.com`) with a UDP, TCP and DNS-over-TLS
  fallback chain, a one-hour cache, and an IPv4/IPv6 filter.
- TLS 1.3 over TCP to the edge (SNI `h2.cftunnel.com`, Cloudflare's internal CAs pinned), then HTTP/2 with the edge as the client.
- `registerConnection` over a hand-written Cap'n Proto RPC client, including the stub bootstrap the edge needs to
  consider the tunnel alive. No Cap'n Proto compiler or runtime dependency.
- High availability: 2 connections by default (up to 4) on distinct `conn_index` values, so one dropped connection
  does not interrupt traffic.
- Reconnect with backoff (1, 2, 4, 8, 16, then 30 s) and `replace_existing`; `handle.reconnectNow()` for network changes.
- HTTP/1.1 reverse proxy to `127.0.0.1:<port>`: keep-alive socket pool (30 s idle, 16 max), chunked decoding,
  WebSocket upgrades, `502`/`504` when the local server is down.
- Graceful shutdown (`unregisterConnection`), metrics (`streams`, `bytesIn`, `bytesOut`, `reconnects`), typed errors,
  `AutoCloseable`.

## Transport

TLS over **TCP** 7844, SNI `h2.cftunnel.com`, no ALPN; then the edge speaks HTTP/2 to us (we are the server on that
connection, as in `cloudflared --protocol http2`). The first stream the edge opens is the control stream: we answer 200 and run
the Cap'n Proto RPC over its body.

**TLS.** The edge's TCP endpoint only accepts TLS 1.3, which the platform gained in Android 10. So
`TcpTls.AUTO` uses the platform's TLS where it speaks 1.3 (Android 10+, any current JDK) and otherwise a pure-Java TLS 1.3
client of our own (`Tls13.kt`, `TlsHandshake.kt`, `TlsVerify.kt`): a handshake state machine written from RFC 8446 and checked
against the RFC 8448 traces, plus a TLS record layer (AES-128-GCM, key updates, close_notify). It verifies the certificate chain
through the trust manager, **and** the server name (the Cloudflare Origin CA issues certificates to any customer, so a valid
chain alone proves nothing), the CertificateVerify signature and the Finished MAC. It is checked against the JDK's TLS server and
against the real edge, and it is what makes the TCP fallback work on Android 7 to 9. `PURE_JAVA` forces it anywhere.

The HTTP/2 transport is a small server written for this library (`Http2.kt`): SETTINGS, HEADERS/CONTINUATION, DATA,
flow control in both directions, PING, RST_STREAM, GOAWAY. HPACK decoding uses `com.twitter:hpack`.

## Usage

```kotlin
val manager = QuickTunnelManager(
    localPort = 8080,
    haConnections = 2,                          // 1..4
    tcpTls = TcpTls.AUTO,                       // or PLATFORM / PURE_JAVA
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

Errors are subclasses of `TunnelException` (`Api`, `ApiBusiness`, `ApiNonJson`, `Discovery`, `EdgeDial`, `Register`,
`DuplicateConnection`, ...), each with a `transient` flag.

## Android notes

See [`sample-android`](sample-android) for a working foreground service. What it taught:

- **Keep it in a foreground service.** The process is otherwise killed in the background.
- **Call `handle.reconnectNow()` when the default network changes** (`ConnectivityManager.registerDefaultNetworkCallback`).
  The TCP sockets are bound to the old interface and would otherwise wait for the OS to notice the dead connection.
- **Android 7 to 9 have no TLS 1.3**, and the edge's TCP endpoint requires it, so there the library uses its own pure-Java TLS 1.3 (see [Transport](#transport)). It needs no JCA provider tricks: only `KeyPairGenerator`, `KeyFactory`, `Signature`, `Cipher` and `Mac`, all present since Android 7.
- **Call `reconnectNow()` when the network returns.** Besides closing the connections it wakes reactors sleeping in a reconnect
  backoff, so a phone that was offline for a minute is back in about a second instead of waiting out a 30 s retry.
- **APIs newer than Android's.** The library is compiled with `-Xjdk-release=1.8`, which rejects Java 9+ calls such as
  `ByteBuffer.get(int, byte[])` (Java 13) that crash older Android versions with `NoSuchMethodError`. The sample uses `minSdk 24`
  with core library desugaring (`java.time`) and works on Android 7.0.
- R8 works with the three-line `proguard-rules.pro` in the sample. The whole sample app, tunnel included, is
  about 260 KB as a release APK (R8, unsigned, with desugaring), which includes the pure-Java TLS.

## Network destinations

Everything the library talks to, for allowlists and firewalls:

| What | Where | Port |
|---|---|---|
| Ask for a tunnel | `https://api.trycloudflare.com/tunnel` (system trust store) | TCP 443 |
| Edge discovery (SRV) and edge addresses | DNS queries for `_v2-origintunneld._tcp.argotunnel.com` and its targets (`regionN.v2.argotunnel.com`), sent **by the library itself** to public resolvers because Android has no SRV API: `1.1.1.1` (UDP 53, then TCP 53), `1.0.0.1` (UDP 53), `8.8.8.8` (UDP 53), and finally DNS-over-TLS to `1.1.1.1` (TCP 853, name `cloudflare-dns.com`). The first resolver that answers wins; normally only `1.1.1.1` over UDP 53 is used. | UDP/TCP 53, TCP 853 |
| The tunnel itself | Cloudflare edge addresses returned by that lookup (seen so far in `198.41.192.0/24`, `198.41.200.0/24`, `2606:4700:a0::/48` and `2606:4700:a8::/48`) | **TCP 7844** |
| Names used only as TLS server names, never resolved | `h2.cftunnel.com` | - |
| What visitors use | `https://<random>.trycloudflare.com`: this is the *other* device's traffic, not the app's | - |

## Requirements and size

- **minSdk 24.** Below Android 8 (API 26) the app needs **core library desugaring** (`desugar_jdk_libs`, AGP 7.4+): dnsjava
  uses `java.time`, which Android 7 lacks. Without it the tunnel fails on Android 7 with
  `NoClassDefFoundError: java.time.Duration` (in the DNS step). Android 8+ needs nothing extra.
- **Size added to a release APK after R8, dex only (there is no native code).** Measured on the sample app, which adds
  its own few KB (`./gradlew :sample-android:assembleRelease`, `-PnoDesugar` for the first row):

  | | all `classes*.dex` | sample release APK |
  |---|---|---|
  | No desugaring (Android 8+) | **333 KB** | **175 KB** |
  | With desugaring (needed below Android 8) | **523 KB** | **261 KB** |

  For comparison, the last build that had QUIC (Kwik + agent15) measured 523 KB / 720 KB of dex. Desugaring adds ~190 KB of
  `j$.*` classes, and it is dnsjava's `java.time` use that needs it.
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

**No LGPL code.** This library has no copyleft dependency: dnsjava (BSD-3-Clause), `com.twitter:hpack`, kotlinx.serialization and
the Kotlin standard library (Apache-2.0). The TLS 1.3 client and the HTTP/2 server are our own code. A QUIC transport existed
until commit `3b93d99`; it needed Kwik and its TLS stack agent15 (LGPL-3.0), and was removed so that apps can bundle this
library without LGPL obligations. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
