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
| JDK 17, macOS | Full flow, HA failover, reconnect, 20 MB download and 5 MB upload with identical checksums |
| Android 14 emulator (API 34, arm64) | Full flow; switching Wi-Fi off and on: ~4 s and ~2 s outages, both connections re-register on their own; R8-minified release build |
| Samsung S24+ (Android 16) | Full flow with the app in the background (foreground service): tunnel up in 4.6 s, 30/30 requests answered, no reconnects needed |

## Limitations

- **QUIC only, which means outbound UDP to port 7844.** There is no fallback to HTTP/2 over TCP, which `cloudflared`
  uses when UDP is blocked. On a network that blocks that port (some corporate, hotel and captive-portal Wi-Fi, some
  carriers) `start()` fails with `TunnelException.QuicDial` after the handshake timeout, and a running tunnel cannot
  recover until the network allows UDP again. Only DNS discovery has a TCP/DNS-over-TLS fallback, not the tunnel itself.
- Quick tunnels are anonymous and rate-limited; named tunnels (Cloudflare account + token) are out of scope.
- No UDP/ICMP proxying (`datagram` v2/v3); HTTP, WebSocket and raw TCP streams only.

Not verified: Android below API 34 (see [Android notes](#android-notes)), networks that block UDP 7844, IPv6-only networks, long runs (hours), doze mode.
73 unit tests run without network access (`./gradlew :quick-tunnel:test`).

## What it does

- `POST /tunnel` against the quick-tunnel API with retries (1 s, 2 s, 4 s on network errors and 5xx).
- Edge discovery through DNS SRV (`_v2-origintunneld._tcp.argotunnel.com`) with a UDP, TCP and DNS-over-TLS
  fallback chain, a one-hour cache, and an IPv4/IPv6 filter.
- QUIC handshake against the edge (ALPN `argotunnel`, SNI `quic.cftunnel.com`, Cloudflare's internal CAs pinned).
- `registerConnection` over a hand-written Cap'n Proto RPC client, including the stub bootstrap the edge needs to
  consider the tunnel alive. No Cap'n Proto compiler or runtime dependency.
- High availability: 2 connections by default (up to 4) on distinct `conn_index` values, so one dropped connection
  does not interrupt traffic.
- Reconnect with backoff (1, 2, 4, 8, 16, then 30 s) and `replace_existing`; `handle.reconnectNow()` for network changes.
- HTTP/1.1 reverse proxy to `127.0.0.1:<port>`: keep-alive socket pool (30 s idle, 16 max), chunked decoding,
  WebSocket upgrades, raw TCP streams, `502`/`504` when the local server is down.
- Graceful shutdown (`unregisterConnection`), metrics (`streams`, `bytesIn`, `bytesOut`, `reconnects`), typed errors,
  `AutoCloseable`.

## Usage

```kotlin
val manager = QuickTunnelManager(
    localPort = 8080,
    haConnections = 2,                          // 1..4
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
- **Do not run the handshake on pool threads without fixing the class loader.** Kwik finds its TLS key exchange with
  `ServiceLoader`, which reads the thread's context class loader. On Android, `ForkJoinPool` threads get the system
  loader, which cannot see the APK's `META-INF/services`, and the handshake fails with `Unsupported named group(s)`.
  `dial()` sets the right loader itself; keep that if you refactor.
- **APIs newer than Android's.** The library is compiled with `-Xjdk-release=11`, which rejects Java 12+ calls such as
  `ByteBuffer.get(int, byte[])` (Java 13) that crash older Android versions with `NoSuchMethodError`. Java 9 to 11 APIs
  are not checked: `minSdk 26` is what the sample uses; going lower needs core library desugaring and has not been tried.
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
