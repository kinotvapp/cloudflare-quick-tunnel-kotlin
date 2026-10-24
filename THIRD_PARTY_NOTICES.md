# Third-party notices

## Bundled in this repository

- **Cloudflare edge CA certificates** (`quick-tunnel/src/main/resources/cf-edge-roots.pem`): the three
  Cloudflare-internal CA certificates that sign the argotunnel edge certificate, taken from `cloudflared`'s
  `tlsconfig/cloudflare_ca.go`. Source: <https://github.com/cloudflare/cloudflared>, Apache License 2.0.
- **Protocol layouts**: the Cap'n Proto field offsets and discriminants in `Rpc.kt` and `Proxy.kt` were read from the
  code `cloudflared` and `go-capnp` generate from `tunnelrpc.capnp` and `rpc.capnp`
  (Apache License 2.0 / MIT). The schemas themselves are not copied here.

## Dependencies (not bundled; resolved by Gradle)

| Dependency | License |
|---|---|
| [dnsjava](https://github.com/dnsjava/dnsjava) | BSD-3-Clause |
| [twitter/hpack](https://github.com/twitter/hpack) (HPACK decoder for the HTTP/2 transport) | Apache-2.0 |
| [kotlinx.serialization](https://github.com/Kotlin/kotlinx.serialization) | Apache-2.0 |
| Kotlin standard library | Apache-2.0 |

### No LGPL

Since the QUIC transport was removed there is no copyleft dependency. Earlier versions (up to commit `3b93d99`) depended on
[Kwik](https://github.com/ptrd/kwik) and its TLS stack agent15, both LGPL-3.0; `./gradlew check` runs `verifyNoLgpl`, which
fails if either returns to the runtime classpath. The TLS 1.3 client (`Tls13.kt`, `TlsHandshake.kt`, `TlsVerify.kt`) was written
from RFC 8446 and RFC 8448 without reading Kwik's or agent15's code.
