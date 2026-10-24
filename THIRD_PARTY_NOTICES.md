# Third-party notices

## Bundled in this repository

- **Cloudflare edge CA certificates** (`quick-tunnel/src/main/resources/cf-edge-roots.pem`): the three
  Cloudflare-internal CA certificates that sign the argotunnel edge certificate, taken from `cloudflared`'s
  `tlsconfig/cloudflare_ca.go`. Source: <https://github.com/cloudflare/cloudflared>, Apache License 2.0.
- **Protocol layouts**: the Cap'n Proto field offsets and discriminants in `Rpc.kt` and `Proxy.kt` were read from the
  code `cloudflared` and `go-capnp` generate from `tunnelrpc.capnp`, `quic_metadata_protocol.capnp` and `rpc.capnp`
  (Apache License 2.0 / MIT). The schemas themselves are not copied here.

## Dependencies (not bundled; resolved by Gradle)

| Dependency | License |
|---|---|
| [Kwik](https://github.com/ptrd/kwik) `tech.kwik:kwik` | **LGPL-3.0** |
| [agent15](https://github.com/ptrd/kwik) `tech.kwik:agent15` (Kwik's TLS 1.3) | **LGPL-3.0** |
| [dnsjava](https://github.com/dnsjava/dnsjava) | BSD-3-Clause |
| [kotlinx.serialization](https://github.com/Kotlin/kotlinx.serialization) | Apache-2.0 |
| Kotlin standard library | Apache-2.0 |

### About the LGPL dependencies

Publishing and using this library as a Maven/Gradle dependency does not copy Kwik or agent15 into this repository.
If you distribute an application that includes them (an Android APK merges every dependency into its dex files),
the LGPL-3.0 applies to that distribution: provide the license text, say that the application uses Kwik, and let
users replace or relink the LGPL libraries, for example by publishing the application's object files or build
inputs. This is general information, not legal advice.
