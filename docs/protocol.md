# Protocol notes

What was not obvious from `cloudflared`'s source. Layouts were taken from the Go code generated from the schemas.

The library only implements the TCP/HTTP/2 transport now. The QUIC details below (ALPN, `quic.cftunnel.com`, the per-request stream framing) are kept as a reference for the version up to commit `3b93d99`, which used Kwik.

## Handshake

| | |
|---|---|
| Edge list | SRV `_v2-origintunneld._tcp.argotunnel.com`, port 7844 |
| ALPN | QUIC: `argotunnel`. TCP/HTTP/2: none |
| SNI | QUIC: `quic.cftunnel.com`; TCP/HTTP/2: `h2.cftunnel.com`. **Not** the ALPN string, and neither resolves in DNS: connect to the edge IP and keep this as the server name |
| Trust | The three Cloudflare-internal CAs; system roots are not enough |

A wrong SNI looks like a 10 s silence, with no TLS alert.

## Control stream

The first bidirectional stream carries Cap'n Proto RPC with no preamble.

1. Client sends `Bootstrap` (question 0); the edge answers with a capability (`senderHosted`, an export id).
2. Client calls `RegistrationServer.registerConnection` (interface `0xf71695ec7fe85497`, method 0) on that export.
   `unregisterConnection` is method 1.
3. **The edge also sends its own `Bootstrap`.** Answer it with any export. If you do not, registration succeeds but
   public requests get `530` or `502`. Calls the edge makes on that export can be answered with an `unimplemented` exception.

Message discriminants (`Message` union, `u16` at offset 0): `bootstrap` 8, `call` 2, `return` 3, `finish` 4, `release` 6, `abort` 1.

| Struct | Data words | Pointers | Fields |
|---|---|---|---|
| `Message` | 1 | 1 | union tag `u16@0`, body `ptr0` |
| `Bootstrap` | 1 | 1 | `questionId u32@0` |
| `Call` | 3 | 3 | `questionId u32@0`, `methodId u16@4`, `interfaceId u64@8`, target `ptr0`, params `ptr1` |
| `Return` | 2 | 1 | `answerId u32@0`, union tag `u16@6` (0 results, 1 exception), body `ptr0` |
| `Payload` | 0 | 2 | content `ptr0`, capTable `ptr1` |
| `registerConnection` params | 1 | 3 | `connIndex u8@0`, `auth ptr0`, `tunnelId ptr1` (16 bytes), `options ptr2` |
| `TunnelAuth` | 0 | 2 | `accountTag ptr0`, `tunnelSecret ptr1` |
| `ConnectionOptions` | 1 | 2 | `replaceExisting bit0`, `compressionQuality u8@1`, `numPreviousAttempts u8@2`, `client ptr0`, `originLocalIp ptr1` |
| `ClientInfo` | 0 | 4 | `clientId ptr0`, `features ptr1`, `version ptr2`, `arch ptr3` |
| `ConnectionResponse` | 1 | 1 | tag `u16@0` (0 error, 1 details), body `ptr0` |
| `ConnectionDetails` | 1 | 2 | `uuid ptr0`, `locationName ptr1`, `tunnelIsRemotelyManaged bit0` |

Features sent by `cloudflared`: `allow_remote_config`, `serialized_headers`, `support_datagram_v2`, `support_quic_eof`,
`management_logs`. Use `replaceExisting = true` when re-registering a `conn_index` after a loss.

## Request streams

The edge opens one bidirectional stream per HTTP request: `6-byte signature 0A36CD12A13E | "01" | ConnectRequest`.
`ConnectRequest` is `dest ptr0`, `type u16@0` (0 http, 1 websocket, 2 tcp), `metadata ptr1` (list of key/value). HTTP
requests carry `HttpMethod`, `HttpHost` and one `HttpHeader:<Name>` entry per header.

The reply is the same preamble + `ConnectResponse` (`error ptr0`, `metadata ptr1` with `HttpStatus` and
`HttpHeader:<Name>`), followed by the raw body bytes, then the stream is finished.

- The edge does **not** re-chunk: decode `Transfer-Encoding: chunked` yourself and drop that header.
- Requests with `Content-Length` arrive as that many raw bytes. A chunked upload arrives already chunk-framed, with
  `Content-Length` set to the framed size, which is what `cloudflared` forwards too.
- A `HEAD`, `204` or `304` response ends right after the head even when it advertises a `Content-Length`.

## HTTP/2 transport (TCP fallback)

Same port, different wire. Mirrors `connection/http2.go` and `connection/header.go` in `cloudflared`.

- **Connect:** TCP to the edge, TLS **1.3 only** (a 1.2 ClientHello gets `protocol_version`) with SNI `h2.cftunnel.com`, the same pinned CAs, **no ALPN**.
- **Roles are reversed:** after the handshake the edge is the HTTP/2 *client* and we are the *server*. We write nothing until
  the client preface arrives; then we send SETTINGS.
- **Control stream:** the first request has `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream`. Answer `200` and run the
  same Cap'n Proto RPC as on QUIC over its body (request body = edge to us, response body = us to edge).
- **Other `Cf-Cloudflared-Proxy-Connection-Upgrade` values:** `websocket`, and `update-configuration` (answer with JSON; we
  report that remote configuration is unsupported). A request with `Cf-Cloudflared-Proxy-Src` is a warp-routing TCP stream.
- **Requests** are ordinary HTTP/2 requests: `:method`, `:path`, `:authority` plus headers. Hop-by-hop headers do not exist in
  HTTP/2, so for a WebSocket we restore `Connection: Upgrade` and `Upgrade: websocket` before talking HTTP/1.1 to the origin.
  A request without `Content-Length` and without END_STREAM has a body of unknown length: re-chunk it for the origin.
- **Responses:** real `:status` (101 becomes 200) and `content-length`; every other origin header travels in one header,
  `cf-cloudflared-response-headers`, as `base64raw(name):base64raw(value)` pairs joined by `;`. Add
  `cf-cloudflared-response-meta: {"src":"origin"}` (`"cloudflared"` for errors we generate, with a 502).
- **Not needed:** a dynamic table in our HPACK encoder (literals without indexing are valid for any peer table size).

### TLS 1.3 record layer notes (Tls13.kt)

- The handshake is our own state machine (`TlsHandshake.kt`, written from RFC 8446, no I/O): the record layer feeds it complete
  handshake messages and installs the traffic secrets it exposes. Order at the end: the server Finished verifies, the machine
  returns our Finished (send it under the HANDSHAKE keys), and only then are both directions switched to the application keys.
  A message that changes keys (ServerHello, server Finished) must end its record, and handshake messages over 128 KiB are refused.
- What is verified: the chain through the trust manager, then the leaf's subjectAltName against the SNI name (RFC 6125 section
  6.4: a wildcard only as the whole left-most label, one label, never the CN), then CertificateVerify over the section 4.4.3
  content with a scheme we offered that matches the key, then the server Finished in constant time. The name check is not
  optional: Cloudflare's Origin CA issues certificates to any Cloudflare customer for their own domains, so a chain that
  validates says nothing about whose server answered. HelloRetryRequest is handled (new share, cookie echo, `message_hash`
  transcript); a second one, an unoffered cipher or group, an unsolicited extension or a CertificateRequest abort the handshake.
- `X509TrustManager.checkServerTrusted` wants a key-exchange name as `authType` (`ECDHE_ECDSA`, `ECDHE_RSA`), not a key type: with `ECDSA` the JDK throws "Unknown authType" on any chain issued by a CA. A self-signed leaf skips that check, so only a test with a real CA-issued chain (`TlsCaChainTest`) or the real edge shows it.
- Record protection: AES-128-GCM, nonce = write IV xor the 64-bit sequence number, AAD = the 5-byte record header, inner
  plaintext = content + content type (+ optional zero padding). Sequence numbers reset on every key change.
- `KeyUpdate` (type 24): rotate the read keys as soon as it arrives. If `update_requested`, answer **on the next write**, not
  from the reader thread: a reader that waits for the write lock can deadlock against a writer blocked on a full socket while the
  peer is blocked writing to us. RFC 8446 only requires the reply before the next application data.
- The JDK sends `user_canceled` (90) before `close_notify` when it closes; RFC 8446 section 6.1 says to ignore it.
- Request bodies: a request without `Content-Length` and without END_STREAM on HEADERS may still be empty (the edge often sends
  `DATA(END_STREAM)` separately). Wait ~200 ms for a first byte like Go's transport does, and only re-chunk if one arrives.
