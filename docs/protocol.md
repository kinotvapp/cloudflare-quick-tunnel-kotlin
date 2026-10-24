# Protocol notes

What was not obvious from `cloudflared`'s source. Layouts were taken from the Go code generated from the schemas.

## Handshake

| | |
|---|---|
| Edge list | SRV `_v2-origintunneld._tcp.argotunnel.com`, port 7844 |
| ALPN | `argotunnel` |
| SNI | `quic.cftunnel.com` (**not** the ALPN string, and it does not resolve in DNS: connect to the edge IP and keep this as the server name. In Kwik: `.host(SNI).proxy(ip)`) |
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
