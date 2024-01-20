# QUIC

TLSPROXY supports the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol
and [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3), both backed by the
[quic-go package](https://pkg.go.dev/github.com/quic-go/quic-go).

QUIC is enabled by default in released binaries since v0.6.0.

## Enable QUIC connections

Set `enableQUIC: true` (default) in the top level configuration. TLSPROXY will listen to
the same address as `TLSAddr`, but on UDP instead of TCP.

QUIC uses the same TLS credentials as usual.

TLS client authentication, IP address restrictions, user authentication (SSO) all
work the same way as with regular TLS connections over TCP.

Incoming QUIC connections can be used with all tlsproxy modes, except `tlspassthrough`.

TLSPROXY communicates with `mode: QUIC` backends using QUIC. All streams are
forwarded to and from these backends.

When forwarding QUIC connections to `mode: TCP` or `mode: TLS` backends, each
incoming QUIC stream is treated like a separate TLS connection.

When forwarding QUIC connections to `mode: HTTPS` backends, the incoming HTTP
requests are proxied to the backend according to the value of `backendProto`. If the value is `h3`, the requests are proxied using HTTP/3. If the value
is `h2`, the requests are proxied using HTTP/2 over TCP. Otherwise, the requests
are proxied using HTTP/1.1.

Note that QUIC requires the use of ALPN. So, `alpnProtos: ` must be set to the desired
protocols, e.g. `alpnProtos: [h3, h2, http/1.1]`

