# TLSPROXY Release Notes

## v0.7.0-beta1

* Add `hwBacked` option. When enabled, hardware-backed cryptographic keys are used to:
  * encrypt local data (the data cannot be used or recovered on a different device),
  * sign authentication tokens,
  * sign the PKI certificates, OCSP responses, and CRLs.
* Add `--quiet` flag. When set (or the `TLSPROXY_QUIET` env variable is `true`), logging is turned off after tlsproxy starts.
* Update go dependencies:
  * upgraded github.com/quic-go/quic-go v0.41.0 => v0.42.0

## v0.6.4

* Update go: 1.22.1
* Update go dependencies

## v0.6.3

* Reduce lock contention in passkey manager.

## v0.6.2

* Update go: 1.22.0
* Log HTTP protocol upgrades.
* Fix bug that prevented PKI admins from revoking certificates.
* Improve heap & lock profiling.
* Reduce lock contention.

## v0.6.1

* Fix WebSocket connections when `backendProto` is set to something other than `http/1.1`.

## v0.6.0

* Starting with v0.6.0, tlsproxy is built with QUIC & HTTP/3 support by default. Binaries without QUIC can still be built with `-tags noquic`.
* Add support for QUIC datagrams.

## v0.5.2

* Report outbound connections on the metrics page.
* Improve how http3 connections are handled.
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20231229205709-960ae82b1e42 => v0.0.0-20240117000934-35fc243c5815
  * upgraded github.com/onsi/ginkgo/v2 v2.13.2 => v2.14.0
  * upgraded github.com/quic-go/quic-go v0.40.1 => v0.41.0
  * upgraded golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc => v0.0.0-20240112132812-db7319d0e0e3
  * upgraded golang.org/x/tools v0.16.1 => v0.17.0

## v0.5.1

* Prevent backend connections from being re-used by other clients when PROXY protocol is enabled.

## v0.5.0

* Add support for the PROXY protocol for incoming connections. See the `AcceptProxyHeaderFrom` config option.
* Fix bug with the handling of the PROXY protocol header with TLS backends. The header was sent after the TLS handshake instead of before.
* Fix bug that prevented logins with passkeys on non default ports when ForceReAuth is set. (introduced in v0.4.4)
* Log aborted ReverseProxy requests more gracefully.
* Update go: 1.21.6
* Update go dependencies:
  * upgraded github.com/beevik/etree v1.2.0 => v1.3.0
  * upgraded github.com/google/pprof v0.0.0-20231212022811-ec68065c825e => v0.0.0-20231229205709-960ae82b1e42
  * upgraded golang.org/x/crypto v0.17.0 => v0.18.0
  * upgraded golang.org/x/exp v0.0.0-20231226003508-02704c960a9b => v0.0.0-20240103183307-be819d1f06fc
  * upgraded golang.org/x/net v0.19.0 => v0.20.0
  * upgraded golang.org/x/sys v0.15.0 => v0.16.0

## v0.4.4

* Improve user experience with the passkey login screen.
* Fix small accounting bug in ingress metrics.
* Apply the forward rate limit to http requests. Before, the rate limit was only applied to incoming connections.

## v0.4.3

* Add support for the OIDC `hd` param (https://developers.google.com/identity/openid-connect/openid-connect#hd-param).
* Return the proper TLS error when a QUIC client requests an unknown server name and/or alpn protocol.
* Return the proper TLS error when a client certificate is revoked.
* Refactor / improve the handling of QUIC connections.

## v0.4.2

* Minor changes to the metrics page: combine runtime and memory profile, add config.
* Remove the /config endpoint.
* Refactor HTTP handlers. No functional change.

## v0.4.1

* Add a confirmation page before redirecting to the remote identity provider's OIDC or SAML login page.
* Add a nonce cookie to the OIDC login flow.
* Convert the metrics page to HTML.

## v0.4.0

* This version changes these config options:
  * `enableQUIC` now defaults to `true` if the binary is compiled with QUIC support, e.g. `+quic` releases.
  * `alpnProtos` now includes `h3` by default when QUIC is enabled and mode is one of `HTTP`, `HTTPS`, `QUIC`, `LOCAL`, or `CONSOLE`.
  * `revokeUnusedCertificates` now defaults to `true`, and revocation is only done at the time the proxy starts.

## v0.3.5

* Add missing lock in revoke.go
* Fix bug that could close legitimate connections after a config change.
* Fixed some flaky tests.
* Add backendProto and buildinfo to metrics page.

## v0.3.4

* Add an option to automatically revoke unused _Let's encrypt_ certificates.
* Add a flag to revoke all cached certificates. This is useful when a server is decommissioned or compromised.
* IDN fixes and tests

## v0.3.3

* Implement OCSP stapling.
* Verify the status of client and server certificates when OCSP servers are specified.
* Fix bug that prevented the PKI WASM client from loading on chrome 119.
* Handle Internationalized Domain Names correctly.
* Add an option to refresh the identity used with passkeys (`refreshInterval`).

## v0.3.2

* Use the certificate provided by _Let's Encrypt_ to authenticate with backends when backends require client authentication.
* go: upgraded github.com/quic-go/quic-go v0.40.0 => v0.40.1 (CVE-2023-49295)

## v0.3.1

* Decouple frontend and backend protocols in `mode: http` and `mode: https`. The ALPN protocols that TLSPROXY accepts are specified in `alpnProtos: [...]`, and the protocol to use with the request to the backend is specified with `backendProto: ...`, which defaults to `http/1.1`. The previous behavior was to use the same protocol that the client used. It is still possible to do that by setting `backendProto` explicitly to an empty string.
* Fix QUIC stream direction in metrics.
* Fix persistent config reload every 30 sec in some conditions.

## v0.3.0

* Add support for the PROXY protocol defined by HAProxy. https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt
* Add QUIC and HTTP/3 support. See [docs/QUIC.md](https://github.com/c2FmZQ/tlsproxy/blob/main/docs/QUIC.md).
* Increase timeouts for proxied HTTP requests to 24 hours for large uploads or downloads.
* Update to go 1.21.5

## v0.2.0

* Add support for the HTTP/2 protocol in reverse proxy mode. This only works when the backend actually supports HTTP/2. So, it is not enabled by default. To enable it, set `alpnProtos: [h2, http/1.1]` on the backend explicitly.
* Add support for routing HTTP requests based on path. By default, all requests go to the same backend servers. When `pathOverrides` is set, some paths can be routed to other servers.

## v0.1.1

* Allow multiple backends with the same server name but different ALPN protos, e.g. one backend could have foo.example.com with the default ALPN protos, and another backend could have foo.example.com with `alpnProtos: [imap]`. If ALPN is not used by the client, the first backend with a matching server name will be used.

## v0.1.0

Let's call this the first _stable_ development release. We'll try to keep decent release notes going forward.

TLSPROXY is primarily a [TLS termination proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy) that uses letsencrypt to provide TLS encryption for any number of TCP or HTTP servers, and any number of server names concurrently on the same port.

Its functionality is similar to an [stunnel](https://www.stunnel.org/) server, but without the need to configure and run [certbot](https://certbot.eff.org/) separately.

TLSPROXY can also be used as a [Reverse Proxy](https://en.wikipedia.org/wiki/Reverse_proxy) for HTTP(S) services, and optionally control access to these services with user authentication and authorization.

Overview of features:

* [x] Use [Let's Encrypt](https://letsencrypt.org/) automatically to get TLS certificates (http-01 & tls-alpn-01 challenges).
* [x] Terminate TLS connections, and forward the data to any TCP server in plaintext.
* [x] Terminate TLS connections, and forward the data to any TLS server. The data is encrypted in transit, but the proxy sees the plaintext.
* [x] Terminate _TCP_ connections, and forward the TLS connection to any TLS server (passthrough). The proxy doesn't see the plaintext.
* [x] Terminate HTTPS connections, and forward the requests to HTTP or HTTPS servers (http/1 only, not recommended with c2fmzq-server).
* [x] TLS client authentication & authorization (when the proxy terminates the TLS connections).
* [x] Built-in Certificate Authority for managing client and backend server TLS certificates.
* [x] User authentication with OpenID Connect, SAML, and/or passkeys (for HTTP and HTTPS connections). Optionally issue JSON Web Tokens (JWT) to authenticated users to use with the backend s
ervices and/or run a local OpenID Connect server for backend services.
* [x] Access control by IP address.
* [x] Routing based on Server Name Indication (SNI), with optional default route when SNI isn't used.
* [x] Simple round-robin load balancing between servers.
* [x] Support any ALPN protocol in TLS, TLSPASSTHROUGH, or TCP mode.
* [x] Use the same TCP address (IPAddr:port) for any number of server names, e.g. foo.example.com and bar.example.com on the same xxx.xxx.xxx.xxx:443.

