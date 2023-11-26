# TLSPROXY Release Notes

## next

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

