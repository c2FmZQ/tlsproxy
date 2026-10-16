# TLSPROXY Release Notes

## v0.26.1

This release fixes additional security and reliability issues found during a follow-up review.

### :warning: Breaking changes

* **Minimum key sizes and supported algorithms:**
  * The built-in PKI rejects CSRs with RSA keys smaller than 2048 bits, RSA keys with an even public exponent or an
    exponent smaller than 3, `P-224` ECDSA keys, the CA's own public key, or unsupported key types.
  * The SSH certificate authority rejects RSA keys smaller than 2048 bits and refuses to sign the CA's own public key.
  * Remote JWKS endpoints (`trustedIssuers`) ignore RSA keys smaller than 2048 bits, RSA keys with an even public
    exponent or an exponent outside `[3, 2^31-1]`, EC keys on unsupported curves or not on the curve, Ed25519 keys with
    an invalid size, and keys whose `use` is not `sig`.
* **Built-in PKI:**
  * The Root CA certificate and delegated OCSP/CRL signing certificates can no longer be revoked through the
    certificate management endpoint (`?get=revokeCert`).
  * Delegated OCSP/CRL responder certificates are now issued with `IsCA: false` (instead of `IsCA: true`), and CRLs
    are signed directly with the Root CA key.
  * If the Root CA certificate doesn't have the `CRLSign` key usage, it is re-issued at startup with the same key,
    subject, and `SubjectKeyId`, but a new serial number and fingerprint. The old certificate is replaced in the
    list of issued certificates, and a warning with the old and new fingerprints is logged. Clients that pin the CA
    certificate's fingerprint must be updated.
  * The OCSP responder (`ServeOCSP`) rejects OCSP requests that use hash algorithms other than SHA-1, SHA-256,
    SHA-384, or SHA-512, and uses the request's hash algorithm for `IssuerHash` in responses.
  * Browser-generated OpenPGP keys in the PKI WASM client now use AES-256 and a higher S2K iteration count.
* **OCSP verification (`ocspcache` and `tlsclient --ocsp`):**
  * Delegated OCSP responder certificates must be within their `NotBefore`/`NotAfter` validity window.
  * OCSP responses without `NextUpdate` are rejected if `ThisUpdate` is more than 24 hours old, and `ThisUpdate`
    cannot be more than 5 minutes in the future.
  * `tlsclient --ocsp` verifies that stapled OCSP response serial numbers match the certificate, and `ocspcache` fails
    chain verification when constructing an OCSP request or parsing an `OCSPServer` URL fails.
* **Cookies and headers:**
  * TLSPROXY's internal cookies (`TLSPROXYAUTH`, `TLSPROXYIDTOKEN`, `TLSPROXYNONCE`, `TLSPROXYSAMLNONCE`, and
    `__tlsproxySid`) are stripped from the `Cookie` header before forwarding requests to backends. `TLSPROXYIDTOKEN`
    is only forwarded when `generateIdTokens` is set on the backend's `sso` configuration and the token is valid.
  * Client `Connection` headers can no longer cause the proxy to strip headers it sets (`X-Forwarded-*`,
    `X-tlsproxy-user-id`, or `forwardHttpHeaders`).
  * `X-Forwarded-Client-Cert` is now populated on HTTP requests served over raw QUIC streams (ALPN other than `h3`).
  * Logging out (`/.sso/logout`) rotates the `__tlsproxySid` session ID cookie.
  * Built-in HTML pages now include `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.
* **Local OIDC server and identity providers:**
  * `rewriteRules` on the local OIDC server are rejected at config validation if they would overwrite reserved
    JWT/OIDC claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `client_id`, `scope`, `groups`, `nonce`,
    `proxyauth`, `provider`, `hhash`, `sid`, `th`, `depth`), and extra claims from identity providers can no longer
    overwrite `sub`, `iss`, `aud`, `exp`,
    `iat`, `nbf`, `jti`, `email`, `scope`, `client_id`, `groups`, `proxyauth`, `provider`, `hhash`, `sid`, `th`, or
    non-integer `depth`.
  * The device verification endpoint only copies standard OIDC profile claims (`sub`, `email`, `email_verified`,
    `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`,
    `website`, `gender`, `birthdate`, `zoneinfo`, `locale`) and `sid` into device authorization sessions instead of
    internal session claims.
* **Passkeys:**
  * When a passkey provider is shared across multiple backends or SSO rules, ACLs from all rules are merged and any
    open rule (`acl: null`) allows all authenticated users to register passkeys.
  * `/.sso/passkeys` and `/.well-known/passkey-endpoints` are now registered on a passkey provider's callback host
    even when that backend uses a different identity provider.
  * Passkey registration and assertion verification require RSA keys of at least 2048 bits with an odd public
    exponent `>= 3`, credential IDs between 16 and 1023 bytes that are unique across users, and a matching
    `rpIdHash` on assertions.
* **Rate and bandwidth limits:**
  * `forwardRateLimit` is now enforced on every HTTP request over keep-alive HTTP/1.1, HTTP/2, and HTTP/3
    connections, not only when establishing a new connection.
  * `bwLimits` names are matched case-insensitively on backends, and bandwidth limits also apply to QUIC datagrams.
* **Metrics and profiling:**
  * `runtime.MemProfileRate` is no longer set to `1` on startup; memory profiling uses Go's default sampling rate.
  * `forwardHttpHeaders` values containing `${JWT:...}` expressions are redacted on the metrics config page.

### :lock: Security fixes

* Remote JWKS keys were cached by `kid` across all `trustedIssuers`, allowing one trusted issuer to override
  another issuer's signing key with the same `kid`.
* Unvalidated `TLSPROXYIDTOKEN` and internal session/nonce cookies were forwarded to backends.
* A client could list `X-Forwarded-For`, `X-tlsproxy-user-id`, or custom `forwardHttpHeaders` in the `Connection`
  header to have the proxy strip them before forwarding the request.
* Reserved JWT claims could be overwritten via OIDC `rewriteRules` or identity provider extra claims.
* The local OIDC server's device verification endpoint copied internal session claims (`provider`, `th`, `depth`)
  into device authorization sessions.
* Passkey assertions did not verify `rpIdHash`, passkey registration did not check for duplicate credential IDs
  across users, and `RefreshID` did not verify the user's email or `RefreshInterval`.
* Re-authorizing connections after a config reload did not close connections without a client certificate when
  `clientAuth` had no `acl`.
* `checkIP` was not enforced before the TLS handshake on QUIC connections.

### :wrench: Misc

* Hardening and bug fixes:
  * Bypass CSRF checks on the PKI OCSP (`POST`) and local OIDC `/userinfo` (`POST`) endpoints, and check the HTTP
    status code before parsing fetched OCSP responses.
  * Fix `GET` OCSP requests when the base64-encoded request contains `/` or `%2F`, and stop caching `ocsp.Unknown`
    responses.
  * Enforce `localHandler` scopes in `enforceSSOPolicy` even when no SSO rule matches.
  * Recognize certificates issued by a local PKI by the `AuthorityKeyId` of all its issued certificates, not only
    the current CA certificate's `SubjectKeyId`, so that a CA certificate re-issued with a different `SubjectKeyId`
    (go 1.25 changed the default derivation from SHA-1 to SHA-256) doesn't send client certificates through OCSP.
  * Key the connection tracker by connection pointer to avoid 4-tuple collisions and leaks on QUIC connection
    migration.
  * Track QUIC stream goroutines during backend shutdown, recover from panics in QUIC stream handlers, close the
    underlying QUIC connection when dialing a stream fails, and fix a `QUICConn.streams` leak on unidirectional
    streams.
  * Close queued connections when `proxyListener` closes, and close `os.Root` handles (`documentRoot`) on backend
    shutdown or reload.
  * Fix a data race in `TokenManager.HMAC()`, a data race on WebSocket `lastActive` timestamps, and a lock held
    while collecting runtime memory/goroutine/mutex profiles on the metrics page; gate `/debug/pprof` handlers
    behind the `pprof` build tag.
  * Handle multi-token `Connection` headers and non-binary frames in the WebSocket handler.
  * Add timeouts, status code checks, and 1 MiB response limits on OIDC discovery, token, and userinfo requests,
    parse all PEM blocks in SAML IdP certificates, and delete denied or already-approved OIDC authorization
    requests immediately.
  * Wipe the temporary SSH CA private key buffer after loading, and cap `RLIM_INFINITY` in `openFileLimit()`.
  * Harden the example servers (`examples/backend`, `examples/oauth2server`, `examples/deviceauth`) and build
    scripts.
* New tests for all the changes above.
* Update go: 1.27.2
* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.3.2 => v0.3.3
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20261007172857-b4d54d07896c => v0.0.0-20261007173353-8a25cfd4b704
  * upgraded github.com/c2FmZQ/tpm v0.5.0 => v0.6.0
  * upgraded github.com/google/go-tpm-tools v0.4.7 => v0.4.10
  * upgraded github.com/quic-go/quic-go v0.63.0 => v0.64.0
  * upgraded golang.org/x/crypto v0.57.0 => v0.58.0
  * upgraded golang.org/x/net v0.59.0 => v0.61.0
  * upgraded golang.org/x/sys v0.48.0 => v0.49.0
  * upgraded golang.org/x/text v0.42.0 => v0.43.0
  * upgraded google.golang.org/protobuf v1.36.5 => v1.36.12
  * upgraded software.sslmate.com/src/go-pkcs12 v0.7.3 => v0.7.4

## v0.26.0

This release fixes a number of security issues found during a security review. Some of the fixes change the
behavior of the proxy in ways that may require config changes. Please read the breaking changes below before
upgrading.

### :warning: Breaking changes

* **PKI server certificates must be allowed explicitly.** Users can no longer request server certificates for
  arbitrary DNS names. The new `serverCertificates` option of `pki` lists the DNS names (or one-label wildcards)
  that can be requested, and optionally which users or groups can request them. Without it, only client
  certificates can be issued. For example:
  ```yaml
  pki:
  - name: "EXAMPLE CA"
    endpoint: https://pki-internal.example.com/certs
    serverCertificates:
    - dnsNames:
      - "*.internal.example.com"
      acl:
      - bob@example.com
  ```
* **`jwksUri` must be an https URL** in `trustedIssuers`.
* **Bearer tokens and ID token cookies must have an `exp` claim.** Tokens issued by TLSPROXY always have one.
* **The Host header must match one of the backend's `serverNames`.** This was already enforced for `HTTP` and
  `HTTPS` backends, but only after authentication. It is now checked first, and also for `LOCAL` and `CONSOLE`
  backends. Requests with a different Host header get `421 Misdirected Request`.
* **Forwarded headers are set by the proxy.** `X-Forwarded-Host` and `X-Forwarded-Proto` are now set on forwarded
  requests, and the client's `Forwarded`, `X-Forwarded-Host`, and `X-Forwarded-Proto` headers are removed. Client
  headers with the same name as `X-Forwarded-For`, `X-Forwarded-Client-Cert`, `X-tlsproxy-user-id`, or any
  `forwardHttpHeaders` key, ignoring case and with `_` instead of `-` (e.g. `X_tlsproxy_user_id`), are removed.
  `forwardHttpHeaders` can still override or remove `X-Forwarded-Host` and `X-Forwarded-Proto`.
* **Backends can't set TLSPROXY's cookies.** `Set-Cookie` headers from backends for `TLSPROXYAUTH`,
  `TLSPROXYIDTOKEN`, `TLSPROXYNONCE`, `TLSPROXYSAMLNONCE`, or `__tlsproxySid` are dropped.
* **SSH certificate authority:**
  * DSA keys are rejected.
  * A `ttl` that is not a positive number of seconds is rejected with `400 Bad Request`. Larger values are still
    capped at `maximumCertificateLifetime`.
* **Login links expire.** The links used on the login, logout, and permission denied pages expire after a week,
  and must point to the same backend.
* **Device authorization page.** The device verification page now has two steps: after entering the user code,
  the page shows which client is requesting access and with which scopes, before the user can approve or deny the
  request.
* **Local OIDC server:**
  * The `redirect_uri` sent to the token endpoint must be the same as in the authorization request.
  * When the client sends a PKCE `code_challenge`, the token request must include a matching `code_verifier`.
  * An authorization request must be approved by the same user who made it.
* **Passkeys:**
  * The origin of passkey assertions is checked, like it already was for registrations.
  * Authenticators with a signature counter must increase it on every login. Authenticators that don't implement
    a counter are not affected.
* **Connection limits:**
  * The TLS handshake timeout is reduced from 2 minutes to 30 seconds.
  * Connections and requests that would wait more than 30 seconds for `forwardRateLimit` are rejected instead of
    waiting indefinitely.
  * Each stream of a non-HTTP/3 QUIC connection counts toward `forwardRateLimit`.
  * The plain HTTP server (`httpAddr`) has 10-second timeouts, and accepts at most 1000 concurrent connections, or
    `maxOpen` if it is lower.
  * At most 50000 pending logins are kept per identity provider, and the local OIDC server keeps at most 10000
    pending authorization or device authorization requests. URLs longer than 4096 bytes can't be used as the
    destination of a login.
* **ACLs:** an ACL entry that is the name of a group is no longer also compared to the user's email address.
* **`tlsclient --ocsp`** verifies OCSP responses against the verified certificate chain, and rejects responses
  signed by certificates that aren't authorized to sign OCSP responses.

### :lock: Security fixes

* SSO rules and exceptions were matched against the raw request path. A path like `/public/../admin` matched an
  exception for `/public/`, and was then forwarded as `/admin` without authentication.
* Bearer tokens signed by any trusted issuer's key were accepted as if they had been issued by TLSPROXY.
* The SSH certificate authority issued certificates that never expire when given a negative or very large `ttl`.
* Forwarding a request to a backend with HTTP/3 crashed the proxy.
* ID tokens issued for one backend could be used on another backend with a different Host header.
* OCSP responses, stapled or fetched, could be signed by any certificate issued by the same CA, including the
  revoked certificate itself. Fetched responses weren't checked for the serial number or freshness.
* Any PKI user could get a server certificate for any DNS name.
* The plain HTTP server had no timeouts, and idle connections could use up all the available file descriptors.
* Unauthenticated device authorization requests could make the local OIDC server very slow.
* Open redirects after login and after setting the ID token cookie.
* SAML responses weren't tied to the browser that started the login, which allowed an attacker to log a victim
  into the attacker's account.
* Client-supplied headers could spoof the user identity header for CGI-style backends.
* The scopes required by built-in endpoints (pki, ssh, etc) weren't checked when no SSO rule matched the path.
* The CSRF check was skipped for any request with an `Authorization` header, even when cookies were used for
  authentication.
* Passkey logins were accepted from other origins, and the existence of passkeys for an email address could be
  detected.
* A user could approve another user's OIDC authorization request and get tokens despite the client's ACL.
* Revoking a certificate issued by the built-in PKI didn't close connections already using it.
* The built-in PKI could serve a CRL that didn't include the latest revocations.
* Memory use could be increased without limit with ECH client hellos with arbitrary server names, and with
  pending login requests.

### :star2: New features

* New `maxOpenPerIP` option to limit the number of open connections from a single client IP address. There is no
  limit by default.
* New `serverCertificates` option for `pki` (see above).
* The local OIDC server supports PKCE (RFC 7636), and advertises `code_challenge_methods_supported`.

### :wrench: Misc

* Hardening:
  * Constant-time comparison of OIDC client secrets.
  * Client-provided server names are quoted in QUIC logs.
  * More secrets are redacted from the config shown on the metrics page: static `forwardHttpHeaders` values and
    ECH webhook URLs.
  * `proxy.mjs` only sends the CSRF token to the same origin.
  * A warning is logged when `--passphrase` is used. `$TLSPROXY_PASSPHRASE` should be used instead.
* Bug fixes:
  * Data races on the ECH keys and in the PKI's OCSP/CRL signing certificate rotation.
  * Panic on `/.sso/` for backends without SSO.
  * Possible panic when re-authorizing connections after a backend was removed.
  * The session chain claim (`th`) wasn't carried over after an OIDC login.
  * The ephemeral certificate manager (for testing) keeps a bounded number of certificates in memory, and reissues
    expired certificates.
* New tests for all the changes above.
* Update go dependencies:
  * upgraded github.com/ProtonMail/go-crypto v1.4.1 => v1.5.2
  * upgraded github.com/beevik/etree v1.7.1 => v1.8.1
  * upgraded github.com/c2FmZQ/ech v0.4.2 => v0.4.3
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260902181210-9e31d44e7146 => v0.0.0-20261007172857-b4d54d07896c
  * upgraded github.com/fxamacker/cbor/v2 v2.9.3 => v2.9.6
  * upgraded github.com/quic-go/quic-go v0.62.0 => v0.63.0
  * upgraded golang.org/x/crypto v0.56.0 => v0.57.0
  * upgraded golang.org/x/net v0.58.0 => v0.59.0
  * upgraded golang.org/x/sys v0.47.0 => v0.48.0
  * upgraded golang.org/x/text v0.41.0 => v0.42.0
  * upgraded golang.org/x/time v0.15.0 => v0.16.0


## v0.25.12

### :wrench: Misc

* Update go: 1.27.1
* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260814232134-21593609a286 => v0.0.0-20260902181210-9e31d44e7146
  * upgraded github.com/quic-go/quic-go v0.61.0 => v0.62.0
  * upgraded golang.org/x/crypto v0.55.0 => v0.56.0

## v0.25.11

### :wrench: Misc

* Update go: 1.27.0
* Update go dependencies:
  * upgraded github.com/beevik/etree v1.7.0 => v1.7.1
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260811002012-644de39a8509 => v0.0.0-20260814232134-21593609a286
  * upgraded github.com/fxamacker/cbor/v2 v2.9.2 => v2.9.3

## v0.25.10

### :wrench: Misc

* Update go: 1.26.6
* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260708140351-a2b4527a234e => v0.0.0-20260811002012-644de39a8509
  * upgraded github.com/cloudflare/circl v1.6.3 => v1.6.5
  * upgraded golang.org/x/crypto v0.54.0 => v0.55.0
  * upgraded golang.org/x/net v0.57.0 => v0.58.0
  * upgraded golang.org/x/text v0.40.0 => v0.41.0

## v0.25.9

### :wrench: Bug fix

* Fix potential panic on config change

### :wrench: Misc

* Switch the pki client to ProtonMail openpgp.
* Update go dependencies:
  * upgraded github.com/beevik/etree v1.6.0 => v1.7.0
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260607011050-6d6478ff2733 => v0.0.0-20260708140351-a2b4527a234e
  * upgraded github.com/pires/go-proxyproto v0.14.0 => v0.15.0
  * upgraded github.com/quic-go/quic-go v0.60.0 => v0.61.0
  * upgraded github.com/russellhaering/goxmldsig v1.6.0 => v1.6.1
  * upgraded golang.org/x/crypto v0.53.0 => v0.54.0
  * upgraded golang.org/x/net v0.56.0 => v0.57.0
  * upgraded golang.org/x/text v0.39.0 => v0.40.0

## v0.25.8

### :wrench: Misc

* Update go: 1.26.5
* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260607003827-7389b812f9da => v0.0.0-20260607011050-6d6478ff2733
  * upgraded github.com/pires/go-proxyproto v0.12.0 => v0.14.0
  * upgraded golang.org/x/crypto v0.52.0 => v0.53.0
  * upgraded golang.org/x/net v0.55.0 => v0.56.0
  * upgraded golang.org/x/sys v0.45.0 => v0.47.0
  * upgraded golang.org/x/text v0.37.0 => v0.39.0
  * upgraded software.sslmate.com/src/go-pkcs12 v0.7.1 => v0.7.3

## v0.25.7

### :wrench: Misc

* Update go: 1.26.4
* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260508202130-0a0e9b94ffe3 => v0.0.0-20260607003827-7389b812f9da
  * upgraded github.com/c2FmZQ/http3-go v0.59.0 => v0.60.0
  * upgraded github.com/c2FmZQ/quic-api v0.59.0 => v0.60.0
  * upgraded github.com/quic-go/quic-go v0.59.1 => v0.60.0

## v0.25.5

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260408211437-f3a70db0dbf0 => v0.0.0-20260508202130-0a0e9b94ffe3
  * upgraded github.com/quic-go/quic-go v0.59.0 => v0.59.1
  * upgraded golang.org/x/crypto v0.51.0 => v0.52.0
  * upgraded golang.org/x/net v0.54.0 => v0.55.0
  * upgraded golang.org/x/sys v0.44.0 => v0.45.0

## v0.25.4

### :wrench: Misc

* Update go: 1.26.3
* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260308015521-e84033c86e36 => v0.0.0-20260408211437-f3a70db0dbf0
  * upgraded github.com/fxamacker/cbor/v2 v2.9.1 => v2.9.2
  * upgraded github.com/pires/go-proxyproto v0.11.0 => v0.12.0
  * upgraded golang.org/x/crypto v0.49.0 => v0.51.0
  * upgraded golang.org/x/net v0.52.0 => v0.53.0
  * upgraded golang.org/x/sys v0.43.0 => v0.44.0
  * upgraded golang.org/x/text v0.35.0 => v0.37.0
  * upgraded software.sslmate.com/src/go-pkcs12 v0.7.0 => v0.7.1

## v0.25.3

### :wrench: Misc

* Update go: 1.26.2
* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.4.0 => v0.4.2
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260210222347-c2dddf848fef => v0.0.0-20260308015521-e84033c86e36
  * upgraded github.com/fxamacker/cbor/v2 v2.9.0 => v2.9.1
  * upgraded github.com/russellhaering/goxmldsig v1.5.0 => v1.6.0
  * upgraded golang.org/x/crypto v0.48.0 => v0.49.0
  * upgraded golang.org/x/net v0.51.0 => v0.52.0
  * upgraded golang.org/x/sys v0.41.0 => v0.43.0
  * upgraded golang.org/x/text v0.34.0 => v0.35.0
  * upgraded golang.org/x/time v0.14.0 => v0.15.0

## v0.25.2

### :wrench: Misc

* Update go: 1.26.1
* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.3.7 => v0.4.0
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260131152559-a997fb69198a => v0.0.0-20260210222347-c2dddf848fef
  * upgraded github.com/c2FmZQ/tpm v0.4.3 => v0.5.0
  * upgraded github.com/google/go-tpm-tools v0.4.5 => v0.4.7
  * upgraded golang.org/x/net v0.50.0 => v0.51.0

## v0.25.1

### :wrench: Misc

* Update go: 1.26.0
* Update go dependencies:
  * upgraded github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260130170702-223855195ae7 => v0.0.0-20260131152559-a997fb69198a
  * upgraded github.com/pires/go-proxyproto v0.9.2 => v0.11.0
  * upgraded golang.org/x/crypto v0.47.0 => v0.48.0
  * upgraded golang.org/x/net v0.49.0 => v0.50.0
  * upgraded golang.org/x/sys v0.40.0 => v0.41.0
  * upgraded golang.org/x/text v0.33.0 => v0.34.0

## v0.25.0

### :star2: New feature 

* Implement distributed authentication trust via TrustedIssuers. See `trustedIssuers`.

### :wrench: Misc

* Refactored JWKS into a new module.
* Update go dependencies:
  * added github.com/c2FmZQ/tlsproxy/jwks v0.0.0-20260130170702-223855195ae7
  * upgraded github.com/golang-jwt/jwt/v5 v5.3.0 => v5.3.1
  * upgraded github.com/pires/go-proxyproto v0.8.1 => v0.9.2

## v0.24.2

### :wrench: Misc

* Update go: 1.25.6
* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.3.1 => v0.3.2
  * upgraded golang.org/x/crypto v0.46.0 => v0.47.0
  * upgraded golang.org/x/net v0.48.0 => v0.49.0

## v0.24.1

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/http3-go v0.57.0 => v0.59.0
  * upgraded github.com/c2FmZQ/quic-api v0.57.0 => v0.59.0
  * upgraded github.com/quic-go/quic-go v0.58.0 => v0.59.0

## v0.24.0

### :star: Feature improvement

* Add two new SSO rule options:
  * `SkipLoginPage` redirects requests directly to the IDP's login page.
  * `Return403ForGetRequests` returns a simple 403 (Forbidden) response for GET requests. Normally, GET requests get a login page.
* Add `TokenLifetime` to OIDC, SAML, and Passkey providers. This optional field set the lifetime of auth tokens set by tlsproxy.

### :wrench: Misc

* Update go: 1.25.5
* Update go dependencies:
  * upgraded github.com/c2FmZQ/http3-go v0.56.0 => v0.57.0
  * upgraded github.com/c2FmZQ/quic-api v0.56.0 => v0.57.0
  * upgraded github.com/google/go-tpm v0.9.7 => v0.9.8
  * upgraded github.com/quic-go/quic-go v0.56.0 => v0.58.0
  * upgraded github.com/quic-go/qpack v0.5.1 => v0.6.0
  * upgraded golang.org/x/crypto v0.45.0 => v0.46.0
  * upgraded golang.org/x/net v0.47.0 => v0.48.0
  * upgraded golang.org/x/sys v0.38.0 => v0.39.0
  * upgraded golang.org/x/text v0.31.0 => v0.32.0
  * upgraded software.sslmate.com/src/go-pkcs12 v0.6.0 => v0.7.0

## v0.23.2

### :wrench: Misc

* Update go: 1.25.4
* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.3.6 => v0.3.7
  * upgraded github.com/c2FmZQ/http3-go v0.55.0 => v0.56.0
  * upgraded github.com/c2FmZQ/quic-api v0.55.0 => v0.56.0
  * upgraded github.com/google/go-tpm v0.9.6 => v0.9.7
  * upgraded github.com/quic-go/quic-go v0.55.0 => v0.56.0
  * upgraded golang.org/x/crypto v0.43.0 => v0.45.0
  * upgraded golang.org/x/net v0.46.0 => v0.47.0
  * upgraded golang.org/x/sys v0.37.0 => v0.38.0
  * upgraded golang.org/x/text v0.30.0 => v0.31.0

## v0.23.1

### :wrench: Misc

* Replace the 🛂 emoji with a svg icon.
* Update go: 1.25.3
* Update go dependencies:
  * upgraded golang.org/x/crypto v0.42.0 => v0.43.0
  * upgraded golang.org/x/mod v0.28.0 => v0.29.0
  * upgraded golang.org/x/net v0.45.0 => v0.46.0
  * upgraded golang.org/x/sys v0.36.0 => v0.37.0
  * upgraded golang.org/x/text v0.29.0 => v0.30.0
  * upgraded golang.org/x/time v0.13.0 => v0.14.0
  * upgraded golang.org/x/tools v0.37.0 => v0.38.0

## v0.23.0

### :wrench: Misc

* Clean up the ssh CA request parsing. When a specific ttl is desired, the request must now use `content-type: application/x-www-form-urlencoded`.
* Update go: 1.25.2
* Update go dependencies:
  * upgraded github.com/c2FmZQ/http3-go v0.54.0 => v0.55.0
  * upgraded github.com/c2FmZQ/quic-api v0.54.0 => v0.55.0
  * upgraded github.com/quic-go/quic-go v0.54.0 => v0.55.0
  * upgraded golang.org/x/net v0.44.0 => v0.45.0

## v0.22.2

### :wrench: Misc

* New tests and refactoring.
* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.3.0 => v0.3.1
  * upgraded github.com/c2FmZQ/tpm v0.4.1 => v0.4.3

## v0.22.1

### :wrench: Bug fix

* Fix minor language matching bug. Under some conditions, the UI would pick the wrong language from the browser.

## v0.22.0

### :star2: New feature

* New translations for 40 languages, mostly AI-generated.

### :wrench: Misc

* Update go: 1.25.1
* Update go dependencies:
  * upgraded github.com/google/go-tpm v0.9.5 => v0.9.6
  * upgraded golang.org/x/crypto v0.41.0 => v0.42.0
  * upgraded golang.org/x/mod v0.27.0 => v0.28.0
  * upgraded golang.org/x/net v0.43.0 => v0.44.0
  * upgraded golang.org/x/sync v0.16.0 => v0.17.0
  * upgraded golang.org/x/sys v0.35.0 => v0.36.0
  * upgraded golang.org/x/text v0.28.0 => v0.29.0
  * upgraded golang.org/x/time v0.12.0 => v0.13.0
  * upgraded golang.org/x/tools v0.36.0 => v0.37.0

## v0.21.0

### :wrench: Misc

* Better CSRF protection for local http handlers.
* Only show groups when the groups scope is granted.
* Require the openid scope to access /userinfo.

## v0.20.0

### :star2: New features

* Groups for access control. See [examples/sso](https://github.com/c2FmZQ/tlsproxy/tree/main/examples/sso#groups)
* Device authorization flow (RFC 8628) to access backend services from non-browser environments, e.g. shell scripts.
  * Parts of this change also add scopes to all the endpoints so that the permissions of tokens issued with oauth2
    can be limited. By default, all the proxied http(s) endpoints that require SSO also require the *sso* scope.
    Built-in endpoints have their own required scopes as well, e.g. ssh, pki, etc.
* New `maximumCertificateLifetime` attribute for `sshCertificateAuthorities`.

### :wrench: Misc

* Fix parsing of SSH Cert request. Sometimes, the requested TTL wasn't parsed correctly.
* Update go dependencies:
  * upgraded github.com/beevik/etree v1.5.1 => v1.6.0
  * upgraded go.uber.org/mock v0.5.2 => v0.6.0

## v0.19.0

### :star: Feature improvement

Backends can now have different SSO ACLs for different paths. The `paths:`, `exceptions:`, `acl:`, and `forceReAuth:` options are moving to `rules:` where each rule has its own `paths:`, `exceptions:`, `acl:`, and `forceReAuth:` options.

Before:
```yaml
   sso:
     provider: <provider>
     paths:
       - /foo
     forceReAuth: 1h
     acl:
       - alice@example.com
       - bob@example.com
```

Now:
```yaml
   sso:
     provider: <provider>
     rules:
       - paths:
           - /foo
         forceReAuth: 1h
         acl:
           - alice@example.com
           - bob@example.com
```

The first rule with matching `paths` (and not matching `exceptions`) is the one that's used for the request.

As before, if `acl:` is not specified, all authenticated requests are allowed. If `acl:` is set to an empty list, i.e. `acl: []`, nothing is allowed.

The old syntax still works, but is now deprecated and will be removed eventually.

### :wrench: Misc

* Update go: 1.25.0
* Update go dependencies:
  * upgraded golang.org/x/crypto v0.40.0 => v0.41.0
  * upgraded golang.org/x/mod v0.26.0 => v0.27.0
  * upgraded golang.org/x/net v0.42.0 => v0.43.0
  * upgraded golang.org/x/sys v0.34.0 => v0.35.0
  * upgraded golang.org/x/text v0.27.0 => v0.28.0
  * upgraded golang.org/x/tools v0.35.0 => v0.36.0

## v0.18.1

### :wrench: Misc

* Update go: 1.24.6

## v0.18.0

### :star: Feature improvement

* Add a simple html form to facilitate acquiring SSH certificates outside of the sshterm app. The form is served from `certificateEndpoint` when the http method is GET.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/fxamacker/cbor/v2 v2.8.0 => v2.9.0
  * upgraded github.com/golang-jwt/jwt/v5 v5.2.2 => v5.3.0
  * upgraded software.sslmate.com/src/go-pkcs12 v0.5.0 => v0.6.0

## v0.17.0

### :wrench: Misc

* Enable QUIC Stream Resets with Partial Delivery.
* Forward QUIC stream errors.
* Update go dependencies:
  * upgraded github.com/c2FmZQ/http3-go v0.53.0 => v0.54.0
  * upgraded github.com/c2FmZQ/quic-api v0.53.0 => v0.54.0
  * upgraded github.com/quic-go/quic-go v0.53.0 => v0.54.0

## v0.16.3

### :wrench: Misc

* Replace github.com/c2FmZQ/quic-go-api with github.com/c2FmZQ/quic-api and github.com/c2FmZQ/http3-go, which allows a cleaner integration with the mainline quic-go library.
* Update go dependencies:
  * upgraded golang.org/x/crypto v0.39.0 => v0.40.0
  * upgraded golang.org/x/net v0.41.0 => v0.42.0
  * upgraded golang.org/x/sys v0.33.0 => v0.34.0

## v0.16.2

### :wrench: Misc

* :warning: This version includes a change to the storage library that makes it very difficult to rollback to an earlier version after upgrading to this version without losing data.
* Update go: 1.24.5
* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.2.5 => v0.3.0

## v0.16.1

### :wrench: Misc

* TLSPROXY now uses a [quic-go fork](https://github.com/c2FmZQ/quic-go-api/tree/v0.53.0) to workaround an API change that broke integration (https://github.com/c2FmZQ/tlsproxy/issues/211).
* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.3.6
  * upgraded github.com/c2FmZQ/ech/publish v0.1.2
  * upgraded github.com/c2FmZQ/ech/quic v0.3.6
  * upgraded github.com/google/pprof v0.0.0-20250602020802-c6617b811d0e => v0.0.0-20250630185457-6e76a2b096b5
  * upgraded github.com/hashicorp/go-retryablehttp v0.7.7 => v0.7.8
  * upgraded github.com/quic-go/quic-go v0.52.0 => v0.53.0
  * upgraded golang.org/x/crypto v0.38.0 => v0.39.0
  * upgraded golang.org/x/net v0.40.0 => v0.41.0
  * upgraded golang.org/x/tools v0.33.0 => v0.34.0

## v0.16.0

### :star2: New features

* Config options that accept multiple values can now be specified on one line if there is only one value, e.g.
  ```
  addresses: 192.168.0.1:80
  ```
  is equivalent to:
  ```
  addresses:
    - 192.168.0.1:80
  ```
* The config file can now be split across multiple files or directories with the 'include' directive, e.g.
  ```
  include: "conf/*.yaml"
  ```
  or
  ```
  include:
    - "conf/*.yaml"
  ```
* tlsclient: New flag `--insecuredns` to use the default go resolver.

### :wrench: Misc

* Update go: 1.24.4
* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.2.4 => v0.2.5
  * upgraded github.com/c2FmZQ/tpm v0.4.0 => v0.4.1
  * upgraded github.com/google/go-tpm v0.9.4 => v0.9.5
  * upgraded github.com/google/go-tpm-tools v0.4.4 => v0.4.5
  * upgraded github.com/google/pprof v0.0.0-20250501235452-c0086092b71a => v0.0.0-20250602020802-c6617b811d0e
  * upgraded github.com/quic-go/quic-go v0.51.0 => v0.52.0
  * upgraded golang.org/x/mod v0.24.0 => v0.25.0
  * upgraded golang.org/x/sync v0.14.0 => v0.15.0
  * upgraded golang.org/x/text v0.25.0 => v0.26.0
  * upgraded golang.org/x/time v0.11.0 => v0.12.0

## v0.15.10

### :wrench: Bug Fix

* [Let's Encrypt is removing support for OCSP](https://letsencrypt.org/2024/12/05/ending-ocsp/). This change broke some assumptions in TLSPROXY which resulted in failed requests and some crashes. This release fixes that problem. OCSP stapling will only be enabled when the certificate authority supports it.

## v0.15.9

### :wrench: Misc

* Update go: 1.24.3
* Update go dependencies:
  * upgraded github.com/google/go-tpm v0.9.3 => v0.9.4
  * upgraded github.com/google/pprof v0.0.0-20250418163039-24c5476c6587 => v0.0.0-20250501235452-c0086092b71a
  * upgraded github.com/pires/go-proxyproto v0.8.0 => v0.8.1
  * upgraded go.uber.org/mock v0.5.1 => v0.5.2
  * upgraded golang.org/x/crypto v0.37.0 => v0.38.0
  * upgraded golang.org/x/net v0.39.0 => v0.40.0
  * upgraded golang.org/x/sync v0.13.0 => v0.14.0
  * upgraded golang.org/x/sys v0.32.0 => v0.33.0
  * upgraded golang.org/x/text v0.24.0 => v0.25.0
  * upgraded golang.org/x/tools v0.32.0 => v0.33.0

## v0.15.8

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/beevik/etree v1.5.0 => v1.5.1
  * upgraded github.com/google/pprof v0.0.0-20250317173921-a4b03ec1a45e => v0.0.0-20250418163039-24c5476c6587
  * upgraded github.com/onsi/ginkgo/v2 v2.23.3 => v2.23.4
  * upgraded github.com/quic-go/quic-go v0.50.1 => v0.51.0
  * upgraded go.uber.org/mock v0.5.0 => v0.5.1
  * upgraded golang.org/x/crypto v0.36.0 => v0.37.0
  * upgraded golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 => v0.0.0-20250408133849-7e4ce0ab07d0
  * upgraded golang.org/x/net v0.38.0 => v0.39.0
  * upgraded golang.org/x/sync v0.12.0 => v0.13.0
  * upgraded golang.org/x/sys v0.31.0 => v0.32.0
  * upgraded golang.org/x/text v0.23.0 => v0.24.0
  * upgraded golang.org/x/tools v0.31.0 => v0.32.0

## v0.15.7

### :wrench: Misc

* Update go: 1.24.2
* Update go dependencies:
  * upgraded github.com/fxamacker/cbor/v2 v2.7.0 => v2.8.0

## v0.15.6

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.3.4 => v0.3.5
  * upgraded github.com/c2FmZQ/ech/quic v0.3.0 => v0.3.5
  * upgraded github.com/golang-jwt/jwt/v5 v5.2.1 => v5.2.2
  * upgraded github.com/google/pprof v0.0.0-20250302191652-9094ed2288e7 => v0.0.0-20250317173921-a4b03ec1a45e
  * upgraded github.com/onsi/ginkgo/v2 v2.23.0 => v2.23.3
  * upgraded github.com/quic-go/quic-go v0.50.0 => v0.50.1
  * upgraded github.com/russellhaering/goxmldsig v1.4.0 => v1.5.0
  * upgraded golang.org/x/net v0.37.0 => v0.38.0

## v0.15.5

### :star: Feature improvement

* Add backend config options to facilitate enabling Encrypted Client Hello (ECH) between tlsproxy and its backends. See `ForwardECH` in proxy/config.go.

## v0.15.4

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/onsi/ginkgo/v2 v2.22.2 => v2.23.0
  * upgraded golang.org/x/crypto v0.35.0 => v0.36.0
  * upgraded golang.org/x/exp v0.0.0-20250228200357-dead58393ab7 => v0.0.0-20250305212735-054e65f0b394
  * upgraded golang.org/x/mod v0.23.0 => v0.24.0
  * upgraded golang.org/x/net v0.36.0 => v0.37.0
  * upgraded golang.org/x/sync v0.11.0 => v0.12.0
  * upgraded golang.org/x/sys v0.30.0 => v0.31.0
  * upgraded golang.org/x/text v0.22.0 => v0.23.0
  * upgraded golang.org/x/time v0.10.0 => v0.11.0
  * upgraded golang.org/x/tools v0.30.0 => v0.31.0

## v0.15.3

### :wrench: Bug fix

* Fix [issue 195](https://github.com/c2FmZQ/tlsproxy/issues/195).
  * Use the default GO resolver by default to resolve backend addresses.
  * Add new config option `UseDoH` to enable DNS-over-HTTPS as needed.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.3.2 => v0.3.4

## v0.15.2

### :star: Feature improvement

* Use [ech.Dialer](https://pkg.go.dev/github.com/c2FmZQ/ech#Dialer) to connect to backends. This has a number of advantages:
  * It can use Encrypted Client Hello automatically when available.
  * It uses DNS-over-HTTPS.
  * It supports delayed concurrent connection attempts for faster connections when some servers are slow or unresponsive.

### :wrench: Misc

* Update go: 1.24.1
* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.2.6 => v0.3.2
  * upgraded github.com/c2FmZQ/ech/quic v0.2.6 => v0.3.0
  * upgraded github.com/google/pprof v0.0.0-20250208200701-d0013a598941 => v0.0.0-20250302191652-9094ed2288e7
  * upgraded golang.org/x/crypto v0.33.0 => v0.35.0
  * upgraded golang.org/x/exp v0.0.0-20250218142911-aa4b98e5adaa => v0.0.0-20250228200357-dead58393ab7
  * upgraded golang.org/x/net v0.35.0 => v0.36.0

## v0.15.1

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/ech v0.2.2 => v0.2.6
  * upgraded github.com/c2FmZQ/ech/publish v0.0.0-20250212043933-8c11bf5e715e => v0.1.1
  * upgraded github.com/c2FmZQ/ech/quic v0.2.2 => v0.2.6
  * upgraded github.com/quic-go/quic-go v0.49.0 => v0.50.0
  * upgraded golang.org/x/exp v0.0.0-20250210185358-939b2ce775ac => v0.0.0-20250218142911-aa4b98e5adaa

## v0.15.0

### :star2: New feature

* Add support for Encrypted Client Hello. This feature improves privacy by allowing the clients to encrypt the Server Name to which they are connecting. Without ECH, this information is actually transmitted in plain text. When `ech:` is set in `config.yaml`, tlsproxy handles ECH as a Client-Facing Server with a Split Mode Topology as specified in https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/. See [ECH](https://github.com/c2FmZQ/tlsproxy/blob/main/docs/ECH.md)

### :wrench: Bug fixes

* Handle quic.ErrTransportClosed correctly.

### :wrench: Misc

* Use os.Root for static file isolation
* Allow customized permission denied messages.
* Update go: 1.24.0
* Update go dependencies:
  * upgraded github.com/quic-go/quic-go v0.48.2 => v0.49.0
  * upgraded github.com/beevik/etree v1.4.1 => v1.5.0
  * upgraded github.com/google/pprof v0.0.0-20241210010833-40e02aabc2ad => v0.0.0-20250208200701-d0013a598941
  * upgraded golang.org/x/crypto v0.32.0 => v0.33.0
  * upgraded golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 => v0.0.0-20250210185358-939b2ce775ac
  * upgraded golang.org/x/mod v0.22.0 => v0.23.0
  * upgraded golang.org/x/net v0.34.0 => v0.35.0
  * upgraded golang.org/x/sync v0.10.0 => v0.11.0
  * upgraded golang.org/x/sys v0.29.0 => v0.30.0
  * upgraded golang.org/x/text v0.21.0 => v0.22.0
  * upgraded golang.org/x/time v0.9.0 => v0.10.0
  * upgraded golang.org/x/tools v0.29.0 => v0.30.0

## v0.14.2

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.2.3 => v0.2.4
  * upgraded github.com/c2FmZQ/tpm v0.3.1 => v0.4.0
  * upgraded github.com/google/go-tpm v0.9.1 => v0.9.3
  * upgraded github.com/jonboulle/clockwork v0.4.0 => v0.5.0
  * upgraded github.com/onsi/ginkgo/v2 v2.22.0 => v2.22.2
  * upgraded golang.org/x/crypto v0.31.0 => v0.32.0
  * upgraded golang.org/x/exp v0.0.0-20241210194714-1829a127f884 => v0.0.0-20250106191152-7588d65b2ba8
  * upgraded golang.org/x/net v0.32.0 => v0.34.0
  * upgraded golang.org/x/sys v0.28.0 => v0.29.0
  * upgraded golang.org/x/time v0.8.0 => v0.9.0
  * upgraded golang.org/x/tools v0.28.0 => v0.29.0

## v0.14.1

### :wrench: Misc

* Simplify the PKI client-side code and remove the service worker.

## v0.14.0

### :star2: New feature

* Add a built-in certificate authority for SSH. It is enabled with the top-level `sshCertificateAuthorities` field in the config file.
  * This CA issues SSH user certificates with the current user's email address as both `Key ID` and `Principal`. It only works when SSO is enabled.
  * User authorization is done by adding a line like this to the user's `.ssh/authorized_keys` file:
```
cert-authority,principals="<email>" <CA's public key>
```

### :star: Feature improvement

* Add an option to exclude some path prefixes from SSO enforcement.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20241203143554-1e3fdc7de467 => v0.0.0-20241210010833-40e02aabc2ad
  * upgraded golang.org/x/crypto v0.29.0 => v0.31.0
  * upgraded golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f => v0.0.0-20241210194714-1829a127f884
  * upgraded golang.org/x/net v0.31.0 => v0.32.0
  * upgraded golang.org/x/sync v0.9.0 => v0.10.0
  * upgraded golang.org/x/sys v0.27.0 => v0.28.0
  * upgraded golang.org/x/text v0.20.0 => v0.21.0
  * upgraded golang.org/x/tools v0.27.0 => v0.28.0

## v0.13.2

### :wrench: Misc

* Update go: 1.23.4
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20241101162523-b92577c0c142 => v0.0.0-20241203143554-1e3fdc7de467
  * upgraded github.com/onsi/ginkgo/v2 v2.21.0 => v2.22.0
  * upgraded github.com/quic-go/quic-go v0.48.1 => v0.48.2

## v0.13.1

### :wrench: Bug fix

* Fix goroutine and connection leak with WebSockets.

## v0.13.0

### :star2: New feature

* Add support for forwarding WebSocket requests to arbitrary TCP servers. WebSockets were already forwarded transparently to backends before, and that is not changing. The new feature lets TLSPROXY itself handle the WebSocket request and forward them to any TCP servers. The content of BinaryMessages is streamed to the remote server, and data received from the server is sent back to the client also as BinaryMessages.
  * This is used by [SSH Term](https://github.com/c2FmZQ/sshterm).

## v0.12.0

### :star: Feature improvement

* Improve passkey authentication to support WebAuthn devices without discoverable credentials.

### :wrench: Misc

* Update go dependencies:
  * upgraded golang.org/x/crypto v0.28.0 => v0.29.0
  * upgraded golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c => v0.0.0-20241108190413-2d47ceb2692f
  * upgraded golang.org/x/mod v0.21.0 => v0.22.0
  * upgraded golang.org/x/net v0.30.0 => v0.31.0
  * upgraded golang.org/x/sync v0.8.0 => v0.9.0
  * upgraded golang.org/x/sys v0.26.0 => v0.27.0
  * upgraded golang.org/x/text v0.19.0 => v0.20.0
  * upgraded golang.org/x/time v0.7.0 => v0.8.0
  * upgraded golang.org/x/tools v0.26.0 => v0.27.0

## v0.11.1

### :wrench: Bug fix

* Add missing lock that might affect the use of `tlsCertificates`.

## v0.11.0

### :star2: New features

* Add a configuration option to filter out logged data. See `LogFilter` in [config.go](https://github.com/c2FmZQ/tlsproxy/blob/main/proxy/config.go). This can be set at the top level config, the backend level config, or both.
* Add support for TLS certificates stored locally. See `tlsCertificates` in [config.go](https://github.com/c2FmZQ/tlsproxy/blob/main/proxy/config.go).

### :wrench: Misc

* Update go: 1.23.3
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20241008150032-332c0e1a4a34 => v0.0.0-20241101162523-b92577c0c142
  * upgraded github.com/onsi/ginkgo/v2 v2.20.2 => v2.21.0
  * upgraded go.uber.org/mock v0.4.0 => v0.5.0
  * upgraded golang.org/x/exp v0.0.0-20241004190924-225e2abe05e6 => v0.0.0-20241009180824-f66d83c29e7c
* Testing:
  * When testing with the `--use-ephemeral-certificate-manager` flag, the ephemeral CA cert and key will be saved if the `CERTMANAGER_STATE_FILE` environment variable is set.

## v0.10.9

### :wrench: Bug fix

* Another fix for `content-length: -1`. The change in v0.10.7 broke HTTP POST requests.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/quic-go/quic-go v0.47.0 => v0.48.1

## v0.10.8

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20240910150728-a0b0bb1d4134 => v0.0.0-20241008150032-332c0e1a4a34
  * upgraded github.com/pires/go-proxyproto v0.7.0 => v0.8.0
  * upgraded golang.org/x/crypto v0.27.0 => v0.28.0
  * upgraded golang.org/x/exp v0.0.0-20240909161429-701f63a606c0 => v0.0.0-20241004190924-225e2abe05e6
  * upgraded golang.org/x/net v0.29.0 => v0.30.0
  * upgraded golang.org/x/sys v0.25.0 => v0.26.0
  * upgraded golang.org/x/text v0.18.0 => v0.19.0
  * upgraded golang.org/x/time v0.6.0 => v0.7.0
  * upgraded golang.org/x/tools v0.25.0 => v0.26.0

## v0.10.7

### :wrench: Bug fix

* Don't send `content-length: -1` to backends. This caused `400` errors in some configurations. This bug was introduced in v0.10.6.

### :wrench: Misc

* Update go: 1.23.2

## v0.10.6

### :wrench: Misc

* Update to quic-go [v0.47.0](https://github.com/quic-go/quic-go/releases/tag/v0.47.0). The release notes point out that a bug in Go 1.23 is causing problems with QUIC. So, we're also setting go version in `go.mod` back to `1.22.0` for now.
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20240903155634-a8630aee4ab9 => v0.0.0-20240910150728-a0b0bb1d4134
  * upgraded github.com/quic-go/qpack v0.5.0 => v0.5.1
  * upgraded github.com/quic-go/quic-go v0.46.0 => v0.47.0
  * upgraded golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e => v0.0.0-20240909161429-701f63a606c0
  * upgraded golang.org/x/tools v0.24.0 => v0.25.0

## v0.10.5

### :wrench: Misc

* Update go: 1.23.1
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 => v0.0.0-20240903155634-a8630aee4ab9
  * upgraded github.com/onsi/ginkgo/v2 v2.19.1 => v2.20.2
  * upgraded github.com/quic-go/qpack v0.4.0 => v0.5.0
  * upgraded golang.org/x/crypto v0.26.0 => v0.27.0
  * upgraded golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 => v0.0.0-20240904232852-e7e105dedf7e
  * upgraded golang.org/x/mod v0.20.0 => v0.21.0
  * upgraded golang.org/x/net v0.28.0 => v0.29.0
  * upgraded golang.org/x/sys v0.23.0 => v0.25.0
  * upgraded golang.org/x/text v0.17.0 => v0.18.0
  * upgraded software.sslmate.com/src/go-pkcs12 v0.4.0 => v0.5.0

## v0.10.4

### :wrench: Misc

* Update go: 1.22.6
* Update go dependencies:
  * upgraded github.com/beevik/etree v1.4.0 => v1.4.1
  * upgraded github.com/google/pprof v0.0.0-20240625030939-27f56978b8b0 => v0.0.0-20240727154555-813a5fbdbec8
  * upgraded github.com/onsi/ginkgo/v2 v2.19.0 => v2.19.1
  * upgraded github.com/quic-go/quic-go v0.45.2 => v0.46.0
  * upgraded golang.org/x/crypto v0.25.0 => v0.26.0
  * upgraded golang.org/x/exp v0.0.0-20240707233637-46b078467d37 => v0.0.0-20240719175910-8a7402abbf56
  * upgraded golang.org/x/mod v0.19.0 => v0.20.0
  * upgraded golang.org/x/net v0.27.0 => v0.28.0
  * upgraded golang.org/x/sync v0.7.0 => v0.8.0
  * upgraded golang.org/x/sys v0.22.0 => v0.23.0
  * upgraded golang.org/x/text v0.16.0 => v0.17.0
  * upgraded golang.org/x/time v0.5.0 => v0.6.0
  * upgraded golang.org/x/tools v0.23.0 => v0.24.0

## v0.10.3

### :wrench: Misc

* Pick up bug fixes in the quic-go package.
* Update go dependencies:
  * upgraded github.com/quic-go/quic-go v0.45.1 => v0.45.2
  * upgraded golang.org/x/crypto v0.24.0 => v0.25.0
  * upgraded golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 => v0.0.0-20240707233637-46b078467d37
  * upgraded golang.org/x/mod v0.18.0 => v0.19.0
  * upgraded golang.org/x/net v0.26.0 => v0.27.0
  * upgraded golang.org/x/sys v0.21.0 => v0.22.0
  * upgraded golang.org/x/tools v0.22.0 => v0.23.0

## v0.10.2

### :wrench: Misc

* Same as v0.10.0. The v0.10.0 docker image was created before the Go linux/amd64 was ready. So, it used linux/386 instead. v0.10.2 should be OK.

## v0.10.1

### :wrench: Misc

* Same as v0.10.0. ~The v0.10.0 docker image was created before the golang linux/amd64 was ready. So, it used linux/386 instead. v0.10.1 should be OK.~

## v0.10.0

### :star: Feature improvements

* When `forwardHttpHeaders` is used, special keywords are automatically expanded from the header values:
  * `${NETWORK}` is either TCP or UDP.
  * `${LOCAL_ADDR}` is the local address of the network connection.
  * `${REMOTE_ADDR}` is the remote address of the network connection.
  * `${LOCAL_IP}` is the local IP address of the network connection.
  * `${REMOTE_IP}` is the remote IP address of the network connection.
  * `${SERVER_NAME}` is the Server Name requested by the client.
  * `${JWT:xxxx}` expands to the value of claim `xxxx` from the ID Token.

### :wrench: Misc

* Update go: 1.22.5
* Update go dependencies:
  * upgraded github.com/fxamacker/cbor/v2 v2.6.0 => v2.7.0
  * upgraded github.com/google/pprof v0.0.0-20240528025155-186aa0362fba => v0.0.0-20240625030939-27f56978b8b0
  * upgraded golang.org/x/exp v0.0.0-20240604190554-fc45aab8b7f8 => v0.0.0-20240613232115-7f521ea00fb8

## v0.9.1

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/quic-go/quic-go v0.45.0 => v0.45.1

## v0.9.0

### :star: Feature improvements

* Add `forwardHttpHeaders` to set HTTP headers in the forwarded HTTP requests. Headers that already exist are overwritten.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/c2FmZQ/storage v0.2.2 => v0.2.3
  * upgraded github.com/c2FmZQ/tpm v0.3.0 => v0.3.1
  * upgraded github.com/google/go-tpm-tools v0.4.3 => v0.4.4
  * upgraded github.com/google/go-tpm v0.9.0 => v0.9.1
  * upgraded github.com/quic-go/quic-go v0.44.0 => v0.45.0

## v0.8.3

### :wrench: Misc

* Update go: 1.22.4
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20240509144519-723abb6459b7 => v0.0.0-20240528025155-186aa0362fba
  * upgraded github.com/onsi/ginkgo/v2 v2.17.3 => v2.19.0
  * upgraded golang.org/x/crypto v0.23.0 => v0.24.0
  * upgraded golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 => v0.0.0-20240604190554-fc45aab8b7f8
  * upgraded golang.org/x/mod v0.17.0 => v0.18.0
  * upgraded golang.org/x/net v0.25.0 => v0.26.0
  * upgraded golang.org/x/sys v0.20.0 => v0.21.0
  * upgraded golang.org/x/text v0.15.0 => v0.16.0
  * upgraded golang.org/x/tools v0.21.0 => v0.22.0

## v0.8.2

### :wrench: Bug fix

* Sign OCSP responses with RSA or ECDSA keys.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/beevik/etree v1.3.0 => v1.4.0
  * upgraded github.com/google/pprof v0.0.0-20240507183855-6f11f98ebb1c => v0.0.0-20240509144519-723abb6459b7
  * upgraded github.com/quic-go/quic-go v0.43.1 => v0.44.0

## v0.8.1

### :star: Feature improvements

* Only allow GET and HEAD methods for static files.
* Sanitize the request path before comparing to local endpoints, e.g. `//.sso` redirects to `/.sso`.
* Add a `sanitizePath` option to backends. When true (default), request paths are sanitized before they are sent to the backends.

### :wrench: Misc

* Update go: 1.22.3
* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20240422182052-72c8669ad3e7 => v0.0.0-20240507183855-6f11f98ebb1c
  * upgraded github.com/onsi/ginkgo/v2 v2.17.1 => v2.17.3
  * upgraded golang.org/x/crypto v0.22.0 => v0.23.0
  * upgraded golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f => v0.0.0-20240506185415-9bf2ced13842
  * upgraded golang.org/x/net v0.24.0 => v0.25.0
  * upgraded golang.org/x/sys v0.19.0 => v0.20.0
  * upgraded golang.org/x/text v0.14.0 => v0.15.0
  * upgraded golang.org/x/tools v0.20.0 => v0.21.0

## v0.8.0

### :star2: New features

* Serve static files from a local filesystem when `documentRoot:` is set.

### :wrench: Misc

* Upgrade github.com/quic-go/quic-go v0.42.0 => v0.43.1

## v0.7.2

### :wrench: Misc

* Update the TPM library to pick up a bug fix. The saved TPM keys would become invalid after a reboot. This only affected configurations with `hwBacked: true`.

## v0.7.1

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/google/pprof v0.0.0-20240402174815-29b9bb013b0f => v0.0.0-20240422182052-72c8669ad3e7
  * upgraded golang.org/x/crypto v0.21.0 => v0.22.0
  * upgraded golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 => v0.0.0-20240416160154-fe59bbe5cc7f
  * upgraded golang.org/x/mod v0.16.0 => v0.17.0
  * upgraded golang.org/x/net v0.23.0 => v0.24.0
  * upgraded golang.org/x/sys v0.18.0 => v0.19.0
  * upgraded golang.org/x/tools v0.19.0 => v0.20.0

## v0.7.0

### :star2: New features

* Add `hwBacked` option. When enabled, hardware-backed cryptographic keys are used to:
  * encrypt local data (the data cannot be used or recovered on a different device),
  * sign authentication Tokens,
  * sign the PKI Certificates, OCSP responses, and CRLs.
* Add `--quiet` flag. When set (or the `TLSPROXY_QUIET` env variable is `true`), logging is turned off after TLSPROXY starts.

### :wrench: Misc

* Release binaries and container images are now signed.
* Update go: 1.22.2
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

* Starting with v0.6.0, TLSPROXY is built with QUIC & HTTP/3 support by default. Binaries without QUIC can still be built with `-tags noquic`.
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
* Fix bug that prevented logins with passkeys on non-default ports when ForceReAuth is set. (introduced in v0.4.4)
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
* Apply the forward rate limit to HTTP requests. Before, the rate limit was only applied to incoming connections.

## v0.4.3

* Add support for the OIDC `hd` param (https://developers.google.com/identity/openid-connect/openid-connect#hd-param).
* Return the proper TLS error when a QUIC client requests an unknown server name and/or alpn protocol.
* Return the proper TLS error when a client certificate is revoked.
* Refactor / improve the handling of QUIC connections.

## v0.4.2

* Minor changes to the Metrics page: combine runtime and memory profile, add Config.
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

* Add an option to automatically revoke unused _Let's Encrypt_ certificates.
* Add a flag to revoke all cached certificates. This is useful when a server is decommissioned or compromised.
* IDN fixes and tests

## v0.3.3

* Implement OCSP stapling.
* Verify the status of client and server certificates when OCSP servers are specified.
* Fix bug that prevented the PKI WASM client from loading on Chrome 119.
* Handle Internationalized Domain Names correctly.
* Add an option to refresh the identity used with passkeys (`refreshInterval`).

## v0.3.2

* Use the certificate provided by _Let's Encrypt_ to authenticate with backends when backends require client authentication.
* go: upgraded github.com/quic-go/quic-go v0.40.0 => v0.40.1 (CVE-2023-49295)

## v0.3.1

* Decouple frontend and backend protocols in `mode: HTTP` and `mode: HTTPS`. The ALPN protocols that TLSPROXY accepts are specified in `alpnProtos: [...]`, and the protocol to use with the request to the backend is specified with `backendProto: ...`, which defaults to `http/1.1`. The previous behavior was to use the same protocol that the client used. It is still possible to do that by setting `backendProto` explicitly to an empty string.
* Fix QUIC stream direction in metrics.
* Fix persistent config reload every 30 seconds in some conditions.

## v0.3.0

* Add support for the PROXY protocol defined by HAProxy. https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt
* Add QUIC and HTTP/3 support. See [docs/QUIC.md](https://github.com/c2FmZQ/tlsproxy/blob/main/docs/QUIC.md).
* Increase timeouts for proxied HTTP requests to 24 hours for large uploads or downloads.
* Update to go 1.21.5

## v0.2.0

* Add support for the HTTP/2 protocol in reverse proxy mode. This only works when the backend actually supports HTTP/2. So, it is not enabled by default. To enable it, set `alpnProtos: [h2, http/1.1]` on the backend explicitly.
* Add support for routing HTTP requests based on path. By default, all requests go to the same backend servers. When `pathOverrides` is set, some paths can be routed to other servers.

## v0.1.1

* Allow multiple backends with the same server name but different ALPN protocols, e.g. one backend could have foo.example.com with the default ALPN protocols, and another backend could have foo.example.com with `alpnProtos: [imap]`. If ALPN is not used by the client, the first backend with a matching server name will be used.

## v0.1.0

Let's call this the first _stable_ development release. We'll try to keep decent release notes going forward.

TLSPROXY is primarily a [TLS termination proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy) that uses Let's Encrypt to provide TLS encryption for any number of TCP or HTTP servers, and any number of server names concurrently on the same port.

Its functionality is similar to an [stunnel](https://www.stunnel.org/) server, but without the need to configure and run [Certbot](https://certbot.eff.org/) separately.

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
* [x] Use the same TCP address (IP Address:port) for any number of server names, e.g. foo.example.com and bar.example.com on the same xxx.xxx.xxx.xxx:443.

