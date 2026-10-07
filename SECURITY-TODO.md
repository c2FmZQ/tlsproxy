# Security review TODO

Findings from the security review on 2026-10-06. Ordered by severity.
Each item is checked off when fixed (or explicitly declined). This file is
deleted when every item is resolved.

## Critical / High

- [x] **1. SSO rule bypass with dot-segments** (Critical)
  *Fixed: rules match only the cleaned path. `sanitizePath: false` still
  forwards the raw path unchanged (by decision).*
  `proxy/backend-sso.go` `pathMatches`/`findSSORule` match `Paths` and
  `Exceptions` against the raw path *or* the cleaned path, but the request is
  forwarded with the cleaned path (`sanitizePath` default). With
  `exceptions: ["/public/"]`, `GET /public/../admin` (or `/public/%2e%2e/admin`)
  skips SSO and the backend receives `/admin`. With ordered rules,
  `/public/../private` picks the permissive `/public/` rule (ACL bypass).
  Fix: match only on the cleaned path; make sure the path that is checked is
  the path that is forwarded, also when `sanitizePath: false`.

- [x] **2. Bearer tokens with local `iss` accepted when signed by any trusted issuer's key** (High)
  *Fixed: `ValidateToken` only uses local keys; trusted-issuer tokens go
  through `ValidateRemoteToken`, which requires the key to belong to `iss`.
  Bearer and ID token cookies require `exp`. `jwksUri` must be https.*
  `proxy/internal/tokenmanager/tokenmanager.go` `ValidateToken`/`getKey` fall
  back to the global remote key set (union of every provider's
  `trustedIssuers`) and only check `iss == local issuer`. `exp` is not
  required. A token with no `scope` claim passes every scope check. Reached via
  `cookiemanager.ValidateAuthorizationHeader`.
  Fix: bind `kid` to its issuer; local keys only for the local issuer; require
  `exp`; require `https` for `jwksUri` in `validateTrustedIssuers`.

- [x] **3. SSH CA issues certificates that never expire** (High)
  *Fixed: `ttl <= 0` or non-numeric returns 400; `ttl` is capped at the
  maximum lifetime before converting to a duration.*
  `proxy/internal/sshca/sshca.go` `ServeCertificate`: `ttl` form value is not
  checked for `<= 0` or overflow. `min(max, ttl)` doesn't cap negatives, and the
  negative `ValidBefore` wraps to a huge `uint64`. OpenSSH sshd accepts it.
  Fix: reject `tt <= 0`, clamp before multiplying, check `ValidBefore > now`.

## Medium

- [x] **4. HTTP/3 backend request crashes the process** (Medium)
  *Fixed: delegate to `c.qc`; added `TestH3Backend`.*
  `proxy/internal/netw/quic.go`: `QUICConn.HandshakeComplete` and
  `NextConnection` call themselves (stack overflow, unrecoverable). Triggered
  by any request forwarded over h3 (`backendProto: h3`, or empty
  `backendProto` with an h3 client).
  Fix: delegate to `c.qc`; add a test with `BackendProto: "h3"`.

- [x] **5. Host header not checked against `ServerNames` before authentication** (Medium)
  *Fixed: `checkRequestHost` returns 421 before authentication in both
  `localHandler` and `reverseProxy`.*
  `proxy/backend-http.go`: `localHandler()` never checks Host; in
  `reverseProxy()` the 421 check runs after `authenticateUser` and
  `handleLocalEndpointsAndAuthorize`. The Bearer token audience
  (`cookiemanager.audienceFromReq`), the ForceReAuth `hhash`, and the URL
  token URL all come from the client-controlled Host. A malicious backend can
  replay visitors' ID tokens (`TLSPROXYIDTOKEN`) against a sibling backend with
  `Host: <its own name>`.
  Fix: reject Host not in `be.ServerNames` at the top of both handlers.

- [x] **6. OCSP checks bypassable with a forged stapled response** (Medium)
  *Fixed: `parseResponse` requires the responder to be the issuer or have
  the OCSPSigning EKU, binds to the cert serial, and checks
  `ThisUpdate`/`NextUpdate` for both stapled and fetched responses. A
  staple only replaces a cached response if it is newer.*
  `proxy/internal/ocspcache/ocsp.go`: `ocsp.ParseResponseForCert` accepts an
  embedded responder cert without the `OCSPSigning` EKU, so any cert from the
  same CA (even the revoked one) can sign "Good". Stapled responses (including
  client-cert staples) are cached and persisted until the attacker-chosen
  `NextUpdate`. The fetched path uses `ocsp.ParseResponse` without checking
  serial or freshness. Affects external CAs (`clientAuth.rootCAs`,
  `forwardRootCAs`, system roots).
  Fix: require responder == issuer or OCSPSigning EKU; use
  `ParseResponseForCert` on fetch; check `ThisUpdate`/`NextUpdate`; don't
  trust or cache client-supplied staples.

- [x] **7. PKI users can get serverAuth certs for any DNS name** (Medium)
  *Fixed (by decision): new `pki[].serverCertificates` allowlist
  (`dnsNames` patterns + optional `acl`). Without it, server certificates
  are denied. **Breaking change: needs a release note.** CA name
  constraints were not added (they'd require re-issuing existing CAs).*
  `proxy/internal/pki/http.go` copies CSR `DNSNames` unchecked; `pki.go` adds
  `ServerAuth` EKU. Any PKI user can get a cert for `*.example.com` or a
  backend's name, which matters if the CA is in `forwardRootCAs`.
  Fix: restrict DNS SANs (allowlist/suffix per user or admins only), reject
  wildcards, consider CA name constraints.

- [x] **8. Port 80 (ACME) HTTP server has no timeouts or connection limit** (Medium)
  *Fixed: 10s read/write timeouts and at most min(MaxOpen, 1000)
  concurrent connections.*
  `proxy/proxy.go` `Start()`: `http.Server{Handler: certManager.HTTPHandler}`
  has no Read/ReadHeader/Write/Idle timeouts and isn't counted in `MaxOpen`.
  Idle connections are held forever and exhaust file descriptors.
  Fix: set timeouts and cap concurrent connections.

- [x] **9. Unauthenticated DoS of the local OIDC provider via device authorization** (Medium)
  *Fixed: `vacuum()` scans at most every 30s, lookups check expiry
  themselves, and pending authorization/device requests are capped at
  10000 (503 beyond). Client secret is not required for device
  authorization (unchanged).*
  `proxy/internal/oidc/deviceauth.go`, `server.go` `vacuum()`: each POST to
  `/device/authorization` with a (public) `client_id` adds map entries for 10
  minutes; every OIDC request runs `vacuum()` which scans all maps under
  `s.mu` (quadratic). Local handlers aren't rate limited.
  Fix: cap map sizes, expire entries off the request path, optionally require
  the client secret.

## Low–Medium

- [x] **10. Open redirect after login via Host header in URL token** (Low–Medium)
  *Fixed: Host is validated first (#5); `serveLogin`/`serveLogout` require
  the token URL host to be one of the backend's server names; URL tokens
  expire after 24h.*
  `proxy/backend-sso.go`: the URL token URL is built from `req.Host` before any
  Host check; `serveLogin`/`serveLogout` don't validate the token URL's host.
  Needs the victim's `__tlsproxySid` (same on every host, not HttpOnly,
  forwarded to backends). URL tokens never expire.
  Fix: #5, plus require the token URL host to be in `be.ServerNames`; add an
  expiry to URL tokens.

- [ ] **11. Open redirect with `//evil.com` paths** (Low–Medium)
  `proxy/backend-sso.go` (ID token cookie reissue:
  `http.Redirect(w, req, req.URL.String(), 302)`), and the same pattern in
  `proxy/internal/passkeys/manager.go` (2 places). `GET //evil.com/x` redirects
  to `//evil.com/x`.
  Fix: build the redirect from the cleaned path + query.

- [ ] **12. SAML login CSRF / session swapping** (Low–Medium)
  `proxy/internal/saml/saml.go`: `InResponseTo` is checked against server state
  only, not bound to the browser (OIDC uses the `TLSPROXYNONCE` cookie). An
  attacker can submit their own signed response in the victim's browser.
  Fix: short-lived host-only `SameSite=None; Secure; HttpOnly` cookie bound to
  the request ID, checked in `HandleCallback`.

- [ ] **13. Unbounded `events` map growth from attacker-chosen SNI** (Low–Medium)
  `proxy/proxy.go` `handleConnection`: ECH accepted/rejected events include the
  outer SNI and are recorded before the backend lookup. ECH needn't be
  configured.
  Fix: record after a successful backend lookup, or drop the SNI from the
  event name.

## Low

- [ ] **14. Spoofable forwarding/identity headers** (Low)
  `proxy/backend-sso.go`, `proxy/backend-http.go` `reverseProxyDirector`:
  `X_tlsproxy_user_id` (underscore variant) and underscore variants of
  `forwardHttpHeaders` keys aren't stripped (CGI-style backends map `_`/`-` to
  the same variable). Client-supplied `X-Forwarded-Host`, `X-Forwarded-Proto`
  and `Forwarded` reach the backend.
  Fix: drop inbound headers that normalize to a proxy-owned header name;
  strip/set `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`.

- [ ] **15. Local handler scopes skipped when no SSO rule matches** (Low)
  `proxy/backend-sso.go` `enforceSSOPolicy` returns true when `rule == nil`
  before checking `overrideScopes`. PKI/SSH/OIDC endpoints then accept tokens
  without the `pki`/`ssh` scope when rules don't cover their paths.
  Fix: still check `overrideScopes` when no rule matches.

- [ ] **16. Unbounded login-state maps in OIDC RP, SAML and passkeys** (Low)
  `oidc/client.go`, `saml/saml.go`, `passkeys/manager.go`: state (including an
  attacker-sized `OriginalURL`) is only expired inside `HandleCallback`.
  Fix: periodic expiry and a size cap.

- [ ] **17. Passkey assertion doesn't check `clientData.origin`** (Low)
  `proxy/internal/passkeys/manager.go` `processAssertion` (registration does
  check it). A subdomain page can obtain an assertion for the RP ID.
  Fix: require the expected origin.

- [ ] **18. OIDC consent approval not bound to the user who started the request** (Low)
  `proxy/internal/oidc/server.go`: `AuthorizeClient` and scope filtering run on
  the GET; the token is minted for whoever POSTs the `request_id`.
  Fix: store the user in `codeData`, require a match on POST, re-run
  `AuthorizeClient` and scope filtering.

- [ ] **19. Device flow phishing and clickjacking hardening** (Low)
  `oidc/verify-template.html`, `authorize-template.html`, `deviceauth.go`: the
  verify page doesn't show the client or scopes; no `X-Frame-Options` /
  `frame-ancestors` on consent and device pages; `verification_uri_complete`
  pre-fills the code.
  Fix: show client and scopes, add framing protection, consider requiring the
  code to be typed.

- [ ] **20. Passkey account enumeration** (Low)
  `proxy/internal/passkeys/manager.go`: `AssertionOptions` returns real
  credential IDs for known emails and a fake 1-byte ID otherwise.
  Fix: deterministic realistic fake IDs (HMAC of email), or an empty allow
  list.

- [ ] **21. `/.sso/` on a backend without SSO panics** (Low)
  `proxy/backend-sso.go` `serveSSOStatus` dereferences `be.SSO` when nil. The
  panic is recovered but logs a full stack trace per request.
  Fix: check `be.SSO == nil`.

- [ ] **22. Built-in PKI CRL staleness and data race** (Low)
  `proxy/internal/pki/pki.go`: the cached CRL is reused up to 30m past
  `NextUpdate`; same-second revocations can be missed by the
  `ThisUpdate.Before(lastRevocation)` check. `maybeRotateDelegateCert` reads
  `m.db` without `m.mu` (called from unauthenticated OCSP/CRL handlers).
  Fix: regenerate earlier / on every revocation; take the lock.

## Hardening / Info

- [ ] **23.** CSRF check is skipped whenever any `Authorization` header is
  present, even if it isn't a valid Bearer token and auth falls back to
  cookies (`proxy/internal/csrf/csrf.go`).
- [ ] **24.** OIDC client secret compared with `==` instead of a constant-time
  compare (`proxy/internal/oidc/server.go`).
- [ ] **25.** OIDC token endpoint doesn't compare `redirect_uri` with the one
  used in the authorization request (RFC 6749 §4.1.3) and ignores PKCE.
- [ ] **26.** OIDC RP accepts a missing `email_verified`
  (`oidc/client.go`); the local OP then asserts `email_verified: true`.
- [ ] **27.** WebAuthn signature counter is ignored.
- [ ] **28.** Revoking a cert doesn't close connections already open with it
  (`reAuthorize` only re-checks ACLs, only on reconfigure).
- [ ] **29.** SSH CA accepts DSA keys (`sshca.go`).
- [ ] **30.** SSH CA holds `ca.mu` while reading the request body; a slow
  upload blocks all issuance.
- [ ] **31.** `tlsclient -ocsp` uses `PeerCertificates[1]` as the issuer
  instead of `VerifiedChains[0][1]` (`tlsclient/main.go`).
- [ ] **32.** `--passphrase` flag is visible in `/proc/*/cmdline`
  (`main.go`); `TLSPROXY_PASSPHRASE` is the safer route.
- [ ] **33.** QUIC `GetConfigForClient` logs SNI and ALPN with `%s` (log
  injection); use `%q` (`proxy/quic.go`).
- [ ] **34.** Connection-level DoS: no per-IP limit, 2-minute handshake
  timeout, per-backend `connLimit.Wait` with no deadline before
  authentication, non-h3 QUIC streams skip the first-request rate limit.
- [ ] **35.** `runtime.MemProfileRate = 1` in `metrics.go` `init()` profiles
  every allocation process-wide.
- [ ] **36.** Data race: `handleConnection` reads `p.echKeys` without `p.mu`.
- [ ] **37.** `oidc/client.go` `HandleCallback` shadows `req` with the token
  endpoint request, so the `th` session-chain claim is never carried over
  (functional bug).
- [ ] **38.** Metrics page config dump doesn't redact `forwardHttpHeaders`
  values or webhook URLs.
- [ ] **39.** `proxy.mjs` global `fetch` wrapper sends the sid as
  `x-csrf-token` to cross-origin URLs.
- [ ] **40.** `emailMatches` treats an ACL entry equal to the email string as a
  match, so a group name could match an IdP-asserted "email" of the same
  value.
- [ ] **41.** OCSP delegate cert has `IsCA: true` (`pki.go`); not needed.
- [ ] **42.** PKI `?owner=all` lists every user's certs to any user with the
  `pki` scope (may be intended).
- [ ] **43.** `certmanager` (test-only) generates and caches an RSA key per SNI
  name without bound.
- [ ] **44.** OIDC RP nonce cookie is scoped to the parent domain, so an
  attacker-controlled subdomain can toss it (login CSRF).
