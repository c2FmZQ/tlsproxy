# User Authentication

Simplified sequence diagrams representing the OIDC and SAML authentication flows.

Refer to the [SSO example](https://github.com/c2FmZQ/tlsproxy/blob/main/examples/sso/README.md) and the [Config godoc](https://pkg.go.dev/github.com/c2FmZQ/tlsproxy/proxy#Config).

## OIDC Flow

```mermaid
sequenceDiagram
  participant IDP as IDENTITY PROVIDER<br>e.g. Google
  actor A as User
  participant PRX as TLSPROXY
  participant BE as BACKEND SERVICE

  A->>PRX: GET https://www.example.com/
  PRX->>A: 302 IDP AuthEndpoint
  A->>IDP: AuthEndpoint
  A-->>IDP: Consent
  IDP->>A: 302 PRX RedirectURL w/ code
  A->>PRX: RedirectURL w/ code

  PRX->>IDP: TokenEndpoint w/ code + ClientSecret
  IDP->>PRX: ID Token (JWT)

  Note over PRX: Parse JWT<br>Create new Auth Token
  PRX->>A: SetCookie TLSPROXYAUTH(domain=example.com), 302 Original URL
  A->>PRX: GET https://www.example.com/

  Note over PRX: Validate TLSPROXYAUTH cookie<br>Create new ID TOKEN
  PRX->>A: SetCookie TLSPROXYIDTOKEN(domain=www.example.com), 302 Original URL
  A->>PRX: GET https://www.example.com/
  Note over PRX: Validate TLSPROXYAUTH cookie<br>Validate TLSPROXYIDTOKEN cookie<br>Filter out TLSPROXYAUTH cookie<br>Set x-tlsproxy-user-id header

  PRX->>BE: GET https://www.example.com/
  BE->>PRX: Response
  PRX->>A: Response
```

## SAML Flow

```mermaid
sequenceDiagram
  participant IDP as IDENTITY PROVIDER<br>e.g. Google
  actor A as User
  participant PRX as TLSPROXY
  participant BE as BACKEND SERVICE

  A->>PRX: GET https://www.example.com/
  PRX->>A: 302 IDP SSOURL
  A->>IDP: SSOURL
  A-->>IDP: Consent
  IDP->>A: POST PRX ACSURL w/ Signed Assertion
  A->>PRX: POST PRX ACSURL w/ Signed Assertion

  Note over PRX: Validate Assertion<br>Create new Auth Token
  PRX->>A: SetCookie TLSPROXYAUTH(domain=example.com), 302 Original URL
  A->>PRX: GET https://www.example.com/

  Note over PRX: Validate TLSPROXYAUTH cookie<br>Create new ID TOKEN
  PRX->>A: SetCookie TLSPROXYIDTOKEN(domain=www.example.com), 302 Original URL
  A->>PRX: GET https://www.example.com/
  Note over PRX: Validate TLSPROXYAUTH cookie<br>Validate TLSPROXYIDTOKEN cookie<br>Filter out TLSPROXYAUTH cookie<br>Set x-tlsproxy-user-id header

  PRX->>BE: GET https://www.example.com/
  BE->>PRX: Response
  PRX->>A: Response
```

## Cookies

The values of the `TLSPROXYAUTH` and `TLSPROXYIDTOKEN` cookies are JSON Web Tokens (JWT) signed by tlsproxy itself.

`TLSPROXYAUTH` is used to authenticate with tlsproxy. It is not forwarded to the backend services.

`TLSPROXYIDTOKEN` is used to authenticate with the backend services. It is set and validated by tlsproxy. The backend services can also validate it using the JSON Web Key Set (JWKS) exported by tlsproxy.

The ID Token can also be passed in the `Authorization` http header as a bearer token.
