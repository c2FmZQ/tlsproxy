# User authentication with OpenID Connect, SAML and/or Passkeys

TLSPROXY can be configured to authenticate users with OpenID Connect and SAML identity providers. Another option is to use Passkeys for password-less user authentication. To configure Passkeys, users still need to authenticate once with OpenID Connect or SAML, but then authentication is done exclusively with Passkeys.

OpenID Connect has been tested with Google, Facebook, SimpleLogin, and GitHub as identity providers.

SAML has been tested with Google Workspace.

## Google OpenID Connect

https://developers.google.com/identity/openid-connect/openid-connect

```yaml
oidc:
- name: google
  authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"
  tokenEndpoint: "https://oauth2.googleapis.com/token"
  redirectUrl: "https://login.EXAMPLE.COM/oidc/google"
  clientId: "<YOUR CLIENT ID>"
  clientSecret: "<YOUR CLIENT SECRET>"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - login.EXAMPLE.COM
  mode: https

- serverNames:
  - www.EXAMPLE.COM
  mode: http
  addresses:
  - 192.168.1.1:80
  sso:
    provider: google
    acl:
      - alice@EXAMPLE.COM
      - bob@EXAMPLE.COM
      - "@EXAMPLE.COM"   <--- allows anyone from EXAMPLE.COM
```

## Facebook OpenID Connect

https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow

```yaml
oidc:
- name: facebook
  authorizationEndpoint: "https://facebook.com/v17.0/dialog/oauth/"
  tokenEndpoint: "https://graph.facebook.com/v17.0/oauth/access_token"
  redirectUrl: "https://login.EXAMPLE.COM/oidc/facebook"
  clientId: "<YOUR APP ID>"
  clientSecret: "<YOUR APP SECRET>"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - login.EXAMPLE.COM
  mode: https

- serverNames:
  - www.EXAMPLE.COM
  mode: http
  addresses:
  - 192.168.1.1:80
  sso:
    provider: facebook
    acl:
      - alice@EXAMPLE.COM
      - bob@EXAMPLE.COM
      - "@EXAMPLE.COM"   <--- allows anyone from EXAMPLE.COM
```

## SimpleLogin OpenID Connect (SIWSL)

https://simplelogin.io/docs/siwsl/app/

```yaml
oidc:
- name: siwsl
  authorizationEndpoint: "https://app.simplelogin.io/oauth2/authorize"
  tokenEndpoint: "https://app.simplelogin.io/oauth2/token"
  redirectUrl: "https://login.EXAMPLE.COM/oidc/siwsl"
  clientId: "<YOUR APP ID>"
  clientSecret: "<YOUR APP SECRET>"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - login.EXAMPLE.COM
  mode: https

- serverNames:
  - www.EXAMPLE.COM
  mode: http
  addresses:
  - 192.168.1.1:80
  sso:
    provider: siwsl
    acl:
      - alice@EXAMPLE.COM
      - bob@EXAMPLE.COM
      - "@EXAMPLE.COM"   <--- allows anyone from EXAMPLE.COM
```

## GitHub OAuth2

GitHub doesn't implement OpenID Connect, but their OAuth2 workflow can be used with TLSPROXY to retrieve the user's identity.

https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

```yaml
oidc:
- name: github
  authorizationEndpoint: "https://github.com/login/oauth/authorize"
  tokenEndpoint: "https://github.com/login/oauth/access_token"
  userinfoEndpoint: "https://api.github.com/user"
  scopes:
  - "user:email"
  redirectUrl: "https://login.EXAMPLE.COM/oauth2/github"
  clientId: "<YOUR CLIENT ID>"
  clientSecret: "<YOUR CLIENT SECRET>"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - login.EXAMPLE.COM
  mode: https

- serverNames:
  - www.EXAMPLE.COM
  mode: http
  addresses:
  - 192.168.1.1:80
  sso:
    provider: github
    acl:
      - alice@EXAMPLE.COM
      - bob@EXAMPLE.COM
      - "@EXAMPLE.COM"   <--- allows anyone from EXAMPLE.COM
```

## Google Workspace SAML SSO

https://support.google.com/a/answer/6087519?hl=en

```yaml
saml:
- name: google-saml
  ssoUrl: https://accounts.google.com/o/saml2/idp?idpid=<YOUR APP ID>
  entityId: https://login.EXAMPLE.COM/
  certs: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  acsUrl: "https://login.EXAMPLE.COM/saml"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - login.EXAMPLE.COM
  mode: https

- serverNames:
  - www.EXAMPLE.COM
  mode: http
  addresses:
  - 192.168.1.1:80
  sso:
    provider: google-saml
    acl:
      - alice@EXAMPLE.COM
      - bob@EXAMPLE.COM
      - "@EXAMPLE.COM"   <--- allows anyone from EXAMPLE.COM
```

## Passkeys with initial authentication with Google OpenID Connect

```yaml
oidc:
- name: google
  authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"
  tokenEndpoint: "https://oauth2.googleapis.com/token"
  redirectUrl: "https://login.EXAMPLE.COM/oidc/google"
  clientId: "<YOUR CLIENT ID>"
  clientSecret: "<YOUR CLIENT SECRET>"
  domain: "EXAMPLE.COM"

passkey:
- name: "passkey"
  identityProvider: "google"
  endpoint: "https://login.EXAMPLE.COM/passkey"
  domain: "EXAMPLE.COM"

backends:
- serverNames:
  - login.EXAMPLE.COM
  mode: https

- serverNames:
  - www.EXAMPLE.COM
  mode: http
  addresses:
  - 192.168.1.1:80
  sso:
    provider: passkey
    acl:
      - alice@EXAMPLE.COM
      - bob@EXAMPLE.COM
      - "@EXAMPLE.COM"   <--- allows anyone from EXAMPLE.COM
```

