# User authentication with OpenID Connect and SAML

TLSPROXY can be configured to authenticate users with OpenID Connect and SAML identity providers.

OpenID Connect has been tested with Google and Facebook as identity providers.
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
