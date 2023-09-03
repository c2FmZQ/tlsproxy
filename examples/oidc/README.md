# User authentication with OpenID Connect

TLSPROXY can be configured to authenticate users with an OpenID Connect provider.

This feature has been tested with Google and Facebook as identity providers. Other OIDC compliant identity providers should also work.

## Using Google

https://developers.google.com/identity/openid-connect/openid-connect

```yaml
acceptTOS: true

oidc:
- name: google
  authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"
  tokenEndpoint: "https://oauth2.googleapis.com/token"
  redirectUrl: "https://oauth2.EXAMPLE.COM/redirect"
  clientId: "<YOUR CLIENT ID>"
  clientSecret: "<YOUR CLIENT SECRET>"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - oauth2.EXAMPLE.COM
  mode: https
  sso:
    provider: google

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

## Using Facebook

https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow

```yaml
acceptTOS: true

oidc:
- name: facebook
  authorizationEndpoint: "https://facebook.com/v17.0/dialog/oauth/"
  tokenEndpoint: "https://graph.facebook.com/v17.0/oauth/access_token"
  redirectUrl: "https://oauth2.EXAMPLE.COM/redirect"
  clientId: "<YOUR APP ID>"
  clientSecret: "<YOUR APP SECRET>"
  domain: EXAMPLE.COM

backends:
- serverNames:
  - oauth2.EXAMPLE.COM
  mode: https
  sso:
    provider: facebook

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
