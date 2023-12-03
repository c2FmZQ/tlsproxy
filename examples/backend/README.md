# Example backend with user authentication

Configure SSO and a backend:

config.yaml
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
  exportJwks: "/keys"

- serverNames:
  - test.EXAMPLE.COM
  mode: https
  insecureSkipVerify: true
  addresses:
  - 192.168.1.100:9443
  alpnProtos: [h3, h2, http/1.1]
  sso:
    provider: google
    generateIdTokens: true
```

Then run the example backend.

```console
cd examples/backend
go run . -addr :9443 --http3 --jwks-url https://login.EXAMPLE.COM/keys
```

And point your favorite browser at https://test.EXAMPLE.COM/
