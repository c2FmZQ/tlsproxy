# Encrypted Client Hello (ECH)

ECH is a TLS extension that improves privacy by allowing the clients to encrypt Client Hello messages to protect the SNI, ALPN protocols, and other potentially sensitive information.

https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/

Note that enabling ECH is not sufficient to protect privacy. The ECH config list also needs to be published, e.g. via DNS, and the client needs to use secure DNS name resolution, e.g. using DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT).

## ECH Support in TLSPROXY

TLSPROXY has built-in support to generate ECH keys and configs. It can also publish the config list in different ways:

  * A local HTTPS endpoint
  * WebHooks
  * DNS update (for cloudflare-hosted domains)

Example:

All fields are optional, except `publicName`.

```yaml
ech:
  publicName: 'WWW.EXAMPLE.COM'
  endpoint: 'https://WWW.EXAMPLE.COM/.ech'
  interval: 48h
  webhooks:
  - 'https://WWW.EXAMPLE.ORG/SOME-WEBHOOK-URL'
  cloudflare:
  - zone: 'EXAMPLE.COM'
    token: 'API-TOKEN'
    names:
    - 'EXAMPLE.COM'
    - '*.EXAMPLE.COM'
```

Note: for DNS updates, the HTTPS records must already exist for TLSPROXY to update them automatically.
