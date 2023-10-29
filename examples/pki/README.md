# PKI, built-in Certificate Authority

TLSPROXY has built-in support for managing X.509 Certificates.

```yaml
pki:
- name: "EXAMPLE CA"
  # Optional: Publish the CA's certificate(s).
  issuingCertificateUrls:
  - https://pki.example.com/ca.pem
  # Optional: Publish the CA's Revocation List.
  crlDistributionPoints:
  - https://pki.example.com/crl.pem
  # Optional: Enable OCSP (Online Certificate Status Protocol).
  ocspServers:
  - https://pki.example.com/ocsp
  # Users can manage their own certificates with this endpoint.
  endpoint: https://pki-internal.example.com/certs
  # Optional: Admins can revoke anybody's certificates.
  admins:
  - bob@example.com

backends:
# Optional: Use a server name to publich the CA's certificate and Revocation
# List.
- serverNames:
  - pki.example.com
  mode: local

# This server name is used to manage certificates. 
- serverNames:
  - pki-internal.example.com
  mode: local
  allowIPs:
  - 192.168.0.0/24
  sso:
    provider: sso-provider # definition omitted for this example
    forceReAuth: 1h
    # The ACL controls who has access to issue and revoke certificates for
    # themselves.
    acl:
    - alice@example.com
    - bob@example.com

# Then use EXAMPLE CA to authenticate and authorize TLS clients.
- serverNames:
  - secure.example.com
  clientAuth:
  - rootCAs:
    - "EXAMPLE CA"
    acl:
    - EMAIL:alice@example.com
    - EMAIL:bob@example.com
```
