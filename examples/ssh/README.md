# SSH, SSH CA, sshterm, SSH Proxying

TLSPROXY can facilitate remote access with SSH in a variety of ways.

* It can proxy SSH connections over TLS. See [tlsclient](https://github.com/c2FmZQ/tlsproxy/tree/main/tlsclient#readme).
* It can run a SSH client in a web browser. See [sshterm](https://github.com/c2FmZQ/sshterm#readme).
* It can issue SSH Certificates with SSO credentials.

## SSH Certificate Authority

```yaml
sshCertificateAuthority:
- name: "EXAMPLE SSH CA"
  # Optional: Publish the CA's public key.
  publicKeyEndpoint:
  - https://ssh.example.com/ca
  # Users can request their own certificate.
  certificateEndpoint: https://ssh.example.com/cert

backends:
- serverNames:
  - ssh.example.com
  mode: local

  # SSO must be enabled to use the SSH CA.
  sso:
    provider: sso-provider # definition omitted for this example
    # Optional: The ACL controls who has access to request certificates.
    acl:
    - alice@example.com
    - bob@example.com
```

## SSHTERM

The SSH CA and the [sshterm](https://github.com/c2FmZQ/sshterm#readme) app can
be served on the same server name. The docroot files must be installed first.

```
backends:
- serverNames:
  - ssh.example.com
  mode: local
  sso:
    provider: sso-provider # definition omitted for this example
    exceptions:
    - /ssh.webmanifest
    - /ssh.png
  # See the sshterm documentation.
  documentRoot: /path/to/sshterm/docroot

webSockets:
- endpoint: wss://ssh.example.com/myserver
  address: 192.168.0.100:22
```

The sshterm app can also use the SSH CA automatically so that the client's public
key doesn't need to be copied manually.
