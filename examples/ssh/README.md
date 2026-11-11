# SSH, SSH CA, sshterm, SSH Proxying

TLSPROXY can facilitate remote access with SSH in a variety of ways.

* It can proxy SSH connections over TLS. See [tlsclient](https://github.com/c2FmZQ/tlsproxy/tree/main/tlsclient#readme).
* It can proxy the [sshterm](https://github.com/c2FmZQ/sshterm#readme) web application and built-in jump host via `sshterm-server`.
* It can issue SSH Certificates with SSO credentials.

## SSH Certificate Authority

```yaml
sshCertificateAuthorities:
- name: "EXAMPLE SSH CA"
  keyType: ed25519
  # Optional: Publish the CA's public key.
  publicKeyEndpoint: https://ssh.example.com/ca
  # Users can request their own certificate.
  certificateEndpoint: https://ssh.example.com/cert
  maximumCertificateLifetime: 24h

backends:
- serverNames:
  - ssh.example.com
  mode: local

  # SSO must be enabled to use the SSH CA.
  sso:
    provider: sso-provider # definition omitted for this example
    rules:
    - acl:
      - alice@example.com
      - bob@example.com
```

## SSHTERM (`sshterm-server`)

The SSH CA and [`sshterm-server`](https://github.com/c2FmZQ/sshterm#readme) can be served on the same hostname (`ssh.example.com`). `tlsproxy` handles TLS, SSO authentication, and the `/ca` and `/cert` SSH CA endpoints locally, while forwarding the web app and WebSocket connections to `sshterm-server`.

### 1. `tlsproxy` Configuration (`data/tlsproxy/config/config.yaml`)

```yaml
httpAddr: ":10080"
tlsAddr: ":10443"

sshCertificateAuthorities:
- name: "EXAMPLE SSH CA"
  keyType: ed25519
  publicKeyEndpoint: https://ssh.example.com/ca
  certificateEndpoint: https://ssh.example.com/cert
  maximumCertificateLifetime: 24h

backends:
- serverNames:
  - ssh.example.com
  mode: http
  addresses:
  - sshterm-server:8080
  sso:
    provider: sso-provider # definition omitted for this example
    rules:
    - exceptions:
      - /ssh.webmanifest
      - /ssh.png
      acl:
      - alice@example.com
      - bob@example.com
```

### 2. `sshterm-server` Configuration (`data/sshterm/config.json`)

Configure `sshterm` to automatically generate an SSH key in the browser and obtain a signed user certificate from `tlsproxy`'s `/cert` endpoint:

```json
{
  "theme": "dark",
  "generateKeys": [
    {
      "name": "default",
      "type": "ed25519",
      "identityProvider": "./cert",
      "addToAgent": true
    }
  ]
}
```

### 3. Jump Host `authorized_keys` (`data/sshterm/authorized_keys`)

Download the SSH CA public key from `https://ssh.example.com/ca` and authorize principals and target hosts in `data/sshterm/authorized_keys` (and on the target SSH servers via `TrustedUserCAKeys`):

```text
cert-authority,principals="alice@example.com,bob@example.com",permitopen="host1.example.com:22,host2.example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... EXAMPLE SSH CA
```

### 4. `docker-compose.yaml`

The `sshterm-server` container can use `extra_hosts` to map the SSH servers' hostnames to their IP addresses:

```yaml
services:
  tlsproxy:
    container_name: tlsproxy
    image: c2fmzq/tlsproxy:latest
    user: 1000:1000
    environment:
      - TLSPROXY_PASSPHRASE=<secret passphrase>
    volumes:
      - ./data/tlsproxy/cache:/.cache
      - ./data/tlsproxy/config:/config:ro
    ports:
      - 80:10080
      - 443:10443
      - 443:10443/udp

  sshterm-server:
    container_name: sshterm-server
    image: c2fmzq/sshterm-server:latest
    user: 1000:1000
    command:
      - --config=/config/config.json
      - --authorized-keys=/config/authorized_keys
      - --host-key=/config/host_key
    volumes:
      - ./data/sshterm:/config:ro
    extra_hosts:
      - "host1.example.com:192.168.1.10"
      - "host2.example.com:192.168.1.11"
```

Generate a persistent jump host key before starting the containers:

```console
ssh-keygen -t ed25519 -N "" -f data/sshterm/host_key
```

Once running, open `https://ssh.example.com/` in your browser and connect directly to any permitted host (e.g. `ssh user@host1.example.com`); `sshterm` will automatically tunnel through the built-in `ssh.example.com-wss` jump host using the certificate issued by `tlsproxy`.
