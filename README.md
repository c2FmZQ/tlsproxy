# TLS Termination Proxy

This repo contains a simple lightweight [TLS termination proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy) that uses letsencrypt to provide TLS encryption for any number of TCP servers and server names concurrently on the same port.

Its functionality is similar to an [stunnel](https://www.stunnel.org/) server, but without the need to configure and run [certbot](https://certbot.eff.org/) separately. It is intended to work smoothly with [c2fmzq-server](https://github.com/c2FmZQ/c2FmZQ), and should also work with any TCP server.

Overview of features:

* Use [Let's Encrypt](https://letsencrypt.org/) automatically to get TLS certificates (http-01 & tls-alpn-01).
* Terminate TLS connections, and forward the data to any TCP server in plaintext.
* Terminate TLS connections, and forward the data to any TLS server. The data is encrypted in transit, but the proxy sees the plaintext.
* Terminate _TCP_ connections, and forward the TLS connection to any TLS server (passthrough). The proxy doesn't see the plaintext.
* TLS client authentication & authorization (when the proxy terminates the TLS connections).
* Access control by IP address.
* Routing based on Server Name Indication (SNI), with optional default route when SNI isn't used.
* Simple round-robin load balancing between servers.
* Support for HTTP/2 and any ALPN protocol.
* Use the same TCP address (IPAddr:port) for any number of server names, e.g. xxx.xxx.xxx.xxx:443.

Example config:

```yaml
# The HTTP address must be reachable from the internet via port 80 for the
# letsencrypt ACME http-01 challenge to work. If the httpAddr is empty, the
# proxy will only use tls-alpn-01 and tlsAddr must be reachable on port 443.
# See https://letsencrypt.org/docs/challenge-types/
httpAddr: ":10080"

# The proxy will receive TLS connections at this address and forward them to
# the backends.
tlsAddr: ":10443"

# Each backend has a list of server names (DNS names that clients connect to),
# and addresses (where to forward connections).
backends:
- serverNames: 
  - example.com
  - www.example.com
  addresses: 
  - 192.168.0.10:80
  - 192.168.0.11:80
  - 192.168.0.12:80

- serverNames:
  - other.example.com
  addresses:
  - 192.168.1.100:443
  mode: TLS
  insecureSkipVerify: true

- serverNames:
  - secure.example.com
  clientAuth: true
  clientCAs: |
    -----BEGIN CERTIFICATE-----
    .....
    -----END CERTIFICATE-----
  addresses:
  - 192.168.2.200:443
  mode: TLS
  forwardServerName: secure-internal.example.com
```

See the [examples](https://github.com/c2FmZQ/tlsproxy/blob/main/examples) directory and [config.go](https://github.com/c2FmZQ/tlsproxy/blob/main/internal/config.go#L59) for more details.


Run the proxy with:
```console
go run ./proxy --config=config.yaml
```

Or, use the [docker image](https://hub.docker.com/r/c2fmzq/tlsproxy), e.g.
```console
docker run                      \
  --name=tlsproxy               \
  --user=1000:1000              \
  --restart=always              \
  --volume=${CONFIGDIR}:/config \
  --volume=${CACHEDIR}:/.cache  \
  --publish=80:10080            \
  --publish=443:10443           \
  c2fmzq/tlsproxy:latest
```

The proxy reads the config from `${CONFIGDIR}/config.yaml`.

> :warning: `${CACHEDIR}` is used to store TLS secrets. It should only be accessible by the UID running tlsproxy.

