# TLS Termination Proxy

This repo contains a simple lightweight [TLS termination proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy) that uses letsencrypt to provide TLS encryption for any number of TCP servers and server names concurrently on the same port.

Its functionality is similar to an [stunnel](https://www.stunnel.org/) server, but without the need to configure and run [certbot](https://certbot.eff.org/) separately. It is intended to work smoothly with [c2fmzq-server](https://github.com/c2FmZQ/c2FmZQ), and should work with any TCP server.

Example config:

```yaml
# The HTTP address must be reachable from the internet via port 80 for the
# letsencrypt ACME http-01 challenge to work. If the httpAddr is empty, the
# proxy will only use tls-alpn-01.
# See https://letsencrypt.org/docs/challenge-types/
httpAddr: ":10080"

# The TLS address will receive TLS connections and forward them to your
# backends.
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
  useTLS: true
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
  useTLS: true
  forwardServerName: secure-internal.example.com
```

See [example-config.yaml](https://github.com/c2FmZQ/tlsproxy/blob/main/example-config.yaml) and [internal/config.go](https://github.com/c2FmZQ/tlsproxy/blob/main/internal/config.go#L41) for more details.


Run the proxy with:
```console
go run ./proxy --config=config.yaml
```

Or, use the docker image, e.g.
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

Store the config in `${CONFIGDIR}/config.yaml`.

> :warning: `${CACHEDIR}` is used to store TLS secrets. It should only be accessible by the UID running tlsproxy.

