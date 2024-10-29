# tlsproxy with docker compose

This example shows how to run tlsproxy with docker compose.

It spins up tlsproxy and 3 backends:
* [c2fmzq-server](https://github.com/c2FmZQ/c2FmZQ)
* [nginx](https://en.wikipedia.org/wiki/Nginx)
* [apache](https://en.wikipedia.org/wiki/Apache_HTTP_Server)

Before starting the docker containers, the we need to edit the tlsproxy config file, and change the permissions on the tlsproxy cache directory and the c2fmzq-server data directory.

## Edit data/tlsproxy/config/config.yaml

Using your favorite text editor, open `data/tlsproxy/config/config.yaml` and replace `example.com` with your own domain name. The hostnames must resolve to your IP address.

```yaml
httpAddr: ":10080"
tlsAddr: ":10443"

backends:
  - serverNames:
    - photos.example.com
    mode: http
    backendProto: h2
    addresses:
    - c2fmzq-server:8080

  - serverNames:
    - www.example.com
    mode: http
    addresses:
    - nginx:80

  - serverNames:
    - www2.example.com
    mode: http
    addresses:
    - apache:80
```

## Change directory permissions

The tlsproxy and c2fmzq-server processes don't run as root. Their directories need to be owned by a non-root user.

```console
mkdir -p examples/docker-compose/data/tlsproxy/cache
mkdir -p examples/docker-compose/data/c2fmzq-server
sudo chown 10001:10001 examples/docker-compose/data/tlsproxy/cache
sudo chown 10002:10002 examples/docker-compose/data/c2fmzq-server
```

## Start the services

Open `tlsproxy-docker.yaml` and replace `<secret passphrase>` with your own passphrase.

```yaml
services:
  tlsproxy:
    container_name: tlsproxy
    image: c2fmzq/tlsproxy:latest
    user: 10001:10001
    volumes:
      - ./data/tlsproxy/cache:/.cache
      - ./data/tlsproxy/config:/config
    ports:
      - 80:10080
      - 443:10443

  c2fmzq-server:
    container_name: c2fmzq-server
    image: c2fmzq/c2fmzq-server:latest
    user: 10002:10002
    environment:
      - C2FMZQ_ADDRESS=:8080
      - C2FMZQ_ALLOW_NEW_ACCOUNTS=true
      - C2FMZQ_AUTO_APPROVE_NEW_ACCOUNTS=true
      - C2FMZQ_PASSPHRASE=<secret passphrase>    <= CHANGE THIS
      - C2FMZQ_PASSPHRASE_FILE=
    volumes:
      - ./data/c2fmzq-server:/data

  nginx:
    container_name: nginx
    image: nginx:latest
    volumes:
      - ./data/nginx:/usr/share/nginx/html:ro

  apache:
    container_name: apache
    image: httpd:latest
    volumes:
      - ./data/apache:/usr/local/apache2/htdocs:ro
```

Then, start the services:
```console
docker compose -f examples/docker-compose/tlsproxy-docker.yaml up
```

When the services are running, open the server names specified in `config.yaml` with your favorite browser.

## Clean up

When you're done, stop the services and remove the containers.
```console
docker compose -f examples/docker-compose/tlsproxy-docker.yaml stop
docker compose -f examples/docker-compose/tlsproxy-docker.yaml rm -f
```
