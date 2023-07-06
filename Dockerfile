FROM golang:1.20.6-alpine3.18 AS build
MAINTAINER info@c2fmzq.org
RUN apk update && apk upgrade
RUN apk add ca-certificates

ADD go.mod /app/go/src/tlsproxy/go.mod
ADD go.sum /app/go/src/tlsproxy/go.sum
WORKDIR /app/go/src/tlsproxy
RUN go mod download

ADD proxy /app/go/src/tlsproxy/proxy
ADD internal /app/go/src/tlsproxy/internal
ADD version.sh /app/go/src/tlsproxy
WORKDIR /app/go/src/tlsproxy
RUN source version.sh && go install -ldflags="-s -w -X main.Version=${VERSION:-dev}" ./proxy

FROM scratch
WORKDIR /
COPY --from=build /etc/ssl /etc/ssl/
COPY --from=build /usr/share/ca-certificates /usr/share/ca-certificates/
COPY --from=build /go/bin/proxy /bin/

EXPOSE 10080 10443
VOLUME ["/config", "/.cache"]
USER 1000:1000

ENTRYPOINT ["/bin/proxy", "--config=/config/config.yaml"]
