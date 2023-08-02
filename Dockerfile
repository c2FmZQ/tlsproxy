FROM golang:1.20.7-alpine3.18 AS build
MAINTAINER info@c2fmzq.org
RUN apk update && apk upgrade
RUN apk add ca-certificates

ADD . /app/go/src/tlsproxy
WORKDIR /app/go/src/tlsproxy
RUN go mod download
RUN source version.sh && go install -ldflags="-s -w -X main.Version=${VERSION:-dev}" .

FROM scratch
WORKDIR /
COPY --from=build /etc/ssl /etc/ssl/
COPY --from=build /usr/share/ca-certificates /usr/share/ca-certificates/
COPY --from=build /go/bin/tlsproxy /bin/

EXPOSE 10080 10443
USER 1000:1000
VOLUME ["/config", "/.cache"]

ENTRYPOINT ["/bin/tlsproxy", "--config=/config/config.yaml", "--stdout"]
