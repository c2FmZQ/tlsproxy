FROM golang:1.24.5-alpine3.21 AS build
RUN apk update && apk upgrade
RUN apk add ca-certificates bluefish

ADD . /app/go/src/tlsproxy
WORKDIR /app/go/src/tlsproxy
RUN go mod download
RUN go generate ./...
RUN source version.sh && go install -ldflags="-s -w -X main.Version=${VERSION:-dev}" -tags "${BUILD_TAGS}" .

FROM scratch
WORKDIR /
COPY --from=build /etc/ssl /etc/ssl/
COPY --from=build /usr/share/ca-certificates /usr/share/ca-certificates/
COPY --from=build /usr/share/mime/globs2 /usr/share/mime/
COPY --from=build /go/bin/tlsproxy /bin/

EXPOSE 10080 10443 10443/udp
USER 1000:1000
VOLUME ["/config", "/.cache"]
ENV GODEBUG="clobberfree=1,http2xconnect=0"

ENTRYPOINT ["/bin/tlsproxy", "--config=/config/config.yaml", "--stdout"]
