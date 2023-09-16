#!/bin/bash

mkdir bin

export CGO_ENABLED=0
flag="-ldflags=-s -w -X main.Version=${GITHUB_REF_NAME:-dev}"
for arch in amd64 arm arm64; do
  # tlsproxy, linux
  GOARCH="${arch}" go build -trimpath "${flag}" -o "bin/tlsproxy-linux-${arch}" .
  sha256sum "bin/tlsproxy-linux-${arch}" | cut -d " " -f1 > "bin/tlsproxy-linux-${arch}.sha256"
  # tlsclient, linux
  GOARCH="${arch}" go build -trimpath "${flag}" -o "bin/tlsclient-linux-${arch}" ./tlsclient
  sha256sum "bin/tlsclient-linux-${arch}" | cut -d " " -f1 > "bin/tlsclient-linux-${arch}.sha256"
done

ls -l bin/
