#!/bin/bash

mkdir -p bin

export CGO_ENABLED=0
flag="-ldflags=-s -w -X main.Version=${GITHUB_REF_NAME:-dev}"
# tlsproxy
for os in darwin linux; do
  for arch in amd64 arm64; do
    GOOS="${os}" GOARCH="${arch}" go build -trimpath "${flag}" -o "bin/tlsproxy-${os}-${arch}" .
    sha256sum "bin/tlsproxy-${os}-${arch}" | cut -d " " -f1 > "bin/tlsproxy-${os}-${arch}.sha256"
  done
done
# tlsclient
for os in android darwin linux; do
  for arch in amd64 arm64; do
    GOOS="${os}" GOARCH="${arch}" go build -trimpath "${flag}" -o "bin/tlsclient-${os}-${arch}" ./tlsclient
    sha256sum "bin/tlsclient-${os}-${arch}" | cut -d " " -f1 > "bin/tlsclient-${os}-${arch}.sha256"
  done
done

ls -l bin/
