#!/bin/bash

mkdir -p bin

export CGO_ENABLED=0
export GOARM=7
flag="-ldflags=-s -w -X main.Version=${GITHUB_REF_NAME:-dev}"
# tlsproxy
for os in darwin linux; do
  for arch in amd64 arm64 arm; do
    echo "Building tlsproxy for ${os}-${arch}"
    GOOS="${os}" GOARCH="${arch}" go build -trimpath "${flag}" -o "bin/tlsproxy-${os}-${arch}" .
    if [[ $? == 0 ]]; then
      sha256sum "bin/tlsproxy-${os}-${arch}" | cut -d " " -f1 > "bin/tlsproxy-${os}-${arch}.sha256"
    fi
  done
done
# tlsclient
for os in android darwin linux; do
  for arch in amd64 arm64 arm; do
    echo "Building tlsclient for ${os}-${arch}"
    GOOS="${os}" GOARCH="${arch}" go build -trimpath "${flag}" -o "bin/tlsclient-${os}-${arch}" ./tlsclient
    if [[ $? == 0 ]]; then
      sha256sum "bin/tlsclient-${os}-${arch}" | cut -d " " -f1 > "bin/tlsclient-${os}-${arch}.sha256"
    fi
  done
done

ls -l bin/
