#!/bin/bash

mkdir -p bin

go generate ./...

sign() {
  local name="$1"
  if [[ -n "${GPG_PASSPHRASE}" ]]; then
    gpg --batch --pinentry-mode loopback --yes --passphrase "${GPG_PASSPHRASE}" --detach-sig --local-user c2FmZQ-bot --output "${name}.sig" "${name}"
  fi
}

export CGO_ENABLED=0
export GOARM=7
flag="-ldflags=-extldflags=-static -s -w -X main.Version=${GITHUB_REF_NAME:-dev}"
tags="$(echo "${GITHUB_REF_NAME:-dev}" | sed -re 's/^v[^+]+[+]?//' -e 's/[.]/,/g')"
# tlsproxy
for os in darwin linux; do
  for arch in amd64 arm64 arm; do
    basename="bin/tlsproxy-${os}-${arch}"
    echo "Building ${basename}"
    GOOS="${os}" GOARCH="${arch}" go build -a -trimpath "${flag}" -tags "${tags}" -o "${basename}" .
    if [[ $? == 0 ]]; then
      sha256sum "${basename}" | cut -d " " -f1 > "${basename}.sha256"
      sign "${basename}"
    fi
  done
done
# tlsclient
for os in android darwin linux; do
  for arch in amd64 arm64 arm; do
    basename="bin/tlsclient-${os}-${arch}"
    echo "Building ${basename}"
    GOOS="${os}" GOARCH="${arch}" go build -a -trimpath "${flag}" -tags "${tags}" -o "${basename}" ./tlsclient
    if [[ $? == 0 ]]; then
      sha256sum "${basename}" | cut -d " " -f1 > "${basename}.sha256"
      sign "${basename}"
    fi
  done
done

ls -l bin/
