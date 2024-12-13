#!/bin/sh -e

cd $(dirname $0)

(cd clientwasm && GOOS=js GOARCH=wasm go build -ldflags="-extldflags=-s -w" -o ../pki.wasm .)

cp $(go env GOROOT)/*/wasm/wasm_exec.js .
bzip2 -c9 < pki.wasm > pki.wasm.bz2
ls -l pki.wasm.bz2 wasm_exec.js
