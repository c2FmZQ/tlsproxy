#!/bin/bash -e
#
# This script checks that the base docker image for linux/amd64 is actually
# built for that platform.

image=$(sed -n -re 's:^FROM ([^ ]+) AS build$:\1:p' Dockerfile)

echo "Pulling ${image} for linux/amd64"
docker image pull --platform=linux/amd64 "${image}"

arch=$(docker image inspect "${image}" | jq -r '.[].Architecture')

if [[ "${arch}" != "amd64" ]]; then
  echo "Image ${image} has platform=${arch}, want amd64"
  exit 1
fi
echo OK
