#!/bin/bash
#
# Check the latest GO version and update the github workflows.

latest=$(curl -s 'https://go.dev/dl/?mode=json' | jq -r '.[].stable = true | .[].version' | head -n 1)
version="${latest#go}"
if [[ "${latest}" =~ ^go ]]; then
  sed -i -re "s/^FROM golang:.*/FROM golang:${version}-alpine3.18 AS build/" Dockerfile
  for f in .github/workflows/*.yml; do
    sed -i -re "s/GOVERSION: .*/GOVERSION: '>=${version}'/" $f
  done
fi

deps=$(go get -u ./... 2>&1 | grep upgrade)

sed -n '1,2p' < CHANGELOG.md > CHANGELOG.md-new
if [[ -n $(git status -s Dockerfile) ]]; then
  echo "* update go: ${version}" | tee -a CHANGELOG.md-new
fi
if [[ -n "${deps}" ]]; then
  echo "* update go dependencies:"
  echo "${deps}" | sed -re 's/^/  * /g' | tee -a CHANGELOG.md-new
fi
sed -n '3,$p' < CHANGELOG.md >> CHANGELOG.md-new
mv CHANGELOG.md-new CHANGELOG.md
exit 0
