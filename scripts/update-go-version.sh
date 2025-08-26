#!/bin/bash
#
# Check the latest GO version and update the github workflows.

latest=$(curl -s 'https://go.dev/dl/?mode=json' | jq -r '.[].stable = true | .[].version' | head -n 1)
version="${latest#go}"
osversion="alpine3.22"
if [[ "${latest}" =~ ^go ]]; then
  sed -i -re "s/^FROM golang:.*/FROM golang:${version}-${osversion} AS build/" Dockerfile
  echo "${version}" > .goversion
fi

deps=$((go get -u ./... 2>&1 && go mod tidy) | grep upgrade | sed -re 's/go: //g')
exdeps=$((cd examples/backend && go get -u ./... 2>&1 && go mod tidy) | grep upgrade | sed -re 's/go: //g')
exdeps2=$((cd examples/deviceauth && go get -u ./... 2>&1 && go mod tidy) | grep upgrade | sed -re 's/go: //g')

sed -n '1,2p' < CHANGELOG.md > CHANGELOG.md-new
echo '## next' >> CHANGELOG.md-new
echo >> CHANGELOG.md-new
echo '### :wrench: Misc' >> CHANGELOG.md-new
echo >> CHANGELOG.md-new
if [[ -n $(git status -s Dockerfile) ]]; then
  echo "* Update go: ${version}" | tee -a CHANGELOG.md-new
fi
if [[ -n "${deps}" ]]; then
  echo "* Update go dependencies:" | tee -a CHANGELOG.md-new
  echo "${deps}" | sed -re 's/^/  * /g' | tee -a CHANGELOG.md-new
fi
if [[ -n "${exdeps}" ]]; then
  echo "* Update go dependencies in examples/backend:"
  echo "${exdeps}" | sed -re 's/^/  * /g'
fi
if [[ -n "${exdeps2}" ]]; then
  echo "* Update go dependencies in examples/deviceauth:"
  echo "${exdeps2}" | sed -re 's/^/  * /g'
fi
echo >> CHANGELOG.md-new
sed -n '3,$p' < CHANGELOG.md >> CHANGELOG.md-new
mv CHANGELOG.md-new CHANGELOG.md
exit 0
