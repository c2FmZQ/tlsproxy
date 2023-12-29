#!/bin/bash
#
# Check the lastest GO version and update the github workflows.

echo '```'

latest=$(curl -s 'https://go.dev/dl/?mode=json' | jq -r '.[].stable = true | .[].version' | head -n 1)
echo "GO version: ${latest}"
if [[ "${latest}" =~ ^go ]]; then
  version="${latest#go}"
  for f in .github/workflows/*.yml; do
    sed -i -re "s/GOVERSION: .*/GOVERSION: '>=${version}'/" $f
  done
fi

go get -u ./... 2>&1 | grep upgrade

echo '```'

exit 0
