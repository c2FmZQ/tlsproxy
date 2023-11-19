#!/bin/bash -e
# Display the release notes for the version passed as command line argument.

cd $(dirname "$0")
version=$(echo $1 | sed 's/[.]/[.]/g')

awk '
  /^## / { on=0 }
  /^## '"${version}"'$/ { on=1 }
  { if (on) print }
' < CHANGELOG.md
