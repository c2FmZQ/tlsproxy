#!/bin/bash -e
# Display the release notes for the version passed as command line argument.

version=$(echo $1 | sed -re 's/[+].*$//' -e 's/[.]/[.]/g')
tags=$(echo $1 | sed -re 's/^([^+]*)([+](.*))?$/\3/' -e 's/[+]/,/g') 

awk '
  /^## / { if (on) exit 0 }
  /^## '"${version}"'$/ { on=1 }
  { if (on) print }
' < CHANGELOG.md

if [[ -n "${tags}" ]]; then
  echo 'Built with: `-tags '"${tags}"'`'
  echo
fi

prev=$(grep "^## v" CHANGELOG.md | grep -E '^## '"${version}"'$' -A1 | tail -n 1 | cut -c4-)
if [[ "${prev}" != "" && "${prev}" != "$1" ]]; then
  echo "[Compare with $prev](https://github.com/c2FmZQ/tlsproxy/compare/${prev}...${1})"
fi
