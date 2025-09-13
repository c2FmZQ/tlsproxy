#!/bin/bash

out="$(git grep X\XX)"
if [[ "${out}" != "" ]]; then
  echo "Found:"
  echo "${out}" | sed -re 's/^/> /'
  exit 1
fi
