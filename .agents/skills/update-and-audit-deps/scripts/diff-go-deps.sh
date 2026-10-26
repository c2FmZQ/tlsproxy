#!/usr/bin/env bash
#
# Compare go.mod against a baseline git ref (default: HEAD) and generate
# code diffs from GOMODCACHE for all upgraded Go module dependencies, along
# with their import call sites in tlsproxy and tlsclient.
#
# Usage:
#   ./diff-go-deps.sh [base-ref] [output-dir]

set -euo pipefail

BASE_REF="${1:-HEAD}"
OUT_DIR="${2:-$(mktemp -d /tmp/tlsproxy-dep-audit.XXXXXX)}"
mkdir -p "${OUT_DIR}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

parse_gomod() {
  awk '
    /^require \(/ { in_req=1; next }
    in_req && /^\)/ { in_req=0; next }
    /^require [^ (]+ [^ (]+/ { print $2, $3; next }
    in_req && NF >= 2 && $1 !~ /^\/\// { print $1, $2 }
  '
}

OLD_MODS="${OUT_DIR}/old_mods.txt"
NEW_MODS="${OUT_DIR}/new_mods.txt"
SUMMARY="${OUT_DIR}/summary.md"

git show "${BASE_REF}:go.mod" | parse_gomod | sort -k1,1 > "${OLD_MODS}"
parse_gomod < go.mod | sort -k1,1 > "${NEW_MODS}"

echo "# Upgraded Go Dependencies (${BASE_REF} -> working tree)" > "${SUMMARY}"
echo "" >> "${SUMMARY}"
echo "Output directory: \`${OUT_DIR}\`" >> "${SUMMARY}"
echo "" >> "${SUMMARY}"

UPGRADED=0

while read -r mod old_ver new_ver; do
  if [[ "${old_ver}" == "${new_ver}" ]]; then
    continue
  fi
  UPGRADED=$((UPGRADED + 1))
  safe_name="$(echo "${mod}" | tr '/.' '__')"
  diff_file="${OUT_DIR}/${safe_name}.diff"

  echo "## ${mod}: ${old_ver} -> ${new_ver}" >> "${SUMMARY}"

  old_dir=""
  new_dir=""
  if [[ "${old_ver}" != "(added)" ]]; then
    old_dir="$(go mod download -json "${mod}@${old_ver}" 2>/dev/null | jq -r '.Dir // empty')"
  fi
  if [[ "${new_ver}" != "(removed)" ]]; then
    new_dir="$(go mod download -json "${mod}@${new_ver}" 2>/dev/null | jq -r '.Dir // empty')"
  fi

  echo "- Old Dir: \`${old_dir:-N/A}\`" >> "${SUMMARY}"
  echo "- New Dir: \`${new_dir:-N/A}\`" >> "${SUMMARY}"

  # Find files in tlsproxy / tlsclient that import this module or its subpackages.
  echo "- Imported in repository files:" >> "${SUMMARY}"
  matches="$(grep -rnE --include='*.go' "\"${mod}(\"|/)" . || true)"
  if [[ -n "${matches}" ]]; then
    echo "${matches}" | sed 's/^/  - `/' | sed 's/$/`/' >> "${SUMMARY}"
  else
    echo "  - (transitive / indirect dependency)" >> "${SUMMARY}"
  fi

  if [[ -n "${old_dir}" && -n "${new_dir}" && -d "${old_dir}" && -d "${new_dir}" ]]; then
    diff -ruN \
      --exclude='*_test.go' \
      --exclude='.git*' \
      "${old_dir}" "${new_dir}" > "${diff_file}" || true
    lines="$(wc -l < "${diff_file}")"
    echo "- Non-test Go source diff: \`${diff_file}\` (${lines} lines)" >> "${SUMMARY}"
  fi
  echo "" >> "${SUMMARY}"
done < <(
  join -a1 -a2 -e '(none)' -o '0,1.2,2.2' "${OLD_MODS}" "${NEW_MODS}" |
    awk '$2 != $3 {
      old = ($2 == "(none)" ? "(added)" : $2)
      new = ($3 == "(none)" ? "(removed)" : $3)
      print $1, old, new
    }'
)

if [[ "${UPGRADED}" -eq 0 ]]; then
  echo "No module version changes detected in go.mod relative to ${BASE_REF}." >> "${SUMMARY}"
fi

echo "Audit summary written to: ${SUMMARY} (${UPGRADED} module(s) changed)"
