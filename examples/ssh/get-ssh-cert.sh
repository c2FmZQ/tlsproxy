#!/bin/bash -e
#
# This script demonstrates how to get SSH certificates from TLSPROXY using
# device authorization from a shell.
#
# The script assumes that the certificate and device authorization endpoints
# are configure like this:
#   - <base URL>/cert
#   - <base URL>/device/authorization
#   - <base URL>/token
#
# The tlsproxy config would look like this:
#
#   sshCertificateAuthority:
#   - name: "EXAMPLE SSH CA"
#     certificateEndpoint: https://ssh.example.com/cert
#
#   backends:
#   - serverNames:
#     - ssh.example.com
#     mode: local
#     sso:
#       provider: sso-provider # definition omitted for this example
#       localOIDCServer:
#         scopes:
#         - ssh
#         clients:
#         - id: myclientid123

if [[ $# != 3 ]]; then
  echo "usage: $(basename $0) <clientID> <base URL> <ssh-key.pub>"
  exit 1
fi

CLIENTID="$1"
BASEURL="$(echo $2 | sed -re 's:/+$::')" # remove trailing /
PUBKEY="$3"
CERTFILE="${PUBKEY/.pub/}-cert.pub"

is_current() {
  if [[ ! -e "$1" ]]; then
    return 1
  fi
  local exp_str exp now
  exp_str="$(ssh-keygen -L -f "$1" 2>/dev/null | awk '/Valid:/ {print $5}')"
  if [[ -z "${exp_str}" ]]; then
    return 1
  fi
  exp="$(date -d "${exp_str}" +%s)" || return 1
  now="$(date +%s)"
  (( now + 60 <= exp ))
}

if is_current "${CERTFILE}"; then
  echo "Certificate ${CERTFILE} is current"
  exit 0
fi

TMPFILE="$(mktemp)"
trap 'rm -f "${TMPFILE}"' EXIT

export BASEURL PUBKEY CERTFILE TMPFILE

CURLCMD="$(cat <<"eof"
  if curl -s --fail-with-body                   \
      --data-binary "@${PUBKEY}"                \
      -o "${TMPFILE}"                           \
      -H "Content-Type: text/plain"             \
      -H "Authorization: Bearer ${TOKEN}"       \
      "${BASEURL}/cert"; then
    mv -f "${TMPFILE}" "${CERTFILE}"
  else
    echo "Error fetching ${BASEURL}/cert"
    cat "${TMPFILE}"
    rm "${TMPFILE}"
    exit 1
  fi
eof
)"

cd "$(dirname $0)/../deviceauth"
go run github.com/c2FmZQ/tlsproxy/examples/deviceauth \
  --qr                                                \
  --client-id="${CLIENTID}"                           \
  --scopes=ssh                                        \
  --auth-endpoint="${BASEURL}/device/authorization"   \
  --token-endpoint="${BASEURL}/token"                 \
  --run="${CURLCMD}"

echo "SSH Certificate saved in ${CERTFILE}"
