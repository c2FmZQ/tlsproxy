#!/bin/bash -e
#
# This script demonstrates how to get SSH certificates from TLSPROXY using
# device authorization from a shell.
#
# The script assumes that the certificate and device authorization endpoints
# are configure like this:
#   - <base URL>/cert
#   - <base URL>/device/authorization
#   - <base URL>/device/token
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

CURLCMD="curl -s -f --data-binary @${PUBKEY} -o ${CERTFILE} \
  -H \"Content-Type: text/plain\"                           \
  -H \"x-csrf-check: 1\"                                    \
  -H \"Authorization: Bearer \${TOKEN}\"                    \
  \"${BASEURL}/cert\""

cd "$(dirname $0)/../deviceauth"
go run github.com/c2FmZQ/tlsproxy/examples/deviceauth \
  --client-id="${CLIENTID}"                           \
  --scopes=ssh                                        \
  --auth-endpoint="${BASEURL}/device/authorization"   \
  --token-endpoint="${BASEURL}/device/token"          \
  --run="${CURLCMD}"

echo "SSH Certificate saved in ${CERTFILE}"
