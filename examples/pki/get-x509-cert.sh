#!/bin/bash -e
#
# This script demonstrates how to get X509 certificates from TLSPROXY using
# device authorization from a shell. The key file is automatically generated
# locally.
#
# The script assumes that the pki and device authorization endpoints are
# configure like this:
#   - <base URL>/pki
#   - <base URL>/device/authorization
#   - <base URL>/device/token
#
# With <base URL> = https://pki.example.com, the tlsproxy config would look
# like this:
#
#   pki:
#   - name: "EXAMPLE CA"
#     endpoint: https://pki.example.com/pki
#
#   backends:
#   - serverNames:
#     - pki.example.com
#     mode: local
#     sso:
#       provider: sso-provider # definition omitted for this example
#       deviceAuth:
#         clients:
#         - id: myclientid123

if [[ $# != 3 ]]; then
  echo "usage: $(basename $0) <clientID> <base URL> <keyname>"
  exit 1
fi

CLIENTID="$1"
BASEURL="$(echo $2 | sed -re 's:/+$::')" # remove trailing /
KEYNAME="$3"

# Generate the ECDSA private key and certificate request.
openssl req -newkey                                                              \
  ec:<(openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256) \
  -subj "/CN=$(basename "${KEYNAME}")"                                           \
  -keyout "${KEYNAME}.key"                                                       \
  -out "${KEYNAME}.csr"                                                          \
  -noenc     # remove -noenc if you want the private key to be encrypted

# This is the command to fetch the certificate. The TOKEN is provided by the
# deviceauth command.
CURLCMD="curl -s -f                            \
  --data-binary \"@${KEYNAME}.csr\"            \
  -o \"${KEYNAME}.cert.json\"                  \
  -H \"Content-Type: application/x-pem-file\"  \
  -H \"x-csrf-check: 1\"                       \
  -H \"Authorization: Bearer \${TOKEN}\"       \
  \"${BASEURL}/pki?get=requestCert\""

# Run the deviceauth command to get the access token required to reach the
# PKI endpoint, and run the curl command to get the x509 certificate.
cd "$(dirname $0)/../deviceauth"
go run github.com/c2FmZQ/tlsproxy/examples/deviceauth \
  --client-id="${CLIENTID}"                           \
  --auth-endpoint="${BASEURL}/device/authorization"   \
  --token-endpoint="${BASEURL}/device/token"          \
  --run="${CURLCMD}"

# The JSON file should look like:
# {"cert":"-----BEGIN CERTIFICATE-----\nXXXX-----END CERTIFICATE-----\n","result":"ok"}
jq -r .cert < "${KEYNAME}.cert.json" > "${KEYNAME}.cert"

echo "=============================================================="
echo "ECDSA KEY saved in ${KEYNAME}.key"
echo "Certificate saved in ${KEYNAME}.cert"
echo
echo "Details:"
openssl x509                            \
  -subject                              \
  -ext subjectAltName                   \
  -issuer                               \
  -dates                                \
  -nocert                               \
  < "${KEYNAME}.cert" | sed -re 's/^/| /'
echo "=============================================================="
