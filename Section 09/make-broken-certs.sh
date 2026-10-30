#!/usr/bin/env bash
# make-broken-certs.sh : TLS-44, five broken certificates on purpose. Run it in an empty folder.
# Builds its own throwaway two-tier CA (not the Section 05 CA) and the files below. Lab only: no key is encrypted.
# Ubuntu 26.04, OpenSSL 3.5.5 (-not_before and -not_after need OpenSSL 3.4 or later).
set -euo pipefail
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$1" -out "$2"; }
ca()  { echo "basicConstraints=critical,CA:TRUE"; echo "keyUsage=critical,keyCertSign,cRLSign"; }
leaf() { echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature"
         echo "extendedKeyUsage=serverAuth"; echo "subjectAltName=DNS:$1"; }
sign() {   # sign <csr-subject> <key> <issuer.crt> <issuer.key> <extensions> <out> [x509 options]
  local subj=$1 k=$2 icrt=$3 ikey=$4 ext=$5 out=$6; shift 6
  openssl req -new -key "$k" -subj "$subj" |
    openssl x509 -req -CA "$icrt" -CAkey "$ikey" -extfile <(echo "$ext") "$@" -out "$out" 2>/dev/null
}

# The lab CA: a root and an intermediate
key P-384 root.key
openssl req -x509 -new -key root.key -subj "/CN=Broken Lab Root" -days 3650 -extensions v3 \
  -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s\n' "$(ca)") -out root.crt
key P-384 intermediate.key
sign "/CN=Broken Lab Intermediate" intermediate.key root.crt root.key "$(ca)" intermediate.crt -days 1825

# One server key for the leaves, and a key that belongs to none of them
key P-256 server.key
key P-256 other.key

# good.crt      : correct in every way (served without its intermediate, it is case 3)
sign /CN=localhost server.key intermediate.crt intermediate.key "$(leaf localhost)" good.crt -days 90
# 1 expired.crt : valid for January 2025 only
sign /CN=localhost server.key intermediate.crt intermediate.key "$(leaf localhost)" expired.crt \
  -not_before 20250101000000Z -not_after 20250201000000Z
# 2 wrong.crt   : issued for www.example.test, not localhost
sign /CN=www.example.test server.key intermediate.crt intermediate.key "$(leaf www.example.test)" wrong.crt -days 90
# 4 rogue.crt   : signed by a root nobody trusts (rogue-root.crt)
key P-384 rogue-root.key
openssl req -x509 -new -key rogue-root.key -subj "/CN=Rogue Root" -days 3650 -extensions v3 \
  -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s\n' "$(ca)") -out rogue-root.crt
sign /CN=localhost server.key rogue-root.crt rogue-root.key "$(leaf localhost)" rogue.crt -days 90
# 5 good.crt with other.key: a certificate and a key from different pairs

rm -f root.key intermediate.key rogue-root.key   # the CA keys are not needed again
ls
