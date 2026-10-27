#!/usr/bin/env bash
# build-ca.sh : builds and proves the S05 CA chain end to end (TLS-26 to TLS-31).
# Root CA, intermediate CA, server certificate with SANs, client certificate,
# a revoked certificate and CRLs, chain checks with openssl verify, and mutual TLS
# with openssl s_server -Verify and openssl s_client -cert.
# Every check is an assertion: the script stops at the first unexpected result.
#
# Usage: OPENSSL=/usr/bin/openssl BASE=/root/tls-ca CA_PASS=... ./build-ca.sh
#   BASE    where the CA lives (the .cnf files say /root/tls-ca; other paths are substituted)
#   CA_PASS passphrase for the root and intermediate keys (on camera you type it at the prompt)
set -euo pipefail
O=${OPENSSL:-openssl}
BASE=${BASE:-/root/tls-ca}
PASS=${CA_PASS:?set CA_PASS}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-18443}
export CA_PASS

ok()   { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; exit 1; }

"$O" version
rm -rf "$BASE"; mkdir -p "$BASE"
for ca in root intermediate; do
  mkdir -p "$BASE/$ca"/{certs,crl,csr,newcerts,private}
  chmod 700 "$BASE/$ca/private"
  touch "$BASE/$ca/index.txt"
done
# Serial numbers are random (rand_serial = yes in the .cnf files); only the CRL numbers count up.
echo 1000 > "$BASE/root/crlnumber"
echo 2000 > "$BASE/intermediate/crlnumber"
for f in root-ca intermediate-ca server-req client-req; do
  sed "s#/root/tls-ca#$BASE#g" "$HERE/$f.cnf" > "$BASE/$f.cnf"
done
cd "$BASE"
R=root; I=intermediate

# TLS-26: root CA (P-384 key, AES-256 encrypted, 20 years)
"$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -aes-256-cbc -pass env:CA_PASS -out $R/private/root.key
chmod 400 $R/private/root.key
"$O" req -config root-ca.cnf -new -x509 -days 7300 -key $R/private/root.key -passin env:CA_PASS -out $R/certs/root.crt
"$O" x509 -in $R/certs/root.crt -noout -subject -issuer -ext basicConstraints,keyUsage
"$O" verify -CAfile $R/certs/root.crt $R/certs/root.crt >/dev/null && ok "root is self-signed and verifies against itself"

# TLS-27: intermediate CA, signed by the root (pathlen:0, 10 years)
"$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -aes-256-cbc -pass env:CA_PASS -out $I/private/intermediate.key
chmod 400 $I/private/intermediate.key
"$O" req -config intermediate-ca.cnf -new -key $I/private/intermediate.key -passin env:CA_PASS -out $I/csr/intermediate.csr
"$O" ca -batch -config root-ca.cnf -extensions v3_intermediate_ca -notext -passin env:CA_PASS \
     -in $I/csr/intermediate.csr -out $I/certs/intermediate.crt
"$O" verify -CAfile $R/certs/root.crt $I/certs/intermediate.crt && ok "intermediate chains to root"
cat $I/certs/intermediate.crt $R/certs/root.crt > $I/certs/ca-chain.crt
cat $R/index.txt

# TLS-28: server certificate with SANs (P-256, unencrypted key so the web server can read it)
"$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $I/private/www.lab.internal.key
"$O" req -config server-req.cnf -new -key $I/private/www.lab.internal.key -out $I/csr/www.lab.internal.csr
"$O" req -in $I/csr/www.lab.internal.csr -noout -verify
"$O" ca -batch -config intermediate-ca.cnf -extensions server_cert -days 365 -notext -passin env:CA_PASS \
     -in $I/csr/www.lab.internal.csr -out $I/certs/www.lab.internal.crt
"$O" x509 -in $I/certs/www.lab.internal.crt -noout -subject -ext subjectAltName,keyUsage,extendedKeyUsage,basicConstraints
"$O" verify -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -purpose sslserver \
     -verify_hostname www.lab.internal $I/certs/www.lab.internal.crt && ok "server cert: chain + purpose + hostname"
if "$O" verify -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -verify_hostname evil.example \
     $I/certs/www.lab.internal.crt 2>/dev/null; then fail "wrong hostname accepted"; else ok "wrong hostname rejected"; fi
if "$O" verify -CAfile $R/certs/root.crt $I/certs/www.lab.internal.crt 2>/dev/null; then fail "leaf verified without intermediate"
else ok "leaf without its intermediate fails (why the server must send the chain)"; fi
cat $I/certs/www.lab.internal.crt $I/certs/intermediate.crt > $I/certs/www.lab.internal.fullchain.crt

# The 2021 mistake: without copy_extensions the SANs vanish
sed 's/^copy_extensions.*/copy_extensions = none/' intermediate-ca.cnf > nocopy.cnf
"$O" ca -batch -config nocopy.cnf -extensions server_cert -days 1 -notext -passin env:CA_PASS \
     -in $I/csr/www.lab.internal.csr -out nosan.crt 2>/dev/null
if "$O" x509 -in nosan.crt -noout -ext subjectAltName | grep -q DNS; then fail "SAN present without copy"
else ok "copy_extensions=none drops the CSR's SANs"; fi
# OpenSSL still falls back to the CN when a cert has no DNS SAN, so this passes here;
# browsers match SANs only (show the browser error on the lane, not here).
"$O" verify -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -verify_hostname www.lab.internal nosan.crt >/dev/null 2>&1 \
  && ok "SAN-less cert: openssl verify still matches via CN fallback (browsers do not)"
# The dash-form digest mistake
if "$O" ca -batch -config intermediate-ca.cnf -extensions server_cert -days 1 -notext -md -sha256 -passin env:CA_PASS \
     -in $I/csr/www.lab.internal.csr -out /dev/null 2>dash.err; then fail "-md -sha256 accepted"
else grep -q "unsupported" dash.err && ok "-md -sha256 fails: $(grep -o 'Algorithm ([^)]*)' dash.err | head -1)"; fi

# TLS-31: client certificate (clientAuth EKU)
"$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $I/private/ahmed.key
"$O" req -config client-req.cnf -new -key $I/private/ahmed.key -out $I/csr/ahmed.csr
"$O" ca -batch -config intermediate-ca.cnf -extensions client_cert -days 90 -notext -passin env:CA_PASS \
     -in $I/csr/ahmed.csr -out $I/certs/ahmed.crt
"$O" verify -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -purpose sslclient $I/certs/ahmed.crt \
     && ok "client cert valid for sslclient"
if "$O" verify -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -purpose sslclient $I/certs/www.lab.internal.crt 2>/dev/null
then fail "server cert accepted as client"; else ok "server-only cert rejected for sslclient"; fi
# A second client to revoke
"$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $I/private/former.key
"$O" req -config client-req.cnf -new -key $I/private/former.key -subj "/C=NL/O=TLS Essentials Lab/OU=admins/CN=former" -out $I/csr/former.csr
"$O" ca -batch -config intermediate-ca.cnf -extensions client_cert -days 90 -notext -passin env:CA_PASS \
     -in $I/csr/former.csr -out $I/certs/former.crt

# TLS-30: revoke, then publish CRLs (one per CA: checking the whole chain needs both)
"$O" ca -config intermediate-ca.cnf -passin env:CA_PASS -revoke $I/certs/former.crt -crl_reason keyCompromise
"$O" ca -config intermediate-ca.cnf -passin env:CA_PASS -gencrl -out $I/crl/intermediate.crl
"$O" ca -config root-ca.cnf -passin env:CA_PASS -gencrl -out $R/crl/root.crl
cat $I/index.txt
"$O" crl -in $I/crl/intermediate.crl -noout -text | sed -n '1,25p'
cat $I/crl/intermediate.crl $R/crl/root.crl > $I/crl/ca-chain.crl
"$O" verify -crl_check -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -CRLfile $I/crl/intermediate.crl \
     $I/certs/ahmed.crt && ok "ahmed passes CRL check"
if "$O" verify -crl_check -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -CRLfile $I/crl/intermediate.crl \
     $I/certs/former.crt 2>crl.err; then fail "revoked cert passed"; else grep -q "revoked" crl.err && ok "former rejected: $(grep -o 'certificate revoked' crl.err | head -1)"; fi
if "$O" verify -crl_check_all -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -CRLfile $I/crl/intermediate.crl \
     $I/certs/ahmed.crt 2>crlall.err; then fail "crl_check_all passed with one CRL"
else ok "crl_check_all with only the intermediate CRL fails: $(grep -o 'unable to get certificate CRL' crlall.err | head -1)"; fi
"$O" verify -crl_check_all -CAfile $R/certs/root.crt -untrusted $I/certs/intermediate.crt -CRLfile $I/crl/ca-chain.crl \
     $I/certs/ahmed.crt && ok "crl_check_all passes with both CRLs"

# TLS-31: mutual TLS with s_server -Verify and s_client -cert
# s_server -CRL reads a single CRL, so give it a hashed directory holding both CAs and both CRLs
mkdir -p trust; cp $R/certs/root.crt $I/certs/intermediate.crt $R/crl/root.crl $I/crl/intermediate.crl trust/
"$O" rehash trust
"$O" s_server -accept $PORT -www -cert $I/certs/www.lab.internal.crt -cert_chain $I/certs/intermediate.crt \
     -key $I/private/www.lab.internal.key -CApath trust -Verify 1 -verify_return_error \
     -crl_check_all >server.log 2>&1 &
SP=$!; trap 'kill $SP 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do (echo > /dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done
probe() { printf 'GET / HTTP/1.0\r\n\r\n' | "$O" s_client -ign_eof -connect 127.0.0.1:$PORT -servername www.lab.internal \
          -CAfile $R/certs/root.crt -verify_return_error -verify_hostname www.lab.internal "$@" 2>&1; }
out=$(probe -cert $I/certs/ahmed.crt -key $I/private/ahmed.key)
echo "$out" | grep -q "HTTP/1.0 200" && ok "mTLS with ahmed's cert: HTTP 200 ($(echo "$out" | grep -m1 -o 'Negotiated TLS1.3 group: [A-Za-z0-9]*'))" || { echo "$out" | tail -20; fail "mTLS good client"; }
out=$(probe) || true
echo "$out" | grep -q "HTTP/1.0 200" && fail "no client cert accepted" || ok "no client cert: refused ($(echo "$out" | grep -m1 -o 'alert[a-z ]*' ))"
out=$(probe -cert $I/certs/former.crt -key $I/private/former.key) || true
echo "$out" | grep -q "HTTP/1.0 200" && fail "revoked client accepted" || ok "revoked client: refused ($(echo "$out" | grep -m1 -o 'alert[a-z ]*'))"
out=$(probe -cert $I/certs/www.lab.internal.crt -key $I/private/www.lab.internal.key) || true
echo "$out" | grep -q "HTTP/1.0 200" && fail "server cert accepted as client" || ok "server cert as client: refused ($(echo "$out" | grep -m1 -o 'alert[a-z ]*'))"
kill $SP; wait $SP 2>/dev/null || true
grep -i "verify error\|error" server.log | sort | uniq -c | head
# Depth: one intermediate needs depth 1 (neither leaf nor root counts). Nginx's
# ssl_verify_depth defaults to 1. (s_server -Verify 0 does not enforce this; its demo
# callback overrides the error, so the check uses openssl verify.)
if "$O" verify -verify_depth 0 -CAfile $I/certs/ca-chain.crt $I/certs/ahmed.crt 2>depth.err; then fail "depth 0 accepted"
else ok "verify_depth 0: $(grep -o 'certificate chain too long' depth.err | head -1)"; fi
"$O" verify -verify_depth 1 -CAfile $I/certs/ca-chain.crt $I/certs/ahmed.crt >/dev/null && ok "verify_depth 1 accepts leaf + intermediate + root"
trap - EXIT
echo "ALL CHECKS PASSED"
