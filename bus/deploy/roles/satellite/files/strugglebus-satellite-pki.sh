#!/usr/bin/env bash
# Ensure the satellite site CA and the satellite proxy's server certificate.
#
# usage: strugglebus-satellite-pki CA_KEY CA_CERT SERVER_DIR HOSTNAME SERVER_GROUP
#
# The CA is created once and never replaced: satellites pin it, so a missing
# half of an existing CA is a refusal, not a reason to start over. The server
# certificate is reissued when absent, expiring within 60 days, not for
# HOSTNAME, or not from this CA. Prints status words only, never key material.
set -euo pipefail

OPENSSL_BIN="${OPENSSL_BIN:-/usr/bin/openssl}"
RENEW_SECONDS=5184000

die() {
  printf 'strugglebus-satellite-pki: %s\n' "$1" >&2
  exit 1
}

[ "$#" -eq 5 ] || die "usage: strugglebus-satellite-pki CA_KEY CA_CERT SERVER_DIR HOSTNAME SERVER_GROUP"
ca_key=$1
ca_cert=$2
server_dir=$3
hostname=$4
server_group=$5
printf '%s' "$hostname" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' \
  || die "hostname must be a lowercase public DNS name"

[ -d "$server_dir" ] || die "the server directory must already exist"
umask 077
# Stage beside the targets so each final move is a rename on one filesystem.
work=$(mktemp -d "$server_dir/.pki.XXXXXX")
trap 'rm -rf "$work"' EXIT

key_digest() {
  "$OPENSSL_BIN" pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1
}

certificate_key_digest() {
  "$OPENSSL_BIN" x509 -in "$1" -noout -pubkey 2>/dev/null \
    | "$OPENSSL_BIN" pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1
}

if [ ! -e "$ca_key" ] && [ ! -e "$ca_cert" ]; then
  "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/ca.key" 2>/dev/null
  "$OPENSSL_BIN" req -x509 -new -key "$work/ca.key" -out "$work/ca.crt" -days 3650 -sha256 \
    -subj "/CN=Strugglebus satellite site CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always" 2>/dev/null
  chmod 0644 "$work/ca.crt"
  mv "$work/ca.key" "$ca_key"
  mv "$work/ca.crt" "$ca_cert"
  echo "ca: created"
elif [ -f "$ca_key" ] && [ -f "$ca_cert" ]; then
  [ "$(key_digest "$ca_key")" = "$(certificate_key_digest "$ca_cert")" ] \
    || die "the site CA key does not match its certificate"
  echo "ca: present"
else
  die "only half of the site CA exists; restore it rather than replacing it"
fi

server_cert="$server_dir/server.crt"
server_key="$server_dir/server.key"
current=no
if [ -f "$server_cert" ] && [ -f "$server_key" ] \
  && "$OPENSSL_BIN" x509 -in "$server_cert" -noout -checkend "$RENEW_SECONDS" >/dev/null 2>&1 \
  && "$OPENSSL_BIN" x509 -in "$server_cert" -noout -checkhost "$hostname" 2>/dev/null | grep -q "does match" \
  && "$OPENSSL_BIN" verify -CAfile "$ca_cert" "$server_cert" >/dev/null 2>&1; then
  current=yes
fi

if [ "$current" = yes ]; then
  echo "server: current"
  exit 0
fi

"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/server.key" 2>/dev/null
"$OPENSSL_BIN" req -new -key "$work/server.key" -out "$work/server.csr" -subj "/CN=$hostname" 2>/dev/null
printf '%s\n' \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:$hostname" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid:always" > "$work/server.ext"
"$OPENSSL_BIN" x509 -req -in "$work/server.csr" -CA "$ca_cert" -CAkey "$ca_key" \
  -CAcreateserial -CAserial "$work/ca.srl" -out "$work/server.crt" -days 365 -sha256 \
  -extfile "$work/server.ext" 2>/dev/null
if [ -n "$server_group" ]; then
  chgrp "$server_group" "$work/server.key" "$work/server.crt"
fi
chmod 0640 "$work/server.key"
chmod 0644 "$work/server.crt"
mv "$work/server.key" "$server_key"
mv "$work/server.crt" "$server_cert"
echo "server: issued"
