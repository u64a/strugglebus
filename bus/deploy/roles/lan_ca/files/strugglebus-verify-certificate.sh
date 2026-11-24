#!/usr/bin/env bash
set -euo pipefail

COMMON=/usr/local/libexec/strugglebus-lan-ca-common
if [ "$(id -u)" -ne 0 ] && [ -n "${STRUGGLEBUS_LAN_CA_TEST_COMMON:-}" ]; then
  COMMON="${STRUGGLEBUS_LAN_CA_TEST_COMMON}"
fi

OPENSSL_BIN="${OPENSSL_BIN:-/usr/bin/openssl}"
AWK_BIN="${AWK_BIN:-/usr/bin/awk}"
SHA256SUM_BIN="${SHA256SUM_BIN:-/usr/bin/sha256sum}"
CUT_BIN="${CUT_BIN:-/usr/bin/cut}"
MKTEMP_BIN="${MKTEMP_BIN:-/usr/bin/mktemp}"
RM_BIN="${RM_BIN:-/usr/bin/rm}"
GREP_BIN="${GREP_BIN:-/usr/bin/grep}"
TAIL_BIN="${TAIL_BIN:-/usr/bin/tail}"
TR_BIN="${TR_BIN:-/usr/bin/tr}"
STAT_BIN="${STAT_BIN:-/usr/bin/stat}"

# shellcheck source=/dev/null
. "${COMMON}"

[ "$#" -eq 7 ] || lan_ca_die \
  "usage: strugglebus-verify-certificate CHAIN KEY BUNDLE DNS ROOT_SHA256 INTERMEDIATE_SHA256 MINIMUM_SECONDS"
lan_ca_verify_certificate "$1" "$2" "$3" "$4" "$5" "$6" "$7"
