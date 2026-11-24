#!/usr/bin/env bash
set -euo pipefail

COMMON=/usr/local/libexec/strugglebus-lan-ca-common
if [ "$(id -u)" -ne 0 ] && [ -n "${STRUGGLEBUS_LAN_CA_TEST_COMMON:-}" ]; then
  # Non-root test execution may point at the reviewed workspace copy.
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

if [ "${1:-}" = "--install-root" ]; then
  [ "$#" -eq 5 ] || lan_ca_die \
    "usage: strugglebus-verify-ca-bundle --install-root BUNDLE ROOT_SHA256 INTERMEDIATE_SHA256 DESTINATION"
  bundle="$2"
  expected_root="$3"
  expected_intermediate="$4"
  destination="$5"
  lan_ca_verify_bundle \
    "${bundle}" "${expected_root}" "${expected_intermediate}" >/dev/null
  workspace="$("${MKTEMP_BIN}" -d)"
  trap '"${RM_BIN}" -rf -- "${workspace}"' EXIT
  lan_ca_split_certificates "${bundle}" "${workspace}"
  temporary="${destination}.new.$$"
  /usr/bin/install -o root -g root -m 0644 \
    "${workspace}/cert-1.pem" "${temporary}"
  if [ -f "${destination}" ] && /usr/bin/cmp -s "${temporary}" "${destination}"; then
    "${RM_BIN}" -f -- "${temporary}"
    printf 'status=unchanged\n'
  else
    /usr/bin/mv -f -- "${temporary}" "${destination}"
    printf 'status=changed\n'
  fi
  exit 0
fi

[ "$#" -eq 3 ] || lan_ca_die \
  "usage: strugglebus-verify-ca-bundle BUNDLE ROOT_SHA256 INTERMEDIATE_SHA256"
lan_ca_verify_bundle "$1" "$2" "$3"
