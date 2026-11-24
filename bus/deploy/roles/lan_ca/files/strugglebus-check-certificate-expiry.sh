#!/usr/bin/env bash
set -eEuo pipefail

ENV_FILE="${STRUGGLEBUS_LAN_CA_ENV:-/etc/lan-ca/strugglebus-renew.env}"
STATUS_FILE="${1:-/run/strugglebus-cert-monitor/status.json}"

write_status() {
  local status="$1" reason="$2" remaining="$3" not_after="$4"
  local temporary="${STATUS_FILE}.new.$$"
  /usr/bin/install -d -m 0755 "$(/usr/bin/dirname "${STATUS_FILE}")"
  printf \
    '{"status":"%s","reason":"%s","remaining_seconds":%s,"not_after":"%s"}\n' \
    "${status}" "${reason}" "${remaining}" "${not_after}" >"${temporary}"
  /usr/bin/chmod 0644 "${temporary}"
  /usr/bin/mv -f -- "${temporary}" "${STATUS_FILE}"
}

write_unexpected_failure() {
  trap - ERR
  write_status critical monitor-error 0 unknown || true
  exit 2
}

[ -r "${ENV_FILE}" ] || {
  write_status critical configuration-unavailable 0 unknown
  exit 2
}
# shellcheck disable=SC1090
if ! . "${ENV_FILE}"; then
  write_status critical configuration-invalid 0 unknown
  exit 2
fi
for required in \
  SERVICE_DNS TLS_ROOT CA_ROOT CA_BUNDLE \
  EXPECTED_ROOT_SHA256 EXPECTED_INTERMEDIATE_SHA256 \
  WARNING_SECONDS CRITICAL_SECONDS; do
  if [ -z "${!required:-}" ]; then
    write_status critical configuration-invalid 0 unknown
    exit 2
  fi
done
trap write_unexpected_failure ERR

VERIFY_BIN=/usr/local/libexec/strugglebus-verify-certificate
OPENSSL_BIN=/usr/bin/openssl
if [ "$(id -u)" -ne 0 ]; then
  VERIFY_BIN="${STRUGGLEBUS_LAN_CA_TEST_VERIFY:-${VERIFY_BIN}}"
  OPENSSL_BIN="${OPENSSL_BIN_OVERRIDE:-${OPENSSL_BIN}}"
fi

certificate="${TLS_ROOT}/current/cert.pem"
key="${TLS_ROOT}/current/key.pem"
if ! "${VERIFY_BIN}" \
  "${certificate}" "${key}" "${CA_BUNDLE}" "${SERVICE_DNS}" \
  "${EXPECTED_ROOT_SHA256}" "${EXPECTED_INTERMEDIATE_SHA256}" 0 >/dev/null 2>&1; then
  write_status critical certificate-invalid 0 unknown
  exit 2
fi

not_after="$("${OPENSSL_BIN}" x509 -in "${certificate}" -noout -enddate)"
not_after="${not_after#notAfter=}"
end_epoch="$(/usr/bin/date -u -d "${not_after}" +%s)"
now_epoch="$(/usr/bin/date -u +%s)"
remaining=$((end_epoch - now_epoch))

if [ "${remaining}" -le "${CRITICAL_SECONDS}" ]; then
  write_status critical expires-soon "${remaining}" "${not_after}"
  exit 2
fi
if [ "${remaining}" -le "${WARNING_SECONDS}" ]; then
  write_status warning expires-soon "${remaining}" "${not_after}"
  exit 1
fi
write_status ok valid "${remaining}" "${not_after}"
trap - ERR
