#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${STRUGGLEBUS_LAN_CA_ENV:-/etc/lan-ca/strugglebus-renew.env}"
[ -r "${ENV_FILE}" ] || {
  printf 'ERROR: renewal configuration is unavailable\n' >&2
  exit 1
}
# shellcheck disable=SC1090
. "${ENV_FILE}"

: "${CA_URL:?CA_URL is required}"
: "${CA_ROOT:?CA_ROOT is required}"
: "${CA_BUNDLE:?CA_BUNDLE is required}"
: "${PROVISIONER_NAME:?PROVISIONER_NAME is required}"
: "${SERVICE_DNS:?SERVICE_DNS is required}"
: "${TLS_ROOT:?TLS_ROOT is required}"
: "${CADDY_CONFIG:?CADDY_CONFIG is required}"
: "${EXPECTED_ROOT_SHA256:?EXPECTED_ROOT_SHA256 is required}"
: "${EXPECTED_INTERMEDIATE_SHA256:?EXPECTED_INTERMEDIATE_SHA256 is required}"
: "${RENEW_BEFORE_SECONDS:?RENEW_BEFORE_SECONDS is required}"
: "${CADDY_GROUP:?CADDY_GROUP is required}"
: "${CREDENTIALS_DIRECTORY:?systemd credential directory is required}"

if [ "$(id -u)" -eq 0 ]; then
  STEP_BIN=/usr/local/bin/step
  CADDY_BIN=/usr/bin/caddy
  SYSTEMCTL_BIN=/usr/bin/systemctl
  VERIFY_BIN=/usr/local/libexec/strugglebus-verify-certificate
else
  STEP_BIN="${STRUGGLEBUS_LAN_CA_TEST_STEP:-/usr/local/bin/step}"
  CADDY_BIN="${STRUGGLEBUS_LAN_CA_TEST_CADDY:-/usr/bin/caddy}"
  SYSTEMCTL_BIN="${STRUGGLEBUS_LAN_CA_TEST_SYSTEMCTL:-/usr/bin/systemctl}"
  VERIFY_BIN="${STRUGGLEBUS_LAN_CA_TEST_VERIFY:-/usr/local/libexec/strugglebus-verify-certificate}"
fi

readonly PASSWORD_FILE="${CREDENTIALS_DIRECTORY}/jwk-password"
readonly GENERATIONS="${TLS_ROOT}/generations"
readonly CURRENT="${TLS_ROOT}/current"
readonly NEW_LINK="${TLS_ROOT}/.current.new.$$"

for path in \
  "${STEP_BIN}" "${CADDY_BIN}" "${SYSTEMCTL_BIN}" "${VERIFY_BIN}" \
  /usr/bin/flock /usr/bin/install /usr/bin/mktemp \
  /usr/bin/mv /usr/bin/ln /usr/bin/readlink /usr/bin/rm /usr/bin/date \
  /usr/bin/grep /usr/bin/timeout; do
  [ -x "${path}" ] || {
    printf 'ERROR: a required certificate command is unavailable\n' >&2
    exit 1
  }
done
for protected in "${CA_ROOT}" "${CA_BUNDLE}" "${PASSWORD_FILE}"; do
  [ -f "${protected}" ] && [ ! -L "${protected}" ] || {
    printf 'ERROR: required protected certificate input is unavailable\n' >&2
    exit 1
  }
done

umask 077
if [ "$(id -u)" -eq 0 ]; then
  /usr/bin/install -d -o root -g "${CADDY_GROUP}" -m 0750 \
    "${TLS_ROOT}" "${GENERATIONS}"
else
  /usr/bin/install -d -m 0750 "${TLS_ROOT}" "${GENERATIONS}"
fi
exec 9>"${TLS_ROOT}/.renew.lock"
/usr/bin/flock -n 9 || {
  printf '{"status":"busy"}\n' >&2
  exit 75
}

stage=""
activation_marker_tmp=""
cleanup() {
  /usr/bin/rm -f -- "${NEW_LINK}"
  if [ -n "${activation_marker_tmp}" ]; then
    /usr/bin/rm -f -- "${activation_marker_tmp}"
  fi
  if [ -n "${stage}" ] && [ -d "${stage}" ]; then
    /usr/bin/rm -rf -- "${stage}"
  fi
}
trap cleanup EXIT

activation_marker_matches() {
  local target="${GENERATIONS}/$1"
  local fingerprint marker
  fingerprint="${target}/fingerprint.sha256"
  marker="${target}/activated.sha256"
  [ -f "${fingerprint}" ] && [ ! -L "${fingerprint}" ] \
    && [ -f "${marker}" ] && [ ! -L "${marker}" ] \
    && [[ "$(<"${fingerprint}")" =~ ^leaf_sha256=[0-9a-f]{64}$ ]] \
    && [ "$(<"${marker}")" = "$(<"${fingerprint}")" ]
}

publish_activation_marker() {
  local target="${GENERATIONS}/$1"
  local fingerprint record
  fingerprint="${target}/fingerprint.sha256"
  [ -f "${fingerprint}" ] && [ ! -L "${fingerprint}" ] \
    || return 1
  record="$(<"${fingerprint}")"
  [[ "${record}" =~ ^leaf_sha256=[0-9a-f]{64}$ ]] || return 1
  activation_marker_tmp="${target}/.activated.sha256.new.$$"
  printf '%s\n' "${record}" >"${activation_marker_tmp}"
  if [ "$(id -u)" -eq 0 ]; then
    /usr/bin/chown root:root "${activation_marker_tmp}"
  fi
  /usr/bin/chmod 0644 "${activation_marker_tmp}"
  /usr/bin/mv -f -- "${activation_marker_tmp}" "${target}/activated.sha256"
  activation_marker_tmp=""
}

restart_caddy() {
  # A reload swaps the certificate without dropping client connections. Debian's
  # Caddy 2.6.2 panicked mid-reload and hung, so the reload is bounded and a
  # failed or hung one falls back to a restart.
  /usr/bin/timeout 20 "${SYSTEMCTL_BIN}" reload caddy.service >/dev/null 2>&1 \
    || "${SYSTEMCTL_BIN}" restart caddy.service >/dev/null
}

activate_generation() {
  local relative_target="$1"
  "${CADDY_BIN}" validate \
    --adapter caddyfile --config "${CADDY_CONFIG}" >/dev/null
  restart_caddy
  publish_activation_marker "${relative_target#generations/}"
}

previous_target=""
if [ -L "${CURRENT}" ]; then
  previous_target="$(/usr/bin/readlink "${CURRENT}")"
  [[ "${previous_target}" =~ ^generations/[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
    printf 'ERROR: current certificate link has an unsafe target\n' >&2
    exit 1
  }
  "${VERIFY_BIN}" \
    "${CURRENT}/cert.pem" \
    "${CURRENT}/key.pem" \
    "${CA_BUNDLE}" \
    "${SERVICE_DNS}" \
    "${EXPECTED_ROOT_SHA256}" \
    "${EXPECTED_INTERMEDIATE_SHA256}" \
    -1 >/dev/null
elif [ -e "${CURRENT}" ]; then
  printf 'ERROR: current certificate path is not a symlink\n' >&2
  exit 1
fi

reconciled=false
if [ -n "${previous_target}" ] \
  && ! activation_marker_matches "${previous_target#generations/}"; then
  activate_generation "${previous_target}"
  reconciled=true
fi

current_is_fresh() {
  [ -L "${CURRENT}" ] \
    && "${VERIFY_BIN}" \
      "${CURRENT}/cert.pem" \
      "${CURRENT}/key.pem" \
      "${CA_BUNDLE}" \
      "${SERVICE_DNS}" \
      "${EXPECTED_ROOT_SHA256}" \
      "${EXPECTED_INTERMEDIATE_SHA256}" \
      "${RENEW_BEFORE_SECONDS}" >/dev/null 2>&1
}

if current_is_fresh; then
  if "${reconciled}"; then
    printf '{"status":"reconciled"}\n'
  else
    printf '{"status":"current"}\n'
  fi
  exit 0
fi

stage="$(/usr/bin/mktemp -d "${TLS_ROOT}/.staging.XXXXXXXX")"

"${STEP_BIN}" ca health \
  --ca-url "${CA_URL}" \
  --root "${CA_ROOT}" >/dev/null
"${STEP_BIN}" ca certificate \
  "${SERVICE_DNS}" "${stage}/cert.pem" "${stage}/key.pem" \
  --provisioner "${PROVISIONER_NAME}" \
  --provisioner-password-file "${PASSWORD_FILE}" \
  --ca-url "${CA_URL}" \
  --root "${CA_ROOT}" \
  --force >/dev/null

if [ "$(id -u)" -eq 0 ]; then
  /usr/bin/chown root:root "${stage}/cert.pem"
  /usr/bin/chown "root:${CADDY_GROUP}" "${stage}/key.pem"
  /usr/bin/chown "root:${CADDY_GROUP}" "${stage}"
fi
/usr/bin/chmod 0644 "${stage}/cert.pem"
/usr/bin/chmod 0640 "${stage}/key.pem"
/usr/bin/chmod 0750 "${stage}"
leaf_record="$(
  "${VERIFY_BIN}" \
    "${stage}/cert.pem" \
    "${stage}/key.pem" \
    "${CA_BUNDLE}" \
    "${SERVICE_DNS}" \
    "${EXPECTED_ROOT_SHA256}" \
    "${EXPECTED_INTERMEDIATE_SHA256}" \
    0
)"
printf '%s\n' "${leaf_record}" >"${stage}/fingerprint.sha256"
if [ "$(id -u)" -eq 0 ]; then
  /usr/bin/chown root:root "${stage}/fingerprint.sha256"
fi
/usr/bin/chmod 0644 "${stage}/fingerprint.sha256"

generation="${GENERATIONS}/$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-$$"
/usr/bin/mv -- "${stage}" "${generation}"
stage=""
/usr/bin/ln -s "generations/${generation##*/}" "${NEW_LINK}"
/usr/bin/mv -Tf -- "${NEW_LINK}" "${CURRENT}"

activation_ok=true
"${CADDY_BIN}" validate --adapter caddyfile --config "${CADDY_CONFIG}" >/dev/null \
  || activation_ok=false
if "${activation_ok}"; then
  restart_caddy || activation_ok=false
fi
if "${activation_ok}"; then
  publish_activation_marker "${generation##*/}" \
    || activation_ok=false
fi

if ! "${activation_ok}"; then
  if [ -n "${previous_target}" ]; then
    rollback_ok=true
    /usr/bin/ln -s "${previous_target}" "${NEW_LINK}"
    /usr/bin/mv -Tf -- "${NEW_LINK}" "${CURRENT}"
    "${VERIFY_BIN}" \
      "${CURRENT}/cert.pem" \
      "${CURRENT}/key.pem" \
      "${CA_BUNDLE}" \
      "${SERVICE_DNS}" \
      "${EXPECTED_ROOT_SHA256}" \
      "${EXPECTED_INTERMEDIATE_SHA256}" \
      0 >/dev/null || rollback_ok=false
    if "${rollback_ok}"; then
      "${CADDY_BIN}" validate \
        --adapter caddyfile --config "${CADDY_CONFIG}" >/dev/null \
        || rollback_ok=false
    fi
    if "${rollback_ok}"; then
      restart_caddy || rollback_ok=false
    fi
    if ! "${rollback_ok}"; then
      printf '{"status":"rollback-failed","reason":"caddy-recovery"}\n' >&2
      exit 2
    fi
    /usr/bin/rm -rf -- "${generation}"
  elif ! /usr/bin/grep -Fq "${CURRENT}/key.pem" "${CADDY_CONFIG}"; then
    /usr/bin/rm -f -- "${CURRENT}"
    /usr/bin/rm -rf -- "${generation}"
  else
    printf '{"status":"rollback-failed","reason":"no-prior-generation"}\n' >&2
    exit 1
  fi
  printf '{"status":"rolled-back","reason":"caddy-activation"}\n' >&2
  exit 1
fi

printf '{"status":"renewed","leaf_sha256":"%s"}\n' \
  "${leaf_record#leaf_sha256=}"
