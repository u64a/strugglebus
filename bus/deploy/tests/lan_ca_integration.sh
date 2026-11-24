#!/usr/bin/env bash
set -euo pipefail

for command in step step-ca openssl python3 flock; do
  command -v "${command}" >/dev/null 2>&1 || {
    printf 'ERROR: required integration command is unavailable: %s\n' "${command}" >&2
    exit 1
  }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY="$(cd "${HERE}/../.." && pwd)"
SUPPORT="${HERE}/lan_ca_test_support.py"
COMMON="${REPOSITORY}/deploy/roles/lan_ca/files/strugglebus-lan-ca-common.sh"
VERIFY_BUNDLE="${REPOSITORY}/deploy/roles/lan_ca/files/strugglebus-verify-ca-bundle.sh"
VERIFY_CERT_SOURCE="${REPOSITORY}/deploy/roles/lan_ca/files/strugglebus-verify-certificate.sh"
RENEW="${REPOSITORY}/deploy/roles/lan_ca/files/strugglebus-renew-certificate.sh"
EXPIRY="${REPOSITORY}/deploy/roles/lan_ca/files/strugglebus-check-certificate-expiry.sh"
TEMPLATE="${HERE}/fixtures/lan-ca/strugglebus-server.tpl"

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/strugglebus-lan-ca.XXXXXXXX")"
chmod 0700 "${work}"
VERIFY_CERT="${work}/strugglebus-verify-certificate"
cp "${VERIFY_CERT_SOURCE}" "${VERIFY_CERT}"
chmod 0755 "${VERIFY_CERT}"
ca_pid=""
cleanup() {
  if [ -n "${ca_pid}" ] && kill -0 "${ca_pid}" >/dev/null 2>&1; then
    kill "${ca_pid}" >/dev/null 2>&1 || true
    wait "${ca_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${work}"
}
trap cleanup EXIT

ca_dns=localhost
service_dns=bus.u64.lan
denied_dns=denied.invalid
provisioner=jwk-strugglebus
root_crt="${work}/root.crt"
root_key="${work}/root.key"
wrong_root_crt="${work}/wrong-root.crt"
wrong_root_key="${work}/wrong-root.key"
intermediate_crt="${work}/intermediate.crt"
intermediate_key="${work}/intermediate.key"
intermediate_password="${work}/intermediate-password"
jwk_public="${work}/jwk-public.json"
jwk_private="${work}/jwk-private.jwe"
jwk_password="${work}/jwk-password"
wrong_password="${work}/wrong-password"
bundle="${work}/ca-bundle.pem"
database="${work}/db"
config="${work}/ca.json"
mkdir -m 0700 "${database}"
printf '%s' 'test-only-intermediate-password' >"${intermediate_password}"
printf '%s' 'test-only-jwk-password' >"${jwk_password}"
printf '%s' 'wrong-test-only-password' >"${wrong_password}"
chmod 0600 "${intermediate_password}" "${jwk_password}" "${wrong_password}"

step certificate create \
  'Test LAN Root' "${root_crt}" "${root_key}" \
  --profile root-ca --kty EC --curve P-384 --not-after 8760h \
  --no-password --insecure --force >/dev/null
step certificate create \
  'Unrelated Test Root' "${wrong_root_crt}" "${wrong_root_key}" \
  --profile root-ca --kty EC --curve P-384 --not-after 8760h \
  --no-password --insecure --force >/dev/null
step certificate create \
  'Test LAN Intermediate' "${intermediate_crt}" "${intermediate_key}" \
  --profile intermediate-ca --kty EC --curve P-384 --not-after 720h \
  --ca "${root_crt}" --ca-key "${root_key}" \
  --password-file "${intermediate_password}" --force >/dev/null
step crypto jwk create "${jwk_public}" "${jwk_private}" \
  --kty EC --crv P-256 --use sig \
  --password-file "${jwk_password}" --force >/dev/null
cat "${root_crt}" "${intermediate_crt}" >"${bundle}"

root_sha256="$(
  openssl x509 -in "${root_crt}" -outform DER | sha256sum | cut -d ' ' -f 1
)"
intermediate_sha256="$(
  openssl x509 -in "${intermediate_crt}" -outform DER \
    | sha256sum | cut -d ' ' -f 1
)"

port="$(python3 "${SUPPORT}" free-port)"
python3 "${SUPPORT}" render-config \
  --root "${root_crt}" \
  --intermediate "${intermediate_crt}" \
  --intermediate-key "${intermediate_key}" \
  --jwk-public "${jwk_public}" \
  --jwk-private "${jwk_private}" \
  --template "${TEMPLATE}" \
  --database "${database}" \
  --ca-dns "${ca_dns}" \
  --service-dns "${service_dns}" \
  --provisioner "${provisioner}" \
  --port "${port}" \
  --output "${config}"

step-ca "${config}" --password-file "${intermediate_password}" \
  >"${work}/step-ca.log" 2>&1 &
ca_pid=$!
for _ in $(seq 1 40); do
  if python3 "${SUPPORT}" tls-health \
    --port "${port}" --sni "${ca_dns}" --root "${root_crt}" \
    >/dev/null 2>&1; then
    break
  fi
  kill -0 "${ca_pid}" >/dev/null 2>&1 || {
    printf 'ERROR: isolated step-ca exited before health verification\n' >&2
    exit 1
  }
  sleep 0.25
done
python3 "${SUPPORT}" tls-health \
  --port "${port}" --sni "${ca_dns}" --root "${root_crt}"
if python3 "${SUPPORT}" tls-health \
  --port "${port}" --sni "${ca_dns}" --root "${wrong_root_crt}" \
  >/dev/null 2>&1; then
  printf 'ERROR: CA endpoint accepted the wrong trust anchor\n' >&2
  exit 1
fi

ca_url="https://${ca_dns}:${port}"
if step ca certificate \
  "${service_dns}" "${work}/wrong.crt" "${work}/wrong.key" \
  --provisioner "${provisioner}" \
  --provisioner-password-file "${wrong_password}" \
  --ca-url "${ca_url}" --root "${root_crt}" --force \
  >/dev/null 2>&1; then
  printf 'ERROR: wrong JWK password was accepted\n' >&2
  exit 1
fi
if step ca certificate \
  "${denied_dns}" "${work}/denied.crt" "${work}/denied.key" \
  --provisioner "${provisioner}" \
  --provisioner-password-file "${jwk_password}" \
  --ca-url "${ca_url}" --root "${root_crt}" --force \
  >/dev/null 2>&1; then
  printf 'ERROR: unauthorized SAN was issued\n' >&2
  exit 1
fi
if step ca certificate \
  "${ca_dns}" "${work}/ca-name.crt" "${work}/ca-name.key" \
  --provisioner "${provisioner}" \
  --provisioner-password-file "${jwk_password}" \
  --ca-url "${ca_url}" --root "${root_crt}" --force \
  >/dev/null 2>&1; then
  printf 'ERROR: service provisioner issued the CA endpoint identity\n' >&2
  exit 1
fi

STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${VERIFY_BUNDLE}" \
    "${bundle}" "${root_sha256}" "${intermediate_sha256}" >/dev/null
if STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${VERIFY_BUNDLE}" \
    "${bundle}" "${intermediate_sha256}" "${root_sha256}" >/dev/null 2>&1; then
  printf 'ERROR: swapped CA fingerprints were accepted\n' >&2
  exit 1
fi

credentials="${work}/credentials"
tls_root="${work}/tls"
mkdir -m 0700 "${credentials}" "${tls_root}"
cp "${jwk_password}" "${credentials}/jwk-password"
chmod 0600 "${credentials}/jwk-password"
caddy_config="${work}/Caddyfile"
printf 'internal-test-config\n' >"${caddy_config}"
environment="${work}/renew.env"
cat >"${environment}" <<EOF
CA_URL=${ca_url}
CA_ROOT=${root_crt}
CA_BUNDLE=${bundle}
PROVISIONER_NAME=${provisioner}
SERVICE_DNS=${service_dns}
TLS_ROOT=${tls_root}
CADDY_CONFIG=${caddy_config}
EXPECTED_ROOT_SHA256=${root_sha256}
EXPECTED_INTERMEDIATE_SHA256=${intermediate_sha256}
RENEW_BEFORE_SECONDS=57600
WARNING_SECONDS=43200
CRITICAL_SECONDS=14400
CADDY_GROUP=$(id -gn)
EOF

caddy_shim="${work}/caddy"
systemctl_shim="${work}/systemctl"
cat >"${caddy_shim}" <<'EOF'
#!/usr/bin/env bash
printf 'validate\n' >>"${CADDY_TEST_LOG:?}"
if [ "${CADDY_TEST_RESULT:-ok}" = fail-once ] \
  && [ ! -f "${CADDY_TEST_STATE:?}" ]; then
  touch "${CADDY_TEST_STATE}"
  exit 1
fi
if [ "${CADDY_TEST_RESULT:-ok}" = fail-always ]; then
  exit 1
fi
exit 0
EOF
cat >"${systemctl_shim}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${1:-}" >>"${SYSTEMCTL_TEST_LOG:?}"
# fail-once fails the first call (the reload), fail-twice the reload and its
# restart fallback.
calls=$(( $(cat "${SYSTEMCTL_TEST_STATE:?}" 2>/dev/null || echo 0) + 1 ))
printf '%s\n' "${calls}" >"${SYSTEMCTL_TEST_STATE}"
case "${SYSTEMCTL_TEST_RESULT:-ok}" in
  fail-once) [ "${calls}" -gt 1 ] || exit 1 ;;
  fail-twice) [ "${calls}" -gt 2 ] || exit 1 ;;
esac
exit 0
EOF
chmod 0755 "${caddy_shim}" "${systemctl_shim}"

run_renew() {
  CREDENTIALS_DIRECTORY="${credentials}" \
  STRUGGLEBUS_LAN_CA_ENV="${environment}" \
  STRUGGLEBUS_LAN_CA_TEST_STEP="$(command -v step)" \
  STRUGGLEBUS_LAN_CA_TEST_CADDY="${caddy_shim}" \
  STRUGGLEBUS_LAN_CA_TEST_SYSTEMCTL="${systemctl_shim}" \
  STRUGGLEBUS_LAN_CA_TEST_VERIFY="${VERIFY_CERT}" \
  STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  CADDY_TEST_LOG="${work}/caddy-events" \
  CADDY_TEST_STATE="${work}/caddy-failed-once" \
  SYSTEMCTL_TEST_LOG="${work}/systemctl-events" \
  SYSTEMCTL_TEST_STATE="${work}/systemctl-failed-once" \
    bash "${RENEW}"
}

run_renew | grep -Fq '"status":"renewed"'
first_target="$(readlink "${tls_root}/current")"
[ -f "${tls_root}/current/activated.sha256" ]
run_renew | grep -Fq '"status":"current"'
[ "$(readlink "${tls_root}/current")" = "${first_target}" ]
rm -f "${tls_root}/current/activated.sha256"
run_renew | grep -Fq '"status":"reconciled"'
[ -f "${tls_root}/current/activated.sha256" ]
[ "$(readlink "${tls_root}/current")" = "${first_target}" ]
generation_count_before="$(find "${tls_root}/generations" -mindepth 1 -maxdepth 1 -type d | wc -l)"
ln -sfn ../unsafe-current-target "${tls_root}/current"
if run_renew >/dev/null 2>&1; then
  printf 'ERROR: unsafe current generation link was accepted\n' >&2
  exit 1
fi
[ "$(find "${tls_root}/generations" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq "${generation_count_before}" ]
ln -sfn "${first_target}" "${tls_root}/current"
chmod 0640 "${root_key}"
if STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${VERIFY_CERT}" \
    "${tls_root}/current/cert.pem" \
    "${root_key}" \
    "${bundle}" "${service_dns}" \
    "${root_sha256}" "${intermediate_sha256}" 0 >/dev/null 2>&1; then
  printf 'ERROR: mismatched certificate and key were accepted\n' >&2
  exit 1
fi

root_signed_key="${work}/root-signed.key"
root_signed_csr="${work}/root-signed.csr"
root_signed_leaf="${work}/root-signed-leaf.crt"
root_signed_chain="${work}/root-signed-chain.pem"
root_signed_extensions="${work}/root-signed.cnf"
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/CN=${service_dns}" \
  -keyout "${root_signed_key}" -out "${root_signed_csr}" >/dev/null 2>&1
cat >"${root_signed_extensions}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:${service_dns}
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "${root_signed_csr}" \
  -CA "${root_crt}" -CAkey "${root_key}" -CAcreateserial \
  -days 1 -sha256 -extfile "${root_signed_extensions}" \
  -out "${root_signed_leaf}" >/dev/null 2>&1
cat "${root_signed_leaf}" "${intermediate_crt}" >"${root_signed_chain}"
chmod 0640 "${root_signed_key}"
if STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${VERIFY_CERT}" \
    "${root_signed_chain}" "${root_signed_key}" \
    "${bundle}" "${service_dns}" \
    "${root_sha256}" "${intermediate_sha256}" 0 >/dev/null 2>&1; then
  printf 'ERROR: root-signed leaf bypassed the required intermediate\n' >&2
  exit 1
fi

extra_eku_key="${work}/extra-eku.key"
extra_eku_csr="${work}/extra-eku.csr"
extra_eku_leaf="${work}/extra-eku-leaf.crt"
extra_eku_chain="${work}/extra-eku-chain.pem"
extra_eku_extensions="${work}/extra-eku.cnf"
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/CN=${service_dns}" \
  -keyout "${extra_eku_key}" -out "${extra_eku_csr}" >/dev/null 2>&1
cat >"${extra_eku_extensions}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:${service_dns}
extendedKeyUsage=serverAuth,codeSigning
EOF
openssl x509 -req -in "${extra_eku_csr}" \
  -CA "${intermediate_crt}" -CAkey "${intermediate_key}" \
  -passin "file:${intermediate_password}" -CAcreateserial \
  -days 1 -sha256 -extfile "${extra_eku_extensions}" \
  -out "${extra_eku_leaf}" >/dev/null 2>&1
cat "${extra_eku_leaf}" "${intermediate_crt}" >"${extra_eku_chain}"
chmod 0640 "${extra_eku_key}"
if STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${VERIFY_CERT}" \
    "${extra_eku_chain}" "${extra_eku_key}" \
    "${bundle}" "${service_dns}" \
    "${root_sha256}" "${intermediate_sha256}" 0 >/dev/null 2>&1; then
  printf 'ERROR: certificate with an additional EKU was accepted\n' >&2
  exit 1
fi

sed -i 's/RENEW_BEFORE_SECONDS=57600/RENEW_BEFORE_SECONDS=90000/' "${environment}"
rm -f "${work}/caddy-failed-once"
CADDY_TEST_RESULT=fail-once run_renew >/dev/null 2>&1 && {
  printf 'ERROR: Caddy validation failure was ignored\n' >&2
  exit 1
}
[ "$(readlink "${tls_root}/current")" = "${first_target}" ]
[ "$(find "${tls_root}/generations" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq "${generation_count_before}" ]
[ "$(grep -c '^validate$' "${work}/caddy-events")" -ge 3 ]
STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${VERIFY_CERT}" \
    "${tls_root}/current/cert.pem" \
    "${tls_root}/current/key.pem" \
    "${bundle}" "${service_dns}" \
    "${root_sha256}" "${intermediate_sha256}" 0 >/dev/null

rm -f "${work}/systemctl-failed-once" "${work}/systemctl-events"
SYSTEMCTL_TEST_RESULT=fail-once run_renew | grep -Fq '"status":"renewed"'
[ "$(cat "${work}/systemctl-events")" = "$(printf 'reload\nrestart')" ]
fallback_target="$(readlink "${tls_root}/current")"
[ "${fallback_target}" != "${first_target}" ]
ln -sfn "${first_target}" "${tls_root}/current"
rm -rf -- "${tls_root:?}/${fallback_target}"

rm -f "${work}/systemctl-failed-once" "${work}/systemctl-events"
SYSTEMCTL_TEST_RESULT=fail-twice run_renew >/dev/null 2>&1 && {
  printf 'ERROR: Caddy reload and restart failure was ignored\n' >&2
  exit 1
}
[ "$(readlink "${tls_root}/current")" = "${first_target}" ]
[ "$(find "${tls_root}/generations" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq "${generation_count_before}" ]
[ "$(head -2 "${work}/systemctl-events")" = "$(printf 'reload\nrestart')" ]

set +e
rollback_failure_output="$(CADDY_TEST_RESULT=fail-always run_renew 2>&1)"
rollback_failure_rc=$?
set -e
[ "${rollback_failure_rc}" -eq 2 ]
grep -Fq '"status":"rollback-failed"' <<<"${rollback_failure_output}"
[ "$(readlink "${tls_root}/current")" = "${first_target}" ]
[ "$(find "${tls_root}/generations" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq "$((generation_count_before + 1))" ]
find "${tls_root}/generations" \
  -mindepth 1 -maxdepth 1 -type d \
  ! -name "${first_target#generations/}" -exec rm -rf -- {} +

lock_ready="${work}/lock-ready"
(
  exec 8>"${tls_root}/.renew.lock"
  flock 8
  touch "${lock_ready}"
  sleep 2
) &
lock_pid=$!
for _ in $(seq 1 20); do
  [ -f "${lock_ready}" ] && break
  sleep 0.05
done
[ -f "${lock_ready}" ]
set +e
run_renew >/dev/null 2>&1
concurrent_rc=$?
set -e
if [ "${concurrent_rc}" -ne 75 ]; then
  printf 'ERROR: concurrent renewal was accepted\n' >&2
  exit 1
fi
wait "${lock_pid}"

step_failure="${work}/step-failure"
cat >"${step_failure}" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = ca ] && [ "\${2:-}" = health ]; then
  exec "$(command -v step)" "\$@"
fi
exit 1
EOF
chmod 0755 "${step_failure}"
before_partial="$(readlink "${tls_root}/current")"
if CREDENTIALS_DIRECTORY="${credentials}" \
  STRUGGLEBUS_LAN_CA_ENV="${environment}" \
  STRUGGLEBUS_LAN_CA_TEST_STEP="${step_failure}" \
  STRUGGLEBUS_LAN_CA_TEST_CADDY="${caddy_shim}" \
  STRUGGLEBUS_LAN_CA_TEST_SYSTEMCTL="${systemctl_shim}" \
  STRUGGLEBUS_LAN_CA_TEST_VERIFY="${VERIFY_CERT}" \
  STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${RENEW}" >/dev/null 2>&1; then
  printf 'ERROR: partial issuance unexpectedly succeeded\n' >&2
  exit 1
fi
[ "$(readlink "${tls_root}/current")" = "${before_partial}" ]
if find "${tls_root}" -maxdepth 1 -name '.staging.*' -print -quit | grep -q .; then
  printf 'ERROR: partial generation remained visible\n' >&2
  exit 1
fi

expired_target="${tls_root}/generations/20260901T010101Z-999"
mkdir -m 0750 "${expired_target}"
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/CN=${service_dns}" \
  -keyout "${expired_target}/key.pem" \
  -out "${work}/expired.csr" >/dev/null 2>&1
openssl x509 -req -in "${work}/expired.csr" \
  -CA "${intermediate_crt}" -CAkey "${intermediate_key}" \
  -passin "file:${intermediate_password}" -CAcreateserial \
  -days 0 -sha256 -extfile "${root_signed_extensions}" \
  -out "${work}/expired-leaf.crt" >/dev/null 2>&1
cat "${work}/expired-leaf.crt" "${intermediate_crt}" \
  >"${expired_target}/cert.pem"
chmod 0640 "${expired_target}/key.pem"
chmod 0644 "${expired_target}/cert.pem"
expired_fingerprint="$(
  openssl x509 -in "${work}/expired-leaf.crt" -outform DER \
    | sha256sum | cut -d ' ' -f 1
)"
printf 'leaf_sha256=%s\n' "${expired_fingerprint}" \
  >"${expired_target}/fingerprint.sha256"
cp "${expired_target}/fingerprint.sha256" \
  "${expired_target}/activated.sha256"
chmod 0644 \
  "${expired_target}/fingerprint.sha256" \
  "${expired_target}/activated.sha256"
ln -sfn "generations/${expired_target##*/}" "${tls_root}/current.new"
mv -Tf "${tls_root}/current.new" "${tls_root}/current"
sleep 1
run_renew | grep -Fq '"status":"renewed"'

issue_expiry_case() {
  local duration="$1" expected_rc="$2" expected_status="$3"
  local target="${tls_root}/generations/expiry-${duration}"
  mkdir -m 0750 "${target}"
  step ca certificate \
    "${service_dns}" "${target}/cert.pem" "${target}/key.pem" \
    --provisioner "${provisioner}" \
    --provisioner-password-file "${jwk_password}" \
    --ca-url "${ca_url}" --root "${root_crt}" \
    --not-after "${duration}" --force >/dev/null
  chmod 0640 "${target}/key.pem"
  chmod 0644 "${target}/cert.pem"
  ln -sfn "generations/expiry-${duration}" "${tls_root}/current.new"
  mv -Tf "${tls_root}/current.new" "${tls_root}/current"
  status="${work}/expiry-${duration}.json"
  set +e
  STRUGGLEBUS_LAN_CA_ENV="${environment}" \
  STRUGGLEBUS_LAN_CA_TEST_VERIFY="${VERIFY_CERT}" \
  STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
    bash "${EXPIRY}" "${status}" >/dev/null 2>&1
  actual_rc=$?
  set -e
  [ "${actual_rc}" -eq "${expected_rc}" ]
  grep -Fq "\"status\":\"${expected_status}\"" "${status}"
}

issue_expiry_case 13h 0 ok
issue_expiry_case 8h 1 warning
issue_expiry_case 3h 2 critical

rm -f "${tls_root}/current"
missing_status="${work}/expiry-missing.json"
set +e
STRUGGLEBUS_LAN_CA_ENV="${environment}" \
STRUGGLEBUS_LAN_CA_TEST_VERIFY="${VERIFY_CERT}" \
STRUGGLEBUS_LAN_CA_TEST_COMMON="${COMMON}" \
  bash "${EXPIRY}" "${missing_status}" >/dev/null 2>&1
missing_rc=$?
set -e
[ "${missing_rc}" -eq 2 ]
grep -Fq '"status":"critical"' "${missing_status}"
grep -Fq '"reason":"certificate-invalid"' "${missing_status}"

stale_status="${work}/expiry-stale.json"
printf '{"status":"ok","reason":"stale"}\n' >"${stale_status}"
set +e
STRUGGLEBUS_LAN_CA_ENV="${work}/missing-renew.env" \
  bash "${EXPIRY}" "${stale_status}" >/dev/null 2>&1
configuration_rc=$?
set -e
[ "${configuration_rc}" -eq 2 ]
grep -Fq '"status":"critical"' "${stale_status}"
grep -Fq '"reason":"configuration-unavailable"' "${stale_status}"

printf 'LAN CA integration passed against isolated real step-ca\n'
