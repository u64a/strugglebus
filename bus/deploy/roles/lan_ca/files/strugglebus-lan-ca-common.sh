#!/usr/bin/env bash
set -euo pipefail

lan_ca_die() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

lan_ca_require_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || lan_ca_die "invalid SHA-256 input"
}

lan_ca_split_certificates() {
  local bundle="$1" destination="$2"
  "${AWK_BIN}" '
    /-----BEGIN CERTIFICATE-----/ { count += 1; output = destination "/cert-" count ".pem" }
    count > 0 { print > output }
    END { print count > destination "/count" }
  ' destination="${destination}" "${bundle}"
  [ "$(<"${destination}/count")" = "2" ] \
    || lan_ca_die "certificate input must contain exactly two certificates"
}

lan_ca_der_sha256() {
  "${OPENSSL_BIN}" x509 -in "$1" -outform DER \
    | "${SHA256SUM_BIN}" \
    | "${CUT_BIN}" -d ' ' -f 1
}

lan_ca_verify_bundle() {
  local bundle="$1" expected_root="$2" expected_intermediate="$3"
  local workspace root intermediate actual_root actual_intermediate
  lan_ca_require_sha256 "${expected_root}"
  lan_ca_require_sha256 "${expected_intermediate}"
  [ -f "${bundle}" ] && [ ! -L "${bundle}" ] \
    || lan_ca_die "CA bundle is missing or symlinked"

  workspace="$("${MKTEMP_BIN}" -d)"
  trap '"${RM_BIN}" -rf -- "${workspace}"' RETURN
  lan_ca_split_certificates "${bundle}" "${workspace}"
  root="${workspace}/cert-1.pem"
  intermediate="${workspace}/cert-2.pem"
  actual_root="$(lan_ca_der_sha256 "${root}")"
  actual_intermediate="$(lan_ca_der_sha256 "${intermediate}")"
  [ "${actual_root}" = "${expected_root}" ] \
    || lan_ca_die "root certificate DER fingerprint mismatch"
  [ "${actual_intermediate}" = "${expected_intermediate}" ] \
    || lan_ca_die "intermediate certificate DER fingerprint mismatch"
  "${OPENSSL_BIN}" verify -CAfile "${root}" "${root}" >/dev/null \
    || lan_ca_die "root certificate is not self-verifying"
  "${OPENSSL_BIN}" verify -CAfile "${root}" "${intermediate}" >/dev/null \
    || lan_ca_die "intermediate certificate is not signed by the expected root"
  "${OPENSSL_BIN}" x509 -in "${root}" -noout -text \
    | "${GREP_BIN}" -Fq 'CA:TRUE' \
    || lan_ca_die "root certificate is not a CA"
  "${OPENSSL_BIN}" x509 -in "${intermediate}" -noout -text \
    | "${GREP_BIN}" -Fq 'CA:TRUE' \
    || lan_ca_die "intermediate certificate is not a CA"
  trap - RETURN
  "${RM_BIN}" -rf -- "${workspace}"
  printf 'root_sha256=%s\nintermediate_sha256=%s\n' \
    "${actual_root}" "${actual_intermediate}"
}

lan_ca_public_key_sha256_from_certificate() {
  "${OPENSSL_BIN}" x509 -in "$1" -pubkey -noout \
    | "${OPENSSL_BIN}" pkey -pubin -outform DER \
    | "${SHA256SUM_BIN}" \
    | "${CUT_BIN}" -d ' ' -f 1
}

lan_ca_public_key_sha256_from_key() {
  "${OPENSSL_BIN}" pkey -in "$1" -pubout -outform DER \
    | "${SHA256SUM_BIN}" \
    | "${CUT_BIN}" -d ' ' -f 1
}

lan_ca_verify_certificate() {
  local chain="$1" key="$2" bundle="$3" service_dns="$4"
  local expected_root="$5" expected_intermediate="$6" minimum_seconds="$7"
  local workspace leaf intermediate san_value eku_value purpose
  local certificate_key_sha256 private_key_sha256 leaf_sha256
  local -a verify_time_arguments

  [[ "${service_dns}" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] \
    || lan_ca_die "service DNS name is invalid"
  if [ "${minimum_seconds}" = "-1" ]; then
    verify_time_arguments=(-no_check_time)
  else
    [[ "${minimum_seconds}" =~ ^[0-9]+$ ]] \
      || lan_ca_die "minimum certificate lifetime is invalid"
    verify_time_arguments=()
  fi
  [ -f "${chain}" ] && [ ! -L "${chain}" ] \
    || lan_ca_die "certificate chain is missing or symlinked"
  [ -f "${key}" ] && [ ! -L "${key}" ] \
    || lan_ca_die "private key is missing or symlinked"
  [ "$("${STAT_BIN}" -c '%a' "${key}")" = "640" ] \
    || lan_ca_die "active private key mode must be 0640"
  lan_ca_verify_bundle \
    "${bundle}" "${expected_root}" "${expected_intermediate}" >/dev/null

  workspace="$("${MKTEMP_BIN}" -d)"
  trap '"${RM_BIN}" -rf -- "${workspace}"' RETURN
  lan_ca_split_certificates "${chain}" "${workspace}"
  leaf="${workspace}/cert-1.pem"
  intermediate="${workspace}/cert-2.pem"
  [ "$(lan_ca_der_sha256 "${intermediate}")" = "${expected_intermediate}" ] \
    || lan_ca_die "leaf chain does not contain the expected intermediate"

  san_value="$(
    "${OPENSSL_BIN}" x509 -in "${leaf}" -noout -ext subjectAltName \
      | "${TAIL_BIN}" -n +2 \
      | "${TR_BIN}" -d '[:space:]'
  )"
  [ "${san_value}" = "DNS:${service_dns}" ] \
    || lan_ca_die "certificate must contain exactly the approved DNS SAN"
  eku_value="$(
    "${OPENSSL_BIN}" x509 -in "${leaf}" -noout -ext extendedKeyUsage \
      | "${TAIL_BIN}" -n +2 \
      | "${TR_BIN}" -d '[:space:]'
  )"
  [ "${eku_value}" = "TLSWebServerAuthentication" ] \
    || lan_ca_die "certificate must contain only the serverAuth extended key usage"
  "${OPENSSL_BIN}" x509 -in "${leaf}" -checkhost "${service_dns}" -noout \
    >/dev/null || lan_ca_die "certificate hostname verification failed"
  if [ "${minimum_seconds}" != "-1" ]; then
    "${OPENSSL_BIN}" x509 -in "${leaf}" -checkend "${minimum_seconds}" -noout \
      >/dev/null || lan_ca_die "certificate lifetime is below the required margin"
  fi

  purpose="$("${OPENSSL_BIN}" x509 -in "${leaf}" -purpose -noout)"
  "${GREP_BIN}" -Fqx 'SSL server : Yes' <<<"${purpose}" \
    || lan_ca_die "certificate is not valid for serverAuth"
  "${GREP_BIN}" -Fqx 'SSL client : No' <<<"${purpose}" \
    || lan_ca_die "certificate unexpectedly permits clientAuth"
  "${OPENSSL_BIN}" verify \
    "${verify_time_arguments[@]}" \
    -CAfile "${intermediate}" \
    -partial_chain \
    -purpose sslserver \
    -verify_hostname "${service_dns}" \
    "${leaf}" >/dev/null \
    || lan_ca_die "certificate chain verification failed"

  certificate_key_sha256="$(
    lan_ca_public_key_sha256_from_certificate "${leaf}"
  )"
  private_key_sha256="$(lan_ca_public_key_sha256_from_key "${key}")"
  [ "${certificate_key_sha256}" = "${private_key_sha256}" ] \
    || lan_ca_die "certificate and private key do not match"
  leaf_sha256="$(lan_ca_der_sha256 "${leaf}")"
  trap - RETURN
  "${RM_BIN}" -rf -- "${workspace}"
  printf 'leaf_sha256=%s\n' "${leaf_sha256}"
}
