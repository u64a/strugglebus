#!/usr/bin/env bash
set -euo pipefail

STEP_CA_VERSION=0.30.2
STEP_VERSION=0.30.6

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    arch=amd64
    step_ca_sha256=126615795bafe3f2d3f890e2d628fa6e2857315fb48d0671d34b23047cc37d73
    step_sha256=e44a5dc5f880a694b24a0f2941a69a81b0bc6ee053170fdfde18453d4d5816de
    ;;
  Linux:aarch64|Linux:arm64)
    arch=arm64
    step_ca_sha256=43f79d1b0b8cab9895dbadd46b0a014006f682a6b1341e1fadf0be31d4b9f4b4
    step_sha256=eff511c3e6797039702e74fada62b10b079e413742f925703e5b7d810e611619
    ;;
  *)
    printf 'ERROR: unsupported LAN CA test platform\n' >&2
    exit 1
    ;;
esac

work="${RUNNER_TEMP:?RUNNER_TEMP is required}/strugglebus-lan-ca-tools"
downloads="${work}/downloads"
bin="${work}/bin"
/usr/bin/mkdir -p "${downloads}" "${bin}"

fetch_and_install() {
  local url="$1" archive="$2" expected="$3" binary="$4"
  local tarball="${downloads}/${archive}" extracted="${downloads}/${binary}"
  /usr/bin/curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --show-error \
    --silent \
    --tlsv1.2 \
    "${url}" \
    --output "${tarball}"
  printf '%s  %s\n' "${expected}" "${tarball}" \
    | /usr/bin/sha256sum --check --status
  /usr/bin/mkdir -p "${extracted}"
  /usr/bin/tar --extract --gzip --file "${tarball}" --directory "${extracted}"
  source="$(
    /usr/bin/find "${extracted}" -type f -name "${binary}" -print -quit
  )"
  [ -n "${source}" ] || {
    printf 'ERROR: %s was absent from the verified archive\n' "${binary}" >&2
    exit 1
  }
  /usr/bin/install -m 0755 "${source}" "${bin}/${binary}"
}

fetch_and_install \
  "https://github.com/smallstep/certificates/releases/download/v${STEP_CA_VERSION}/step-ca_linux_${STEP_CA_VERSION}_${arch}.tar.gz" \
  "step-ca-${STEP_CA_VERSION}-${arch}.tar.gz" \
  "${step_ca_sha256}" \
  step-ca
fetch_and_install \
  "https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/step_linux_${STEP_VERSION}_${arch}.tar.gz" \
  "step-${STEP_VERSION}-${arch}.tar.gz" \
  "${step_sha256}" \
  step

"${bin}/step-ca" version >&2
"${bin}/step" version >&2
printf '%s\n' "${bin}"
