#!/bin/bash
# Updates a Docker-hosted Strugglebus from the public release page. Run it on
# the Docker host, from the folder that holds compose.yaml.
#
#   bash update.sh status   show the setting and the installed version
#   bash update.sh now      check and install now, whatever the setting
#   bash update.sh check    for a daily schedule: installs only when automatic
#                           updates are on (the button in the console under
#                           Administration > Updates)
set -euo pipefail

# Everything is inside main so the whole file is read before any of it runs:
# an update replaces this file while it is running.
main() {
  local command="${1:-status}"
  cd "$(dirname "${BASH_SOURCE[0]}")"

  # Dated, because the scheduled check appends these lines to update.log.
  say() { echo "$(date '+%Y-%m-%d %H:%M:%S') strugglebus-update: $*"; }
  fail() { echo "$(date '+%Y-%m-%d %H:%M:%S') strugglebus-update: ERROR: $*" >&2; exit 1; }
  in_bus() { docker compose exec -T bus "$@"; }
  local -a fetch_options=() run_options=()
  # Optional, for a mirror of the release page: RELEASE_API,
  # RELEASE_DOWNLOAD_PREFIX and FETCH_NETWORK (a docker network name).
  if [ -r update.conf ]; then
    # shellcheck disable=SC1091
    . ./update.conf
    [ -z "${RELEASE_API:-}" ] || fetch_options+=(--api "$RELEASE_API")
    [ -z "${RELEASE_DOWNLOAD_PREFIX:-}" ] || fetch_options+=(--download-prefix "$RELEASE_DOWNLOAD_PREFIX")
    [ -z "${FETCH_NETWORK:-}" ] || run_options+=(--network "$FETCH_NETWORK")
  fi

  docker compose version >/dev/null 2>&1 || fail "'docker compose' is not available to this account."
  [ -f compose.yaml ] && [ -f fetch_release.py ] \
    || fail "compose.yaml and fetch_release.py must be in $(pwd). Run this from the Strugglebus install folder."
  [ -n "$(docker compose ps --status running -q bus 2>/dev/null)" ] \
    || fail "the bus container is not running. Start it with: docker compose up -d"

  setting() {
    local value
    value="$(in_bus sh -c 'head -c 8 /data/bus/selfhost/auto-update 2>/dev/null || true' | tr -d '[:space:]')"
    if [ "$value" = "off" ]; then echo off; else echo on; fi
  }

  installed_version() {
    in_bus strugglebus --version | tr -d '\r' | awk '{print $NF}'
  }

  record() {
    # record <result> <installed> <latest> <detail>; the console shows it.
    in_bus /opt/strugglebus/bin/python - "$(setting)" "$@" <<'PY' || true
import json, os, sys, time
setting, result, installed, latest, detail = sys.argv[1:6]
path = "/data/bus/selfhost/update-status.json"
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
record = {
    "checked_at": int(time.time()), "auto_update": setting, "result": result,
    "installed_version": installed, "latest_version": latest, "detail": detail[:500],
}
with open(path + ".new", "w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
os.replace(path + ".new", path)
PY
  }

  healthy() {
    local container
    for _ in $(seq 1 90); do
      container="$(docker compose ps -q bus 2>/dev/null || true)"
      if [ -n "$container" ] && [ "$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null)" = "healthy" ]; then
        return 0
      fi
      sleep 2
    done
    return 1
  }

  update() {
    local mode="$1" installed answer code word latest kit name
    installed="$(installed_version)"
    [ -n "$installed" ] || fail "could not read the installed version from the bus container."
    if [ "$mode" = "check" ] && [ "$(setting)" = "off" ]; then
      record off "$installed" "" "Automatic updates are turned off."
      say "automatic updates are turned off; nothing was checked. 'bash update.sh now' updates once."
      return 0
    fi

    mkdir -p .update
    rm -rf .update/release.new
    set +e
    answer="$(docker run --rm --user "$(id -u):$(id -g)" "${run_options[@]}" -v "$PWD":/w -w /w \
      python:3.13-slim python fetch_release.py --installed "$installed" \
      --into .update/release.new "${fetch_options[@]}" 2>.update/fetch.err)"
    code=$?
    set -e
    if [ "$code" != "0" ]; then
      rm -rf .update/release.new
      if [ "$code" = "3" ]; then
        record unreachable "$installed" "" "The release page could not be reached. This will be tried again at the next check."
      else
        record invalid "$installed" "" "$(tail -n 1 .update/fetch.err)"
      fi
      cat .update/fetch.err >&2
      fail "could not get the newest release; nothing was changed."
    fi
    read -r word latest <<<"$(printf '%s' "$answer" | tr -d '\r')"
    if [ "$word" = "current" ]; then
      record current "$installed" "$latest" "This is the newest release."
      say "version $installed is the newest release."
      return 0
    fi
    if [ "$mode" = "check" ] && [ "$(cat .update/failed-version 2>/dev/null)" = "$latest" ]; then
      rm -rf .update/release.new
      record failed "$installed" "$latest" "Version $latest did not install last time and is not retried automatically. Run 'bash update.sh now' on the Docker host to try again."
      say "version $latest did not install last time; not retrying automatically. Run 'bash update.sh now' to try again."
      return 0
    fi

    say "installing version $latest (currently $installed)"
    if ! in_bus strugglebus backup >/dev/null; then
      rm -rf .update/release.new
      record failed "$installed" "$latest" "The backup before the update failed, so nothing was changed."
      fail "the backup before the update failed, so nothing was changed. Run 'docker compose exec bus strugglebus backup' to see why."
    fi
    # Keep the files of the running version so they can be put back.
    rm -rf .update/previous
    mkdir .update/previous
    for name in strugglebus-*.whl requirements.lock SHA256SUMS Dockerfile compose.yaml \
        Caddyfile entrypoint.sh info.sh env.example update.sh fetch_release.py; do
      [ ! -f "$name" ] || cp -p "$name" .update/previous/
    done
    kit=".update/release.new/_wheel/strugglebus/selfhost"
    rm -f strugglebus-*.whl
    cp .update/release.new/strugglebus-*.whl .update/release.new/requirements.lock .update/release.new/SHA256SUMS .
    cp "$kit"/docker/* .
    cp "$kit/fetch_release.py" .
    # An update is the whole install: the application, the gateway
    # configuration, these scripts, and the images the container is built
    # from, which carry the gateway (Caddy) and Python. Without a route to the
    # image registry the build below uses the images already on this host.
    docker compose build --pull >.update/last-install.log 2>&1 \
      || say "could not refresh the gateway and Python images; building with the ones already here"
    if docker compose up -d --build >>.update/last-install.log 2>&1 && healthy; then
      rm -f .update/failed-version
      rm -rf .update/release.new
      record updated "$latest" "$latest" "Updated from $installed to $latest."
      say "updated from $installed to $latest."
      return 0
    fi
    say "version $latest did not start; putting version $installed back"
    echo "$latest" > .update/failed-version
    rm -f strugglebus-*.whl
    cp -p .update/previous/* .
    rm -rf .update/release.new
    if docker compose up -d --build >>.update/last-install.log 2>&1 && healthy; then
      record failed "$installed" "$latest" "Version $latest did not start, so version $installed was put back and is running."
      fail "version $latest did not start, so version $installed was put back and is running. The log is $(pwd)/.update/last-install.log"
    fi
    # The bus is down, so the console cannot be told; the line below is the record.
    fail "version $latest did not start, and version $installed did not start either. The database may have been changed by the update; the copy taken before it is in the data volume under /data/backups. The log is $(pwd)/.update/last-install.log"
  }

  case "$command" in
    status)
      echo "Automatic updates : $(setting)"
      echo "Installed version : $(installed_version)"
      ;;
    check|now) update "$command" ;;
    -h|--help|help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *) fail "unknown command '$command'. Use: status, now, check." ;;
  esac
}

main "$@"
exit 0
