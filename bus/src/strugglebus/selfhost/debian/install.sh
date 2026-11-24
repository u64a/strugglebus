#!/bin/bash
# Installs or upgrades Strugglebus on a Debian 13 machine, VM or Proxmox container.
#
#   sudo bash install.sh --hostname bus.home.arpa [--port 443] [--release-dir DIR]
#                        [--auto-update on|off] [--allow-clients "RANGE ..."]
#
# Run it again with a newer release folder to upgrade; settings and data are kept.
# Automatic updates are on unless you pass --auto-update off; change it later
# with 'strugglebus-update on|off' or in the console.
# The bus only answers clients on private networks. --allow-clients adds your
# own ranges (for example "203.0.113.0/24") if your network uses other addresses.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTNAME_ARG=""
PORT_ARG=""
RELEASE_DIR="$PWD"
AUTO_UPDATE_ARG=""
ALLOW_CLIENTS_ARG=""
ALLOW_CLIENTS_SET=no
ENV_FILE=/etc/strugglebus/strugglebus.env
TOKEN_FILE=/etc/strugglebus/credentials/admin-token
CA_FILE=/etc/strugglebus/ca-root.crt
PREFIX=/opt/strugglebus
DATA_DIR=/var/lib/strugglebus
BACKUP_DIR=/var/backups/strugglebus
UPDATE_STATE=/var/lib/strugglebus-update
UPDATE_SWITCH=$DATA_DIR/selfhost/auto-update
ALLOWED_CLIENTS_FILE=/etc/strugglebus/allowed-clients
GATEWAY_ROOT=/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt

say() { echo "strugglebus-install: $*"; }
fail() { echo "strugglebus-install: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --hostname) HOSTNAME_ARG="${2:-}"; shift 2 ;;
    --port) PORT_ARG="${2:-}"; shift 2 ;;
    --release-dir) RELEASE_DIR="${2:-}"; shift 2 ;;
    --auto-update) AUTO_UPDATE_ARG="${2:-}"; shift 2 ;;
    --allow-clients) ALLOW_CLIENTS_ARG="${2:-}"; ALLOW_CLIENTS_SET=yes; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown option '$1'. Usage: install.sh --hostname NAME [--port 443] [--release-dir DIR] [--auto-update on|off] [--allow-clients RANGES]" ;;
  esac
done

case "$AUTO_UPDATE_ARG" in
  ''|on|off) ;;
  *) fail "--auto-update must be 'on' or 'off' (got '$AUTO_UPDATE_ARG')." ;;
esac
[ "$(id -u)" = "0" ] || fail "run this as root (sudo bash install.sh ...)."
command -v systemctl >/dev/null || fail "this installer needs systemd. For Docker hosts use the docker folder instead."
[ -d /run/systemd/system ] || fail "systemd is not running here. For Docker hosts use the docker folder instead."

# --- settings: from the command line, else from the previous install -----------
UPGRADE=no
if [ -s "$ENV_FILE" ]; then
  UPGRADE=yes
  previous_url="$(sed -n 's/^STRUGGLEBUS_PUBLIC_BASE_URL=https:\/\///p' "$ENV_FILE")"
  [ -n "$HOSTNAME_ARG" ] || HOSTNAME_ARG="${previous_url%%:*}"
  if [ -z "$PORT_ARG" ]; then
    case "$previous_url" in *:*) PORT_ARG="${previous_url##*:}" ;; *) PORT_ARG=443 ;; esac
  fi
fi
# Extra client ranges for the gateway's private-network guard: from the
# command line, else what the previous install saved. Usually empty.
if [ "$ALLOW_CLIENTS_SET" = "yes" ]; then
  ALLOWED_CLIENTS="$ALLOW_CLIENTS_ARG"
elif [ -f "$ALLOWED_CLIENTS_FILE" ]; then
  ALLOWED_CLIENTS="$(head -n 1 "$ALLOWED_CLIENTS_FILE")"
else
  ALLOWED_CLIENTS=""
fi
case "$ALLOWED_CLIENTS" in
  *[!0-9a-fA-F:./\ ]*) fail "--allow-clients takes address ranges such as 203.0.113.0/24, separated by spaces (got '$ALLOWED_CLIENTS')." ;;
esac
BUS_HOSTNAME="$HOSTNAME_ARG"
BUS_PORT="${PORT_ARG:-443}"
[ -n "$BUS_HOSTNAME" ] || fail "--hostname is required: the name people will type to reach the bus, for example --hostname bus.home.arpa"
case "$BUS_HOSTNAME" in
  *[!a-z0-9.-]*) fail "--hostname must be a lower-case DNS name such as bus.home.arpa (got '$BUS_HOSTNAME'). Do not include https:// or a port." ;;
esac
case "$BUS_PORT" in ''|*[!0-9]*) fail "--port must be a number (got '$BUS_PORT')." ;; esac
PORT_SUFFIX=""
[ "$BUS_PORT" = "443" ] || PORT_SUFFIX=":$BUS_PORT"
BASE_URL="https://${BUS_HOSTNAME}${PORT_SUFFIX}"

# --- release files ----------------------------------------------------------------
[ -d "$RELEASE_DIR" ] || fail "release folder not found: $RELEASE_DIR"
RELEASE_DIR="$(cd "$RELEASE_DIR" && pwd)"
shopt -s nullglob
wheels=("$RELEASE_DIR"/strugglebus-*.whl)
shopt -u nullglob
[ "${#wheels[@]}" = "1" ] || fail "expected exactly one strugglebus-*.whl in $RELEASE_DIR (found ${#wheels[@]}). Pass --release-dir with the folder holding the downloaded release files."
WHEEL="${wheels[0]}"
for needed in requirements.lock SHA256SUMS; do
  [ -s "$RELEASE_DIR/$needed" ] || fail "$needed is missing from $RELEASE_DIR. Download every file of the release into one folder."
done
(cd "$RELEASE_DIR" && sha256sum --check --ignore-missing --quiet SHA256SUMS) \
  || fail "a release file does not match SHA256SUMS. Download the release again."
say "release files verified: $(basename "$WHEEL")"

# --- operating system packages -------------------------------------------------------
say "installing operating system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || fail "apt-get update failed. This machine needs internet access to the Debian mirrors."
apt-get install -y -qq python3 python3-venv caddy ca-certificates curl >/dev/null \
  || fail "could not install python3, python3-venv, caddy, ca-certificates and curl with apt."
python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)' \
  || fail "Strugglebus needs Python 3.13, which Debian 13 provides. This system has $(python3 --version 2>&1). Use a Debian 13 container or VM, or the Docker install."

# Checked here, before anything of a running bus is touched.
python3 - "$ALLOWED_CLIENTS" <<'PY' || fail "--allow-clients takes address ranges such as 203.0.113.0/24, separated by spaces, and never a whole-internet range such as 0.0.0.0/0 (got '$ALLOWED_CLIENTS')."
import ipaddress, sys
for text in sys.argv[1].split():
    if ipaddress.ip_network(text, strict=False).prefixlen == 0:
        raise SystemExit(1)
PY

# --- can systemd sandbox a service here? (Proxmox containers need nesting) ------
if ! systemd-run --quiet --wait --collect -p PrivateTmp=true -p ProtectSystem=strict \
    -p ProtectHome=true true 2>/dev/null; then
  fail "systemd cannot sandbox services in this container. On the Proxmox host run: pct set <container id> --features nesting=1  then restart the container and run this installer again."
fi

# --- account, folders, admin token ----------------------------------------------
getent group strugglebus >/dev/null || groupadd --system strugglebus
getent passwd strugglebus >/dev/null || useradd --system --gid strugglebus --home-dir "$DATA_DIR" --shell /usr/sbin/nologin strugglebus
install -d -m 0755 "$PREFIX" /etc/strugglebus
install -d -m 0700 -o strugglebus -g strugglebus /etc/strugglebus/credentials "$DATA_DIR" "$BACKUP_DIR"
if [ ! -s "$TOKEN_FILE" ]; then
  (umask 077 && python3 -c "import secrets; print(secrets.token_urlsafe(48), end='')" > "$TOKEN_FILE")
fi
chown strugglebus:strugglebus "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

# --- back up before an upgrade -----------------------------------------------------
if [ "$UPGRADE" = "yes" ] && [ -x "$PREFIX/venv/bin/strugglebus" ] && [ -s "$DATA_DIR/strugglebus.db" ]; then
  say "upgrade: backing up the database to $BACKUP_DIR"
  /usr/local/sbin/strugglebus-admin backup >/dev/null \
    || fail "the pre-upgrade backup failed, so nothing was changed. Run 'strugglebus-admin backup' to see why."
fi

# --- the application ----------------------------------------------------------------
say "installing the application (downloads its dependencies from pypi.org)"
systemctl stop strugglebus.service 2>/dev/null || true
rm -rf "$PREFIX/venv.previous"
[ ! -d "$PREFIX/venv" ] || mv "$PREFIX/venv" "$PREFIX/venv.previous"
put_back() {
  rm -rf "$PREFIX/venv"
  if [ -d "$PREFIX/venv.previous" ]; then
    mv "$PREFIX/venv.previous" "$PREFIX/venv"
    systemctl start strugglebus.service 2>/dev/null || true
    say "the previous version was put back and restarted"
  fi
}
python3 -m venv "$PREFIX/venv" || { put_back; fail "could not create the Python environment in $PREFIX/venv."; }
"$PREFIX/venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes --only-binary=:all: -r "$RELEASE_DIR/requirements.lock" \
  || { put_back; fail "could not download the dependencies. This machine needs internet access to pypi.org."; }
"$PREFIX/venv/bin/pip" install --quiet --disable-pip-version-check --no-deps "$WHEEL" \
  || { put_back; fail "could not install $(basename "$WHEEL")."; }
VERSION="$("$PREFIX/venv/bin/strugglebus" --version | awk '{print $NF}')"

# --- HTTPS gateway ------------------------------------------------------------------
say "configuring the HTTPS gateway for $BASE_URL"
if [ -f /etc/caddy/Caddyfile ] && ! grep -q "Strugglebus" /etc/caddy/Caddyfile; then
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.before-strugglebus"
fi
printf '%s\n' "$ALLOWED_CLIENTS" > "$ALLOWED_CLIENTS_FILE"
sed -e "s/__BUS_HOSTNAME__/$BUS_HOSTNAME/g" -e "s/__BUS_PORT__/$BUS_PORT/g" \
  -e "s|__BUS_ALLOWED_CLIENTS__|$ALLOWED_CLIENTS|g" \
  "$HERE/Caddyfile" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
  || fail "the HTTPS gateway configuration is not valid. Check --allow-clients, then see: caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile"
systemctl enable --quiet caddy.service
systemctl restart caddy.service || fail "the HTTPS gateway (caddy) did not start. See: journalctl -u caddy -n 30"
for _ in $(seq 1 60); do [ -s "$GATEWAY_ROOT" ] && break; sleep 1; done
[ -s "$GATEWAY_ROOT" ] || fail "the gateway did not create its certificate root within 60 seconds. See: journalctl -u caddy -n 30"
install -m 0644 "$GATEWAY_ROOT" "$CA_FILE"
CA_SHA256="$(python3 -c "import hashlib, ssl, sys; print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1]).read())).hexdigest())" "$CA_FILE")"

# --- settings and service -----------------------------------------------------------
cat > "$ENV_FILE" <<EOF
# Written by the Strugglebus installer. Re-run the installer to change the name or port.
STRUGGLEBUS_PUBLIC_BASE_URL=$BASE_URL
STRUGGLEBUS_ALLOWED_HOSTS=$BUS_HOSTNAME,$BUS_HOSTNAME:*,127.0.0.1:*,localhost:*
STRUGGLEBUS_ALLOWED_ORIGINS=$BASE_URL
STRUGGLEBUS_BIND_HOST=127.0.0.1
STRUGGLEBUS_BIND_PORT=8080
STRUGGLEBUS_DATA_DIR=$DATA_DIR
STRUGGLEBUS_DATABASE_PATH=$DATA_DIR/strugglebus.db
STRUGGLEBUS_BACKUP_DIR=$BACKUP_DIR
STRUGGLEBUS_RUNTIME_DIR=/run/strugglebus
STRUGGLEBUS_CA_BUNDLE_PATH=$CA_FILE
STRUGGLEBUS_CA_ROOT_SHA256=$CA_SHA256
EOF
chmod 644 "$ENV_FILE"
install -m 0644 "$HERE/strugglebus.service" /etc/systemd/system/strugglebus.service
install -m 0755 "$HERE/strugglebus-admin" /usr/local/sbin/strugglebus-admin
install -m 0755 "$HERE/strugglebus-info" /usr/local/sbin/strugglebus-info
install -d -m 0755 "$UPDATE_STATE" /usr/local/lib/strugglebus
install -m 0644 "$HERE/../fetch_release.py" /usr/local/lib/strugglebus/fetch_release.py
install -m 0755 "$HERE/strugglebus-update" /usr/local/sbin/strugglebus-update
# 'pct exec' and other non-login shells do not always search /usr/local/sbin.
for helper in strugglebus-admin strugglebus-info strugglebus-update; do
  ln -sfn "/usr/local/sbin/$helper" "/usr/sbin/$helper"
done
install -m 0644 "$HERE/strugglebus-update.service" /etc/systemd/system/strugglebus-update.service
install -m 0644 "$HERE/strugglebus-update.timer" /etc/systemd/system/strugglebus-update.timer
systemctl daemon-reload
systemctl enable --quiet strugglebus.service
systemctl reset-failed strugglebus.service 2>/dev/null || true
systemctl restart strugglebus.service

wait_ready() {
  for _ in $(seq 1 45); do
    if curl --silent --fail --max-time 3 --cacert "$CA_FILE" \
        --resolve "$BUS_HOSTNAME:$BUS_PORT:127.0.0.1" "$BASE_URL/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

say "waiting for the bus to answer"
if ! wait_ready; then
  journalctl -u strugglebus.service -n 15 --no-pager >&2 || true
  if [ "$UPGRADE" = "yes" ] && [ -d "$PREFIX/venv.previous" ]; then
    say "the new version did not start; putting the previous version back"
    systemctl stop strugglebus.service 2>/dev/null || true
    rm -rf "$PREFIX/venv"
    mv "$PREFIX/venv.previous" "$PREFIX/venv"
    systemctl reset-failed strugglebus.service 2>/dev/null || true
    systemctl start strugglebus.service 2>/dev/null || true
    if wait_ready; then
      fail "version $VERSION did not start, so the previous version was put back and is running. The lines above are the new version's log."
    fi
    fail "version $VERSION did not start, and the previous version did not start either. The database may have been changed by the upgrade; the copy taken before it is in $BACKUP_DIR. See: journalctl -u strugglebus -n 30"
  fi
  fail "the bus did not become ready. The lines above are its log."
fi

# --- automatic updates ---------------------------------------------------------------
# The daily timer is always installed. Whether it installs anything is the
# on/off setting, which the console can change without root. The setting file
# also tells the bus that this install has an updater. An upgrade keeps the
# setting unless --auto-update says otherwise.
if [ -n "$AUTO_UPDATE_ARG" ]; then
  /usr/local/sbin/strugglebus-update "$AUTO_UPDATE_ARG" >/dev/null
elif ! runuser -u strugglebus -- test -e "$UPDATE_SWITCH"; then
  /usr/local/sbin/strugglebus-update on >/dev/null
fi
systemctl enable --quiet --now strugglebus-update.timer

echo
say "Strugglebus $VERSION is running."
/usr/local/sbin/strugglebus-info
if [ "$(runuser -u strugglebus -- cat "$UPDATE_SWITCH" 2>/dev/null)" = "off" ]; then
  echo "Auto updates    : off. Turn on with 'strugglebus-update on' or in the console under Administration > Updates."
else
  echo "Auto updates    : on, checked once a day. Turn off with 'strugglebus-update off' or in the console under Administration > Updates."
fi
ADDRESS="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "Next steps:"
echo "  1. Make '$BUS_HOSTNAME' resolve to ${ADDRESS:-this machine} on your network (router DNS record, or a hosts-file entry on each PC)."
if [ "$UPGRADE" = "no" ]; then
  echo "  2. Open $BASE_URL/setup in a browser, enter the setup code above and choose an operator password (15 characters or more)."
  echo "     The browser will warn about the certificate until you trust $CA_FILE on that PC; check the fingerprint above first."
fi
