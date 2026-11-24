#!/bin/bash
# Starts the HTTPS gateway and the bus, and stops the container if either dies
# so Docker's restart policy brings both back together.
set -euo pipefail
umask 077

fail() {
  echo "strugglebus: $*" >&2
  exit 64
}

BUS_HOSTNAME="${BUS_HOSTNAME:-}"
BUS_PORT="${BUS_PORT:-443}"
[ -n "$BUS_HOSTNAME" ] || fail "BUS_HOSTNAME is not set. Put the name people will type, for example BUS_HOSTNAME=bus.home.arpa, in the .env file next to compose.yaml."
case "$BUS_HOSTNAME" in
  *[!a-z0-9.-]*) fail "BUS_HOSTNAME must be a lower-case DNS name such as bus.home.arpa (got '$BUS_HOSTNAME'). Do not include https:// or a port." ;;
esac
case "$BUS_PORT" in
  ''|*[!0-9]*) fail "BUS_PORT must be a number (got '$BUS_PORT')." ;;
esac
[ -w /data ] || fail "/data is not writable by the bus account (uid $(id -u)). Use the named volume from compose.yaml, not a folder shared from Windows or macOS."

# Extra client ranges for the gateway's private-network guard; usually empty.
BUS_ALLOWED_CLIENTS="${BUS_ALLOWED_CLIENTS:-}"
/opt/strugglebus/bin/python - "$BUS_ALLOWED_CLIENTS" <<'PY' || fail "BUS_ALLOWED_CLIENTS must be address ranges such as 203.0.113.0/24, separated by spaces, and never a whole-internet range (got '$BUS_ALLOWED_CLIENTS')."
import ipaddress, sys
for text in sys.argv[1].split():
    if ipaddress.ip_network(text, strict=False).prefixlen == 0:
        raise SystemExit(1)
PY
export BUS_HOSTNAME BUS_ALLOWED_CLIENTS
export STRUGGLEBUS_DATA_DIR=/data/bus
export STRUGGLEBUS_DATABASE_PATH=/data/bus/strugglebus.db
export STRUGGLEBUS_BACKUP_DIR=/data/backups
export STRUGGLEBUS_RUNTIME_DIR=/tmp/strugglebus-run
export CREDENTIALS_DIRECTORY=/data/credentials
export STRUGGLEBUS_ADMIN_CREDENTIAL_PATH="$CREDENTIALS_DIRECTORY/admin-token"
export XDG_DATA_HOME=/data/gateway
export XDG_CONFIG_HOME=/data/gateway/config
mkdir -p "$STRUGGLEBUS_DATA_DIR" "$STRUGGLEBUS_BACKUP_DIR" "$STRUGGLEBUS_RUNTIME_DIR" \
  "$CREDENTIALS_DIRECTORY" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"
chmod 700 "$STRUGGLEBUS_DATA_DIR" "$CREDENTIALS_DIRECTORY"
# The automatic-update switch, read by update.sh on the Docker host. Its
# presence is what makes the console show the on/off button.
if [ ! -e "$STRUGGLEBUS_DATA_DIR/selfhost/auto-update" ]; then
  mkdir -p "$STRUGGLEBUS_DATA_DIR/selfhost"
  echo on > "$STRUGGLEBUS_DATA_DIR/selfhost/auto-update"
fi
if [ ! -s "$STRUGGLEBUS_ADMIN_CREDENTIAL_PATH" ]; then
  /opt/strugglebus/bin/python -c "import secrets; print(secrets.token_urlsafe(48), end='')" \
    > "$STRUGGLEBUS_ADMIN_CREDENTIAL_PATH"
fi

port_suffix=""
[ "$BUS_PORT" = "443" ] || port_suffix=":$BUS_PORT"
export STRUGGLEBUS_PUBLIC_BASE_URL="https://${BUS_HOSTNAME}${port_suffix}"
export STRUGGLEBUS_ALLOWED_HOSTS="${BUS_HOSTNAME},${BUS_HOSTNAME}:*,127.0.0.1:*,localhost:*"
export STRUGGLEBUS_ALLOWED_ORIGINS="https://${BUS_HOSTNAME}${port_suffix}"

caddy run --config /etc/strugglebus/Caddyfile --adapter caddyfile &
gateway_pid=$!

# The gateway makes its own certificate authority on first start. The bus
# publishes that root so agents and devices can pin it during onboarding.
gateway_root="$XDG_DATA_HOME/caddy/pki/authorities/local/root.crt"
for _ in $(seq 1 60); do
  [ -s "$gateway_root" ] && break
  kill -0 "$gateway_pid" 2>/dev/null || fail "the HTTPS gateway stopped during startup; see the lines above."
  sleep 1
done
[ -s "$gateway_root" ] || fail "the HTTPS gateway did not create its certificate root within 60 seconds."
cp "$gateway_root" /data/ca-root.crt
export STRUGGLEBUS_CA_BUNDLE_PATH=/data/ca-root.crt
STRUGGLEBUS_CA_ROOT_SHA256="$(/opt/strugglebus/bin/python -c "import hashlib, ssl, sys; print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1]).read())).hexdigest())" /data/ca-root.crt)"
export STRUGGLEBUS_CA_ROOT_SHA256

/opt/strugglebus/bin/strugglebus serve &
bus_pid=$!

stop() {
  kill -TERM "$bus_pid" "$gateway_pid" 2>/dev/null || true
}
trap stop TERM INT

echo "strugglebus: starting at ${STRUGGLEBUS_PUBLIC_BASE_URL} - run 'docker compose exec bus strugglebus-info' for the setup code and certificate fingerprint"
set +e
wait -n "$bus_pid" "$gateway_pid"
status=$?
stop
wait
exit "$status"
