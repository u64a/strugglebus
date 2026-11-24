#!/bin/bash
# Joins this machine's agent to a Strugglebus in one step: checks the bus
# certificate, redeems the one-time enrollment, proves the new key, stores it
# in a private folder, and writes a launcher that starts GitHub Copilot CLI
# already connected to the bus.
#
# The onboarding package gives the exact command. The enrollment token is read
# from the STRUGGLEBUS_ENROLLMENT environment variable, never the command line.
set -euo pipefail
umask 077

fail() {
  echo "join: $*" >&2
  exit 1
}

endpoint=""
name=""
ca_sha256=""
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) endpoint="${2:-}"; shift 2 ;;
    --name) name="${2:-}"; shift 2 ;;
    --ca-sha256) ca_sha256="${2:-}"; shift 2 ;;
    -h|--help)
      echo "usage: STRUGGLEBUS_ENROLLMENT=<token> bash join.sh --endpoint https://<bus> --name <agent> --ca-sha256 <fingerprint>"
      exit 0 ;;
    *) fail "unknown option '$1'. Run the command from the onboarding package exactly as written." ;;
  esac
done

[ -n "$endpoint" ] || fail "--endpoint is required. Run the command from the onboarding package exactly as written."
[ -n "$name" ] || fail "--name is required. Run the command from the onboarding package exactly as written."
[ -n "$ca_sha256" ] || fail "--ca-sha256 is required. Run the command from the onboarding package exactly as written."
case "$endpoint" in
  https://*) ;;
  *) fail "the bus address must start with https:// (got '$endpoint')." ;;
esac
endpoint="${endpoint%/}"
case "$name" in
  *[!A-Za-z0-9._-]*|.*) fail "the agent name may only contain letters, digits, dots, dashes and underscores (got '$name')." ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is not installed. Install curl and run this again; nothing has been used up."
python=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null; then
    python="$candidate"
    break
  fi
done
[ -n "$python" ] || fail "python3 is not installed. Install python3 and run this again, or follow the by-hand steps in the onboarding package. Nothing has been used up."

home="${STRUGGLEBUS_HOME:-$HOME/.strugglebus}"
folder="$home/$name"
mkdir -p "$folder"
chmod 700 "$home" "$folder"
cd "$folder"

ca="$folder/ca-root.crt"
state="$folder/agent.json"
key="$folder/agent-key"
[ -s "$ca" ] || fail "$ca is missing. Run every line of the command from the onboarding package, starting at the top."

# The package states the fingerprint of the certificate root it carries. If the
# saved file differs, someone or something changed it on the way here.
actual="$("$python" - "$ca" <<'PY'
import hashlib, ssl, sys
digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1]).read())).hexdigest().upper()
print(":".join(digest[i:i + 2] for i in range(0, 64, 2)))
PY
)" || fail "$ca is not a certificate. Copy the command from the onboarding package again."
expected="$(printf '%s' "$ca_sha256" | tr 'a-f' 'A-F')"
[ "$actual" = "$expected" ] || fail "the certificate root does not match the onboarding package (expected $expected, found $actual). Stop and tell your operator. Nothing has been used up."

request() {
  # request <output-file> <secret-header-file> <json-body> <url>; prints the HTTP status
  curl --silent --show-error --cacert "$ca" --max-time 30 \
    --header "@$2" --header 'Content-Type: application/json' \
    --data-binary "$3" --output "$1" --write-out '%{http_code}' --url "$4"
}

detail() {
  "$python" - "$1" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8")).get("detail", "")
except Exception:
    value = ""
print(value if isinstance(value, str) else json.dumps(value))
PY
}

new_id() {
  "$python" -c 'import uuid; print(uuid.uuid4())'
}

cleanup() {
  rm -f "$folder/.join-header" "$folder/.join-response"
}
trap cleanup EXIT

if [ ! -s "$state" ]; then
  token="${STRUGGLEBUS_ENROLLMENT:-}"
  [ -n "$token" ] || fail "STRUGGLEBUS_ENROLLMENT is not set. Run every line of the command from the onboarding package."
  [ ! -e "$key" ] || fail "$key already exists but $state does not. Do not enroll this name again; tell your operator, who can recover it."
  printf 'Authorization: Bearer %s\n' "$token" > "$folder/.join-header"
  body="$("$python" - "$name" "$(new_id)" <<'PY'
import json, socket, sys
print(json.dumps({"request_id": sys.argv[2], "name": sys.argv[1], "host": socket.gethostname()[:255]}))
PY
)"
  status="$(request "$folder/.join-response" "$folder/.join-header" "$body" "$endpoint/api/enrollments/redeem")" \
    || fail "could not reach $endpoint. Check that the name resolves on this machine and the bus is running. The enrollment has not been used; run this again."
  if [ "$status" != "201" ]; then
    reason="$(detail "$folder/.join-response")"
    case "$status" in
      401) fail "the bus refused the enrollment (${reason:-not valid}). It may have expired or already been used. Ask your operator for a new onboarding package." ;;
      409) fail "an agent named '$name' already exists (${reason:-name taken}). Ask your operator; do not pick a different name yourself." ;;
      *) fail "the bus answered $status (${reason:-no detail}). Tell your operator." ;;
    esac
  fi
  # Split the response: the secret goes in agent-key and nowhere else.
  "$python" - "$folder/.join-response" "$key" "$state" "$endpoint" <<'PY'
import json, os, sys
response = json.load(open(sys.argv[1], encoding="utf-8"))
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
with os.fdopen(os.open(sys.argv[2], flags, 0o600), "w", encoding="ascii") as stream:
    stream.write(response["credential_secret"])
record = {
    "endpoint": sys.argv[4],
    "mcp": sys.argv[4] + "/mcp",
    "agent_id": response["agent"]["id"],
    "agent_name": response["agent"]["name"],
    "credential_epoch": response["agent"]["credential_epoch"],
    "credential_version": response["credential"]["version"],
    "proved": False,
}
with os.fdopen(os.open(sys.argv[3], flags, 0o600), "w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
PY
  cleanup
  echo "join: enrolled as $name"
fi
unset STRUGGLEBUS_ENROLLMENT

field() {
  "$python" - "$state" "$1" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])
PY
}

[ -s "$key" ] || fail "$key is missing, so this agent has no key. Tell your operator, who can recover it; do not enroll the name again."
if [ "$(field endpoint)" != "$endpoint" ]; then
  fail "this folder belongs to an agent on $(field endpoint), not $endpoint."
fi

if [ "$(field proved)" != "True" ]; then
  printf 'Authorization: Bearer %s\n' "$(cat "$key")" > "$folder/.join-header"
  body="$("$python" - "$state" "$(new_id)" <<'PY'
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
print(json.dumps({
    "request_id": sys.argv[2],
    "expected_agent_id": record["agent_id"],
    "expected_agent_name": record["agent_name"],
    "expected_credential_epoch": record["credential_epoch"],
    "expected_credential_version": record["credential_version"],
}))
PY
)"
  status="$(request "$folder/.join-response" "$folder/.join-header" "$body" "$endpoint/api/credentials/prove")" \
    || fail "enrolled, but could not reach $endpoint to prove the key. Run the same join command again within a few minutes; it will only retry this step."
  if [ "$status" != "200" ]; then
    reason="$(detail "$folder/.join-response")"
    fail "enrolled, but the bus answered $status when proving the key (${reason:-no detail}). If the key has expired, tell your operator, who can recover it; do not enroll the name again."
  fi
  "$python" - "$state" <<'PY'
import json, os, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
record["proved"] = True
temporary = sys.argv[1] + ".new"
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
os.replace(temporary, sys.argv[1])
PY
  cleanup
  echo "join: key proved"
fi

# The key stays out of this file: Copilot CLI fills it in from the environment
# variable the launcher sets.
cat > "$folder/copilot-mcp.json" <<JSON
{
  "mcpServers": {
    "bus": {
      "type": "http",
      "url": "$endpoint/mcp",
      "headers": { "Authorization": "Bearer \${STRUGGLEBUS_AGENT_KEY}" },
      "tools": ["*"]
    }
  }
}
JSON

cat > "$folder/bus-copilot" <<'LAUNCHER'
#!/bin/bash
# Starts GitHub Copilot CLI connected to the bus as this agent. Run it from the
# folder the agent should work in. Extra arguments are passed to copilot.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
command -v copilot >/dev/null 2>&1 || { echo "bus-copilot: GitHub Copilot CLI ('copilot') is not installed or not on PATH." >&2; exit 1; }
[ -s "$here/agent-key" ] || { echo "bus-copilot: $here/agent-key is missing; this agent has not joined the bus." >&2; exit 1; }
roots="$here/ca-root.crt"
# Copilot CLI only trusts the bus certificate through NODE_EXTRA_CA_CERTS. Keep
# any roots already configured there, such as a company proxy.
if [ -n "${NODE_EXTRA_CA_CERTS:-}" ] && [ "$NODE_EXTRA_CA_CERTS" != "$roots" ] && [ -r "$NODE_EXTRA_CA_CERTS" ]; then
  (umask 077; cat "$NODE_EXTRA_CA_CERTS" "$here/ca-root.crt" > "$here/.node-roots.pem")
  roots="$here/.node-roots.pem"
fi
export NODE_EXTRA_CA_CERTS="$roots"
STRUGGLEBUS_AGENT_KEY="$(cat "$here/agent-key")"
export STRUGGLEBUS_AGENT_KEY
exec copilot --additional-mcp-config "@$here/copilot-mcp.json" "$@"
LAUNCHER
chmod 700 "$folder/bus-copilot"
rm -f "$folder/join.sh"

cat <<DONE

Joined the bus.
  Agent name : $(field agent_name)
  Agent id   : $(field agent_id)
  Bus        : $endpoint
  Folder     : $folder   (private to this account; holds this agent's key)

To start GitHub Copilot CLI connected to the bus, go to the folder the agent
should work in and run:
  $folder/bus-copilot

First thing in that session, ask the agent to call the bus "orientation" tool
and do what it says.

Delete the onboarding package now. Never post it, or anything in
$folder, to the bus, a chat or source control.
DONE
