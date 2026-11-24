#!/bin/bash
# Optional second level: lets the bus agent start, shut down, stop and reboot
# the guests in ONE resource pool. Everything else stays read-only.
#
#   bash create-lifecycle-role.sh --pool POOL [--user busagent@pve] [--token-name bus]
#   bash create-lifecycle-role.sh --remove --pool POOL [--user busagent@pve] [--token-name bus]
#
# Run it on the Proxmox host as root, after create-readonly-token.sh.
#
# Why one pool and not the whole host: a permission on "/" or "/vms" would cover
# every guest, including ones you add later, your router or firewall guest and
# the bus itself. A pool is a list that you write. The agent can power-cycle
# only the guests you put in that pool, and taking a guest out of the pool takes
# the permission away at once. Leave out of the pool anything that must not go
# down, above all the guest that runs the bus.
#
# The role holds two privileges and nothing else:
#   VM.Audit      see a guest and its settings
#   VM.PowerMgmt  start, shut down, stop, reboot, reset, suspend and resume
# It cannot create or delete guests, change their settings, roll back
# snapshots, move guests to another node, touch backups or open a console.
# Remember that "stop" is the same as pulling the power cable.
set -euo pipefail

USER_ID="busagent@pve"
TOKEN_NAME="bus"
POOL=""
REMOVE=no
ROLE="BusAgentPower"
PRIVS="VM.Audit VM.PowerMgmt"

say() { echo "hostmanager: $*"; }
fail() { echo "hostmanager: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --pool) POOL="${2:-}"; shift 2 || fail "--pool needs a value, for example --pool agent-managed" ;;
    --user) USER_ID="${2:-}"; shift 2 || fail "--user needs a value, for example --user busagent@pve" ;;
    --token-name) TOKEN_NAME="${2:-}"; shift 2 || fail "--token-name needs a value, for example --token-name bus" ;;
    --remove) REMOVE=yes; shift ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown option '$1'. Usage: create-lifecycle-role.sh [--remove] --pool POOL [--user busagent@pve] [--token-name bus]" ;;
  esac
done

[ "$(id -u)" = "0" ] || fail "run this as root on the Proxmox host."
command -v pveum >/dev/null || fail "the 'pveum' command was not found. Run this on the Proxmox VE host itself, not inside a guest and not on your PC."
command -v perl >/dev/null || fail "the 'perl' command was not found. It is part of every Proxmox VE install, so this does not look like a Proxmox VE host."

[ -n "$POOL" ] || fail "--pool is required: the name of the resource pool whose guests the agent may start and stop, for example --pool agent-managed"
case "$POOL" in
  *[!A-Za-z0-9._-]*) fail "--pool must be a plain pool name made of letters, digits, '.', '_' and '-' (got '$POOL')." ;;
esac
case "$USER_ID" in
  *[!A-Za-z0-9._@-]*|@*|*@*@*) fail "--user must look like busagent@pve (got '$USER_ID')." ;;
  ?*@pve) ;;
  *) fail "--user must end with @pve (got '$USER_ID')." ;;
esac
case "$TOKEN_NAME" in
  ''|[!A-Za-z]*|*[!A-Za-z0-9._-]*) fail "--token-name must start with a letter and use only letters, digits, '.', '_' and '-' (got '$TOKEN_NAME')." ;;
esac
TOKEN_ID="$USER_ID!$TOKEN_NAME"

# found JSON FIELD VALUE [FIELD VALUE ...]
# Succeeds when the JSON list has an entry where every FIELD equals its VALUE.
found() {
  local json="$1" rc=0
  shift
  perl -MJSON::PP -e '
    my %want = @ARGV;
    local $/;
    my $list = eval { decode_json(<STDIN> // "") };
    exit 2 if ref($list) ne "ARRAY";
    for my $entry (@$list) {
      next if ref($entry) ne "HASH";
      my $ok = 1;
      for my $field (keys %want) {
        $ok = 0 if !defined($entry->{$field}) || "$entry->{$field}" ne $want{$field};
      }
      exit 0 if $ok;
    }
    exit 1;' "$@" <<<"$json" || rc=$?
  [ "$rc" -le 1 ] || fail "could not understand the answer from pveum. Nothing more was changed."
  return "$rc"
}

ROLES="$(pveum role list --output-format json)" || fail "could not list roles with pveum."

# --- remove ---------------------------------------------------------------------
if [ "$REMOVE" = "yes" ]; then
  ACLS="$(pveum acl list --output-format json)" || fail "could not list permissions with pveum."
  if found "$ACLS" path "/pool/$POOL" ugid "$TOKEN_ID" roleid "$ROLE"; then
    pveum acl delete "/pool/$POOL" --tokens "$TOKEN_ID" --roles "$ROLE" \
      || fail "could not remove the permission of token $TOKEN_ID on pool '$POOL'."
    say "token $TOKEN_ID can no longer start or stop guests in pool '$POOL'"
  else
    say "token $TOKEN_ID had no start/stop permission on pool '$POOL'"
  fi
  if found "$ACLS" path "/pool/$POOL" ugid "$USER_ID" roleid "$ROLE"; then
    pveum acl delete "/pool/$POOL" --users "$USER_ID" --roles "$ROLE" \
      || fail "could not remove the permission of user $USER_ID on pool '$POOL'."
  fi
  if found "$ROLES" roleid "$ROLE"; then
    ACLS="$(pveum acl list --output-format json)" || fail "could not list permissions with pveum."
    if found "$ACLS" roleid "$ROLE"; then
      say "role $ROLE is still used on another pool, so the role itself was kept"
    else
      pveum role delete "$ROLE" || fail "could not delete role $ROLE."
      say "deleted role $ROLE"
    fi
  fi
  say "the agent is back to read-only for pool '$POOL'."
  exit 0
fi

# --- create ---------------------------------------------------------------------
USERS="$(pveum user list --output-format json)" || fail "could not list users with pveum."
found "$USERS" userid "$USER_ID" \
  || fail "user $USER_ID does not exist. Run create-readonly-token.sh first."
TOKENS="$(pveum user token list "$USER_ID" --output-format json)" || fail "could not list the tokens of $USER_ID."
found "$TOKENS" tokenid "$TOKEN_NAME" \
  || fail "token $TOKEN_ID does not exist. Run create-readonly-token.sh first."
found "$TOKENS" tokenid "$TOKEN_NAME" privsep 1 \
  || fail "token $TOKEN_ID was not made with separate permissions (privsep), so it cannot be limited to one pool. Remove it and make it again with create-readonly-token.sh."
POOLS="$(pveum pool list --output-format json)" || fail "could not list pools with pveum."
found "$POOLS" poolid "$POOL" \
  || fail "pool '$POOL' does not exist. Create it first (web interface: Datacenter, Permissions, Pools, Create; or: pveum pool add $POOL), put in it only the guests the agent may start and stop, then run this again."

# Set the role to exactly the two privileges every time, so running this again
# can never leave it with more than that.
if found "$ROLES" roleid "$ROLE"; then
  pveum role modify "$ROLE" --privs "$PRIVS" || fail "could not reset role $ROLE."
else
  pveum role add "$ROLE" --privs "$PRIVS" || fail "could not create role $ROLE."
  say "created role $ROLE with: $PRIVS"
fi

# Granted on the pool only. Both lines are needed: Proxmox lets a token do only
# what its user may also do. The user has no password, so the token is the only
# way to use this permission.
pveum acl modify "/pool/$POOL" --users "$USER_ID" --roles "$ROLE" \
  || fail "could not give $USER_ID the role on pool '$POOL'."
pveum acl modify "/pool/$POOL" --tokens "$TOKEN_ID" --roles "$ROLE" \
  || fail "could not give token $TOKEN_ID the role on pool '$POOL'."

cat <<EOF

Done. Token $TOKEN_ID can now start, shut down, stop and reboot the guests in
pool '$POOL', and only those. Everywhere else it is still read-only.

  See what the token may do:  pveum user token permissions $USER_ID $TOKEN_NAME
  Take this level away again: bash $0 --remove --pool $POOL --user $USER_ID --token-name $TOKEN_NAME

Guests you add to pool '$POOL' later are covered too. Keep the bus guest and
anything else that must stay up out of this pool.
EOF
