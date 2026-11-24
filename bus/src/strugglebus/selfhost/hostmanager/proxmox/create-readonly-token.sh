#!/bin/bash
# Gives one bus agent read-only access to this Proxmox VE host.
#
#   bash create-readonly-token.sh [--user busagent@pve] [--token-name bus]
#   bash create-readonly-token.sh --remove [--user busagent@pve] [--token-name bus]
#
# Run it on the Proxmox host as root. It creates a user with no password, gives
# it the built-in read-only role PVEAuditor, and creates one API token that is
# limited to the same read-only role. --remove takes all of it away again.
set -euo pipefail

USER_ID="busagent@pve"
TOKEN_NAME="bus"
REMOVE=no
# Written into the user's comment. --remove only deletes a user that carries it,
# so this script can never delete an account it did not create.
MARKER="StruggleBus host-manager agent (made by create-readonly-token.sh)"

say() { echo "hostmanager: $*"; }
fail() { echo "hostmanager: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_ID="${2:-}"; shift 2 || fail "--user needs a value, for example --user busagent@pve" ;;
    --token-name) TOKEN_NAME="${2:-}"; shift 2 || fail "--token-name needs a value, for example --token-name bus" ;;
    --remove) REMOVE=yes; shift ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown option '$1'. Usage: create-readonly-token.sh [--remove] [--user busagent@pve] [--token-name bus]" ;;
  esac
done

[ "$(id -u)" = "0" ] || fail "run this as root on the Proxmox host."
command -v pveum >/dev/null || fail "the 'pveum' command was not found. Run this on the Proxmox VE host itself, not inside a guest and not on your PC."
command -v perl >/dev/null || fail "the 'perl' command was not found. It is part of every Proxmox VE install, so this does not look like a Proxmox VE host."

# The pve realm is Proxmox's own user list. A user there is not a Linux account
# and cannot log in over SSH.
case "$USER_ID" in
  *[!A-Za-z0-9._@-]*|@*|*@*@*) fail "--user must look like busagent@pve (got '$USER_ID')." ;;
  ?*@pve) ;;
  *) fail "--user must end with @pve (got '$USER_ID'). This script only makes users in the 'pve' realm and never touches root@pam." ;;
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

# Prints "path role" for every permission entry that belongs to NAME.
entries_of() {
  perl -MJSON::PP -e '
    local $/;
    my $list = eval { decode_json(<STDIN> // "") };
    exit 2 if ref($list) ne "ARRAY";
    for my $entry (@$list) {
      print "$entry->{path} $entry->{roleid}\n" if ($entry->{ugid} // "") eq $ARGV[0];
    }' "$2" <<<"$1"
}

USERS="$(pveum user list --output-format json)" || fail "could not list users with pveum."
USER_EXISTS=no
USER_IS_OURS=no
if found "$USERS" userid "$USER_ID"; then
  USER_EXISTS=yes
  if found "$USERS" userid "$USER_ID" comment "$MARKER"; then USER_IS_OURS=yes; fi
fi
TOKEN_EXISTS=no
if [ "$USER_EXISTS" = "yes" ]; then
  TOKENS="$(pveum user token list "$USER_ID" --output-format json)" || fail "could not list the tokens of $USER_ID."
  if found "$TOKENS" tokenid "$TOKEN_NAME"; then TOKEN_EXISTS=yes; fi
fi

# --- remove ---------------------------------------------------------------------
if [ "$REMOVE" = "yes" ]; then
  if [ "$USER_EXISTS" = "no" ]; then
    say "user $USER_ID does not exist. Nothing to remove."
    exit 0
  fi
  ACLS="$(pveum acl list --output-format json)" || fail "could not list permissions with pveum."
  # Take away every permission the token has, on every path. A permission left
  # behind would come back to life if a token with the same name were made later.
  # This also removes the pool permission from create-lifecycle-role.sh.
  TOKEN_ENTRIES="$(entries_of "$ACLS" "$TOKEN_ID")" || fail "could not read the permission list."
  while read -r path role; do
    [ -n "$path" ] || continue
    pveum acl delete "$path" --tokens "$TOKEN_ID" --roles "$role" \
      || fail "could not remove role $role on $path from token $TOKEN_ID. Nothing else was removed."
    say "removed role $role on $path from token $TOKEN_ID"
  done <<<"$TOKEN_ENTRIES"
  if [ "$TOKEN_EXISTS" = "yes" ]; then
    pveum user token delete "$USER_ID" "$TOKEN_NAME" >/dev/null \
      || fail "could not delete token $TOKEN_ID."
    say "deleted token $TOKEN_ID. Its secret no longer works."
  else
    say "token $TOKEN_ID does not exist."
  fi
  if [ "$USER_IS_OURS" != "yes" ]; then
    say "user $USER_ID was not created by this script, so it was left alone."
    exit 0
  fi
  USER_ENTRIES="$(entries_of "$ACLS" "$USER_ID")" || fail "could not read the permission list."
  while read -r path role; do
    [ -n "$path" ] || continue
    pveum acl delete "$path" --users "$USER_ID" --roles "$role" \
      || fail "could not remove role $role on $path from user $USER_ID. The user was not deleted."
    say "removed role $role on $path from user $USER_ID"
  done <<<"$USER_ENTRIES"
  pveum user delete "$USER_ID" || fail "could not delete user $USER_ID."
  say "deleted user $USER_ID. The agent no longer has any access to this host."
  exit 0
fi

# --- create ---------------------------------------------------------------------
if [ "$USER_EXISTS" = "yes" ] && [ "$USER_IS_OURS" != "yes" ]; then
  fail "user $USER_ID already exists and was not created by this script. Nothing was changed. Pick another name with --user, for example --user busagent2@pve."
fi
if [ "$USER_EXISTS" = "no" ]; then
  # No password is set, so nobody can log in as this user. Only its token works.
  pveum user add "$USER_ID" --comment "$MARKER" || fail "could not create user $USER_ID."
  say "created user $USER_ID (no password, cannot log in)"
else
  say "user $USER_ID already exists, keeping it"
fi

# PVEAuditor is Proxmox's built-in read-only role. It can look at guests, nodes,
# storage, pools and network settings. It cannot start, stop, change or delete
# anything. A token can never do more than its user, so the user needs the role
# as well as the token.
pveum acl modify / --users "$USER_ID" --roles PVEAuditor \
  || fail "could not give $USER_ID the read-only role."

if [ "$TOKEN_EXISTS" = "yes" ]; then
  pveum acl modify / --tokens "$TOKEN_ID" --roles PVEAuditor \
    || fail "could not give token $TOKEN_ID the read-only role."
  say "token $TOKEN_ID already exists. It was left as it is and still has read-only access."
  say "Proxmox cannot show its secret again. If the secret is lost, make a new one:"
  say "  bash $0 --remove --user $USER_ID --token-name $TOKEN_NAME"
  say "  bash $0 --user $USER_ID --token-name $TOKEN_NAME"
  exit 0
fi

# --privsep 1 gives the token its own, separate permissions. Without it the
# token would simply copy whatever its user is ever given.
echo
pveum user token add "$USER_ID" "$TOKEN_NAME" --privsep 1 --comment "StruggleBus host-manager agent, read-only" \
  || fail "could not create token $TOKEN_ID."
if ! pveum acl modify / --tokens "$TOKEN_ID" --roles PVEAuditor; then
  fail "the token was created but could not be given the read-only role, so it can do nothing yet. Keep the secret shown above and run this script again to finish."
fi

HOST_NAME="$(hostname -f 2>/dev/null || hostname)"
cat <<EOF

The token is ready. Its secret is in the "value" row of the table above.
COPY THE SECRET NOW. Proxmox cannot show it again.

  Token ID:     $TOKEN_ID
  API address:  https://$HOST_NAME:8006/api2/json
  Sent as:      Authorization: PVEAPIToken=$TOKEN_ID=<the secret>
  Certificate:  copy /etc/pve/pve-root-ca.pem to the agent's PC so it can check
                that it is really talking to this host.

Keep the secret private. Do not paste it into a chat, a bus message or a file
under source control. Then clear this screen with: clear

This token can only look. It cannot start, stop, change or delete anything.
To take the access away again: bash $0 --remove --user $USER_ID --token-name $TOKEN_NAME
EOF
