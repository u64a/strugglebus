# Operator release promotion

`scripts/promote_release.py` is an operator-side wrapper around the existing
build-once qualification workflow and annotated-tag publisher. It does not build
release bytes, publish or repair drafts itself, rerun workflows, merge changes,
or deploy production. Development, tests, and a merged PR do not authorize live
promotion.

## Prerequisites

Use trusted reviewed release-control source and Python 3.12 or 3.13 on Linux or
WSL. Native Windows execution is refused; this does not change the application's
supported Python versions or platforms. The command reads candidate source by
exact GitHub commit without executing it and never changes checkout branches,
local tags, or the working tree.

The selected `gh` must already authenticate to github.com as `NZCypher819`.
The repository is fixed to `NZCypher819/strugglebus`, default branch `main`.
Use `--gh /absolute/path/to/gh` to select an existing trusted executable. In WSL,
an explicit mounted path to the Windows `gh.exe` can reuse its existing owner
authentication. Do not copy tokens to files or put them on the command line.
The command obtains that credential once in bounded memory, verifies `/user`,
and never silently switches account or executable. Only select an executable
you trust: it is part of the operator's authentication boundary.

The existing credential needs private repository/Actions reads, Actions write
for dispatch, Contents write for annotated tag/ref creation, and Administration
read for immutable-release settings. GET-only preflight cannot prove every
write capability. Missing rights fail closed; the tool does not provision a
credential, change repository settings, or increase workflow permissions.
Both existing workflow tokens remain read-only, and the release App's existing
single-repository permissions and owner-only event gate remain unchanged.

Main must already contain the intended package version and pass every required
exact-main CI job. Immutable releases and the release App must already be
configured. Previously consumed tags are not reclaimable. The command explicitly
blocks the historical failed tags `v0.2.0` through `v0.2.3`, disqualified versions
`0.2.5`, `0.2.6`, `0.2.28`, `0.2.31`, `0.2.32`, `0.2.33`, `0.2.34`, and
`0.2.35`, `0.2.36`, `0.2.37`, and any
conflicting existing tag or release. Version `0.2.28` failed before activation because its application
module omitted the freeze-capability export. Version `0.2.31` failed before
activation because its updater did not resolve the protected `current` release
symlink before validating immutable runtime ancestry. Version `0.2.32` failed
before activation because maintenance used the updater package version instead of
the active application version and therefore could not discover the update.
Version `0.2.33` discovered the public release correctly but could not prepare it
because pre-public-source applications bound candidate confirmation to the old
private-repository identity. Version `0.2.34` proved that compatibility bridge,
but its maintenance supervisor consumed the immediate asynchronous check
acceptance instead of waiting for the exact check and prepare operations to
finish, so the real manual installation path failed closed before mutation.
Version `0.2.35` corrected terminal polling, but its dev rehearsal redundantly
rediscovered a portal-prepared candidate and the required board announcement
failed closed after the generic five-second SQLite contention window. Its
successor reuses only an exact application-bound prepared candidate and gives the
announcement a bounded 30-second SQLite busy timeout. Version `0.2.36` is also
permanently disqualified because the transition notice still executes through the
active older application, which retains its five-second timeout. Its successor
retries the idempotent notice within one bounded 30-second supervisor deadline.
Version `0.2.37` is permanently disqualified because repeated short waits still
failed in the live transition. Its successor runs a fixed trusted shim through
the active application's code to apply one continuous bounded 30-second SQLite
wait without interpolating candidate input.

## Release and deployment rules

These moved here from `AGENTS.md`. They bind any change to releases,
deployment or backups.

- Deploy checksummed wheels into versioned virtual environments through
  Ansible. Do not clone the repository or build from a mutable source tree in
  production. Keep Ansible provisioning idempotent.
- Run as an unprivileged service account with a non-writable source tree and a
  dedicated writable data directory.
- Never activate a freeze-incapable release while persisted state is frozen, or
  restore a pre-freeze database through ordinary rollback.
- Back up before migrating. Keep seven integrity-checked daily SQLite backups
  and four weekly `vzdump` backups; changes to backup automation require a
  restore test.
- Deployed updaters from 0.2.46 onward verify both the legacy 3.12+3.13 and the
  3.13-only release contract. Never ship release metadata the deployed updaters
  cannot verify.
- Releases are cut only from exact `main` commits that passed the full gate.
- Self-hosted buses with automatic updates on install a public release within
  a day, with nobody checking it first. Before publishing one, run
  `uv run python tests/selfhost_smoke.py` on a machine with Docker. It
  installs, updates and rolls back a bus for real on Debian and on Docker
  (about ten minutes) and is not part of CI.

## One entry point

Replace `TAG` and `FULL_MAIN_SHA` with the exact intended version tag and its
40-character current main commit. Commands below are Linux/WSL shell examples.

```sh
python scripts/promote_release.py plan --tag TAG --commit FULL_MAIN_SHA
```

`plan` performs authenticated reads only. It writes no receipt, lock, or
download, and cannot dispatch or tag. A ready qualification in this output still
needs artifact byte verification before tagging.

Create a private state directory on native local Linux storage, outside the
repository. In WSL use the Linux home filesystem, not a Windows/DrvFS mount.
The directory must be owned by the current user with mode `0700`; receipts and
stable lock files use `0600`. Unsafe ancestors, links, hardlinks, mounts, and
file permissions are refused rather than repaired automatically.

```sh
mkdir -m 700 "$HOME/strugglebus-promotion"
python scripts/promote_release.py promote \
  --tag TAG --commit FULL_MAIN_SHA \
  --receipt "$HOME/strugglebus-promotion/TAG.json" \
  --approval publish-exact-qualified-bytes
```

This explicit approval authorizes the supported sequence for this exact identity:
reuse or dispatch one qualification, verify its exact artifact, create one
annotated tag, and observe and verify the existing publisher. It does not grant
permission to deploy. The server-side workflow gates still independently enforce
owner, exact current main, version, CI, and qualified bytes.

For an interrupted invocation, keep the same receipt:

```sh
python scripts/promote_release.py status \
  --receipt "$HOME/strugglebus-promotion/TAG.json"
python scripts/promote_release.py promote --resume \
  --tag TAG --commit FULL_MAIN_SHA \
  --receipt "$HOME/strugglebus-promotion/TAG.json" \
  --approval publish-exact-qualified-bytes
```

`status` is read-only and does not update the receipt or acquire a writer lock.
It distinguishes recorded intent from observed state. Metadata-only historical
status is not a new download or qualification verification.

## Interruption and conflicts

Each mutation intent is atomically persisted before its request. A separate,
stable lock inode serializes invocations using the same receipt even while the
receipt is replaced. Preserve that operation directory: its unsigned non-secret
receipt is a recovery record, not an independent signature or authorization.
The same trusted owner can edit or restore files; not every valid-looking
rollback of state can be detected. Do not edit, reset, delete, or copy an old
receipt to make the command retry.

Workflow dispatch does not return a run ID. A lost response or no visible run
does not prove that nothing happened. Run IDs and timestamps alone do not prove
dispatch inputs. The command waits for the existing unique resolver and the
exact artifact's receipt to establish the binding. Unattributed same-commit
runs, multiple matches, failed qualification, expired artifacts, and truncated
listings block advancement; it never silently dispatches a replacement.

Annotated tag-object creation and ref creation are separate durable steps.
The canonical annotation binds this operation and its qualification. An unknown
object response reconciles the expected content-addressed object; unexpected
GitHub serialization stops without creating a ref. An unknown ref response
reconciles the exact ref and annotation. Same target commit alone is not enough
to adopt an existing tag. No force, delete, move, or recreate operation exists.

An active publisher with a partial draft remains pending. A failed workflow may
already have published a valid immutable release, so actual release state is
examined before failure is declared. A completed unsuccessful publication is
not repaired or rerun by this tool; its tag stays consumed. A new candidate
requires the normal reviewed version-bump process and separate approval.
Expired qualification blocks fresh advancement. Already completed receipts may
still report historical immutable metadata without backdating verification.

The local lock cannot serialize other machines or owner actions outside this
command. It guarantees no automatic repeat per intact durable operation, not
global exactly-once execution. Do not concurrently dispatch, tag, change drafts,
or advance main during promotion. Main is revalidated before mutation gates;
the existing server gates remain authoritative for races.

## Bounds and output

The default invocation deadline is 45 minutes, configurable with
`--timeout-seconds` from 60 to 3600. `--poll-seconds` accepts 2 through 60
(default 10) for promotion. Blocking I/O, subprocesses, and polling are bounded;
the command is not a daemon. API responses, receipts, both subprocess streams,
archive size, central-directory parsing, extracted bytes, and disk downloads
have fixed limits. One invocation has a shared 10,000-request ceiling, including
HTTP retries, internal pagination, and CLI subprocess requests. At most the
existing 1 GiB Actions archive and bounded copies
of its assets are staged; temporary downloads are cleaned afterward.

Actions ZIP acquisition uses the selected authenticated `gh api` transport, not
a new wildcard storage-host redirect allowlist. The existing publisher's stricter
release-asset transport remains in use for published-byte verification. ZIP
size/SHA-256 are checked before extraction, which accepts only the five expected
release files and the qualification receipt; links, extra members, traversal,
duplicates, ZIP64 directory overrides, and expansion beyond limits are refused.

Output is bounded JSON with safe errors and no raw token or gh diagnostic
output. Exit codes are `0` success, `2` usage, `3` configuration/platform,
`4` authentication, `5` network/deadline, `6` unsafe/conflicting state, and
`130` interruption. Deadline/interruption never means a mutation was not accepted.

## Public assets-only mirror

After private promotion completes, mirror the same verified five-file bundle to
`NZCypher819/strugglebus-releases`. This is a separate mutation and never deploys
anything. Run it on Linux or WSL with the trusted reviewed checkout and an
existing owner-authenticated `gh`; token environment variables are deliberately
removed, and the selected CLI's credential store is used without exporting a
token. A native Linux `gh` may read a native Linux bundle. When selecting a
mounted Windows `gh.exe` from WSL, place `BUNDLE_DIR` on `/mnt/<drive>` so input
paths can be converted to the Windows form; keep the receipt on native Linux
storage.

Record the public repository's exact current default-branch commit before the
first attempt. Create the receipt directory on native Linux storage with mode
`0700`; preserve the receipt and its stable lock for recovery. `BUNDLE_DIR` must
contain exactly the five checksum-verified assets from the immutable private
release.

```sh
TAG=vX.Y.Z
SOURCE_COMMIT=<40-character private source commit>
SOURCE_TREE=<40-character private source tree>
PUBLIC_ANCHOR="$(gh api repos/NZCypher819/strugglebus-releases/branches/main --jq .commit.sha)"
APPROVAL="publish-public-release-${TAG}-${SOURCE_COMMIT}"
mkdir -m 700 "$HOME/strugglebus-public-promotion"
python scripts/publish_public_release.py "$BUNDLE_DIR" \
  --tag "$TAG" \
  --source-commit "$SOURCE_COMMIT" \
  --source-tree "$SOURCE_TREE" \
  --public-anchor-commit "$PUBLIC_ANCHOR" \
  --approval "$APPROVAL" \
  --receipt "$HOME/strugglebus-public-promotion/${TAG}.json" \
  --gh "$(command -v gh)"
```

The publisher revalidates the private annotated tag, immutable private release,
source commit/tree, all five names/sizes/digests/media types, public repository
identity, immutable-release setting and canonical provenance before mutation.
It creates an annotated public tag, a draft, uploads each asset with its explicit
media type, and publishes only after the complete set reconciles. The resulting
canonical body binds the private source repository, commit and tree. A public
release is not consumable until anonymous updater discovery independently
accepts it.

If an outcome is ambiguous, rerun the identical command with `--resume`; do not
change the receipt, approval, source identity or anchor. Resume accepts that the
public default branch may have advanced because the receipt and annotated tag
still pin the original anchor. Exit code `3` denotes a platform/configuration or
approval error; `5` denotes interruption, deadline, or an outcome requiring
reconciliation. Other conflicts also fail closed with bounded, non-sensitive
errors.

A timed-out upload can leave a draft asset in GitHub's `starter` state. The
publisher will name that asset and refuse to proceed. Inspect the draft and,
only with separate approval for that deletion, remove the incomplete draft asset
before resuming. Never delete or recreate a published immutable release or tag,
and never relax media-type or provenance validation to reclaim a consumed
version.

Anonymous GitHub API access is rate-limited more tightly than authenticated
operator access. Scheduled checks are intentionally conservative; repeated
manual checks can temporarily report `source_unavailable` after the shared
source-address limit is exhausted.

## Separate maintenance handoff

Completion identifies the release URL, exact tag/commit/tree, qualification
run/artifact, and verified immutable bytes. Follow
[Maintenance-window upgrade](DEPLOYMENT.md#maintenance-window-upgrade) using
`deploy/playbooks/maintenance_deploy.yml`.

That independently approved operation still requires exact
`strugglebus_release_version`, `verified_release_dir`, authenticated immutable
acquisition attestations, the real external-backup gate, and typed
`maintenance_approval=deploy-<exactversion>`. Promotion's temporary verification
directory is not a persistent deployment input. Acquire and validate the release
through the documented maintenance procedure.

Maintenance supports its own staged candidate settings and forward-only
recovery. Selecting a candidate is not proof of a healthy completed deployment,
and promotion does not promise automatic predecessor rollback.
