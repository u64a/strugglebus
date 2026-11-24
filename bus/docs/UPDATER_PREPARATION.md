# Protected update discovery and package preparation

**G1 contract approved for local implementation:** 18 September 2026.
The owner approved the design and separately authorized local implementation
from `8b8a593`, on an isolated branch/worktree. That local-only approval did not
authorize commits, pushes, GitHub App/credential creation, provisioning, release
publication or deployment. The v0.2.27 review candidate is unchanged.

**Separate review submission approved:** 18 September 2026. After local
qualification, the owner authorized committing and pushing the isolated updater
branch, opening a stacked draft PR against `release/v0.2.27`, and running the
existing CI. This does not authorize merge, tags, publication, credential
creation, host provisioning or production adoption. PR #108 remains unchanged.

## Outcome and authority boundary

Browser **Check -> review exact release -> fresh-password Prepare** produces a
durable receipt for verified release files while the bus continues serving.
Prepared does not mean installed, a ready virtual environment, offline dependency
availability, successful migration/recovery qualification or activation approval.
There is no install, restart, rollback, schedule, shell, arbitrary-URL or upload
operation. Agent credentials, the admin bearer and containment grants do not
authorize this operator workflow.

The application uses its existing human session, exact Origin/CSRF/form bounds
and a separate password-confirmation budget. The final active-session check,
after password and exact-intent verification and immediately before submitting
the fixed IPC command, is the decision authorizing one bounded cache job.
Worker durable acceptance is a separate event, not a distributed atomic session
check. Later logout may race with acceptance; only that exact cache job may
finish. It grants no session, credential, installation or freeze authority.

No password, session cookie, CSRF value, bus/admin credential or device grant is
sent to the worker. Only the deciding actor identity and exact operation are
audited. Review tickets are process-local, session/actor/intent/application/
worker-policy bound, expire after five minutes and are limited to eight.
Application restart requires a fresh review/login, while an already accepted
worker operation remains observable.

## Components and trust

The operator application is the human-authentication boundary. An independently
confined non-root worker accepts a bounded Unix-socket protocol from the configured
application UID, verified with Linux peer credentials. Peer UID identifies the
application, not an independently proven human. The worker has no capability to
read/write the live database, admin credential, backups, service configuration,
current release link or freeze state.

The root-managed systemd socket is `0660`, accessible to the application's
existing group. Its parent is not writable by the application or worker. The
listening descriptor is passed to the dedicated worker, which does not join the
bus data group. The bus has no `Requires` dependency on the worker; unavailable
updates do not change `/healthz` or application startup/readiness.

The narrow first host profile leaves only the bus data directory's metadata
visible through a read-only namespace path so the worker can compare the actual
device. It requires application-owned `0700`/`0750`, a distinct worker UID/GID,
no bus-group membership and explicit absence of access/default POSIX ACLs.
Live database, backups, admin credentials, runtime and release paths remain
explicitly masked. This is not a claim of whole-directory masking. A blanket
data-root mask would substitute metadata and requires a separately reviewed
immutable topology-provenance contract, not an unchecked exemption. Actual
namespace/DAC/ACL behavior remains a real-host adoption gate.

The fixed update source is the public, assets-only repository
`NZCypher819/strugglebus-releases`. The worker reads it anonymously and sends no
Authorization header, ambient GitHub credential, cookie or proxy setting. It
therefore holds no source-repository credential and cannot use update discovery
to access private code, issues, Actions or other repository data. Worker config
version 2 pins both the public release repository and the private source identity;
unknown repositories or older credential-bearing config versions fail closed.

Public publication does not move source or operational configuration into the
public repository. A separately approved operator mirror step first verifies the
five bytes already published from `NZCypher819/strugglebus`, their manifest,
checksums and exact source commit/tree. It then creates an annotated tag and an
immutable public release whose canonical JSON body binds that private source
identity. Publication uses bounded operator release tooling; no GitHub credential
is installed on the Strugglebus VM.

A qualified installed wheel supplies the verifier. A mutable checkout,
downloaded candidate helper or candidate Python module is never executed.

## Discovery and verification contract

Release discovery is fixed to NZCypher819/strugglebus-releases, while
canonical metadata and the bundle manifest must bind source repository
NZCypher819/strugglebus. Verified TLS and exact
API/asset hosts are mandatory; redirects must not forward authorization or stale
Host headers. Ignore ambient proxy overrides. API authentication errors and
unavailable/partial results are never "no updates".

Check reads at most two pages of 20 releases. It chooses at most one newer stable
numeric release from that bounded window for exact resolution; a newer blocked
release is reported as blocked, not silently hidden. No arbitrary version picker
or `latest` acquisition exists in this slice. Incomplete pagination is explicit.
The running version/release identity comes from the application's own loaded
configuration, not browser fields, and is not proof of live migration readiness.

An exact candidate binds repository, numeric release ID, tag-object SHA, direct
annotated-tag target commit, source tree, package version, verifier policy ID
and the five asset IDs/names/sizes/digests/media types. Require non-draft,
non-prerelease immutable publication. Draft PRs and local artifacts are ineligible.

Prepare reobserves that identity, downloads exactly the wheel, production lock,
support archive, manifest and `SHA256SUMS` into a private quarantine, validates
canonical structure/limits/hashes/source/compatibility and reobserves publication
afterward. Hashes are byte integrity, not independent publisher authentication.
Retain the installed verifier's exact reviewed schema/guide/protocol/Python/uv
policy; unknown policy needs a trusted verifier update, not a bypass checkbox.
Historical published releases do not require current-main equality or a still
available seven-day qualification artifact.

Extract/share existing read-only validation and transport primitives rather than
copying a second verifier. Existing publication/build/controller entry points
retain their contracts. The existing published-byte verifier can download an
additional complete copy; this new path must not accidentally double download
or exceed its quarantine budget.

## Fixed local protocol, version 1

The wire format is one UTF-8 JSON object terminated by LF in each direction.
Reject duplicates, unknown keys, non-finite numbers, extra frames, invalid types,
NUL/control characters, oversized/truncated messages and unexpected peers.
Do not deserialize pickle from an external connection.

| Verb | Exact request keys in addition to `version`, `action` |
| --- | --- |
| `status` | `operation_id` (null for global status, otherwise 32 lowercase hex) |
| `check` | `operation_id`, `actor_id`, `application_version`, `application_release_id` |
| `prepare` | check keys plus `observation_id`, `candidate_digest` |

An actor ID is validated, at most 128 UTF-8 bytes, and supplied only from operator
context. Versions are bounded numeric `major.minor.patch`; release ID is null or
bounded safe text. Digests are 64 lowercase hex, operation/observation IDs 32 hex.
There are no credentials, paths, URLs, limits, environment values or commands.

Responses have exactly `version`, `ok`, `error`, `status`. A successful response
has a typed status and no error; a failure uses a static public error code, never
raw exception text, GitHub response bodies or signed download URLs. Unknown
outcomes are explicit, not success-shaped fallbacks.

The shared Python contract uses frozen dataclasses:

- `UpdateAsset(asset_id, name, size_bytes, sha256, media_type)`.
- `UpdateCandidate(version, release_id, tag, tag_object_sha, commit, tree,
  policy_id, assets)` with canonical `digest` binding every field.
- `UpdateDiscovery(candidate, complete, inspected, blocked_version,
  blocked_reason)`, where candidate is optional and only one is resolved.
- `UpdateOperation(operation_id, action, actor_id, phase, started_at,
  finished_at, error)`.
- `UpdateObservation(observation_id, checked_at, expires_at, application_version,
  application_release_id, discovery)`.
- `UpdatePrepared(candidate, verified_at, operation_id)`.
- `UpdateStatus(state, worker_version, policy_id, operation, observation,
  prepared, history_available)`.

Timestamps are bounded integer UTC epoch seconds; absent values are null.
Operation phases are accepted/running/succeeded/failed/interrupted. Global states
are idle/checking/observed/preparing/prepared/failed/interrupted/unavailable.
Serialization and decoding are exact and bounded, not permissive dataclass casts.

The read-side interface is `GitHubReleaseSource(settings, limits)` with
`policy_id`, synchronous `check(running_version, *, deadline) -> UpdateDiscovery`
and `prepare(candidate, directory, *, deadline) -> None`. The latter succeeds
only after exact published-byte verification. `verify_prepared(candidate,
directory, limits)` performs the corresponding trusted offline check.
`GitHubAppSettings(app_id, installation_id, repository_id, credential_path)`
contains no plaintext token. Tests inject synthetic transports/sources, never
production CLI bypass flags or actual credentials.

The application client interface is asynchronous `UpdateClient(socket_path,
timeout=2)`: `status(operation_id=None)`, `check(operation_id, actor_id,
application_version, application_release_id)` and `prepare(operation_id,
actor_id, application_version, application_release_id, observation_id,
candidate_digest)`, all returning `UpdateStatus` or raising `UpdateError(code)`.

## Durable worker state and budgets

Use a strict versioned journal, one current operation, one observation, one
prepared candidate and at most 16 terminal receipts. Protect filesystem ownership,
explicit modes, ancestry, links, inode substitution and atomic/fsynced publication.
Unknown/corrupt journal versions fail closed without recreating history.

Record accepted intent before starting external work. Identical operation ID and
intent reconcile; changed intent conflicts. A lost reply requires status lookup.
An absent/evicted receipt is history-unavailable, not proof no work occurred.
After restart, reconcile published bytes/receipts locally and mark incomplete work
interrupted; do not silently resume network work. A distinct request cannot bypass
an unresolved operation. Cleanup removes only exact owned quarantine paths, never
live data, prior good preparation or receipts to manufacture a clean history.

Keep one prepared and one quarantine slot. Cache replacement is disclosed during
confirmation. Publish the new verified receipt durably before retiring the old
inactive slot, and retain cleanup-pending state on failure. No new operation may
create an unbounded third slot.

| Resource | Bound |
| --- | --- |
| Work | One active check/prepare, no queue; at most four IPC status connections |
| Wire | 4 KiB request, 64 KiB response, two-second admission/status deadline |
| Discovery | Two pages x 20 releases; 2 MiB metadata responses; observation TTL 900s |
| Network work | 30s request timeout, at most three reads/retries, capped retry delay; absolute check 120s / prepare 600s |
| Artifacts | Exact five, existing per-file validator caps, 256 MiB aggregate candidate |
| Storage | 512 MiB artifact budget plus 4 MiB journal/receipts; 256 MiB free-space reserve |
| Traffic | At most 4 MiB/s aggregate, sequential asset downloads |
| Password | Independent updater budget, defaults 3/caller/minute and 6/global/minute |
| Refresh | At most one check per 60s globally |

Absolute deadlines include retries/token issuance. Use a bounded isolated trusted
job process when necessary to enforce a hard deadline without blocking status;
terminate only that owned child, not by process name. No candidate is executed.
Configuration may narrow ceilings, not enlarge them via browser or release data.
The 60-second check cooldown and 256 MiB free-space reserve are safety floors:
reducing either is not a narrower resource profile.

For the first host bootstrap profile, require an already provisioned persistent,
separately bounded cache filesystem, distinct from the bus data filesystem, with
capacity no larger than 1 GiB and sufficient free capacity for the above budgets.
Its mount root is exactly `root:strugglebus-updater 0710`: group traversal permits
the worker to reach its private `0700` state child without granting mount-root
listing or writes. Bootstrap must verify this; it does not provision disks,
mounts, ownership or modes, or accept an unchecked "quota exists" boolean. Other
quota profiles need separate review.
Use low CPU/I/O weight, a reviewed CPU cap, 512 MiB memory and 16 tasks.
This profile's actual systemd/filesystem behavior remains a Debian adoption gate.

## Console and deployment integration

Default disabled. Only `/operator/updates` human routes are added, with existing
exact host/origin/session/body admission. Check uses CSRF; Prepare also requires
its fresh password and unexpired exact review ticket. Render new review/status
pages with trusted bundled styling, no JavaScript, and manual status refresh.
Escape all metadata; do not render release-note HTML.

Worker/credential failure leaves the bus healthy. No agent REST/MCP updater tool
is added. Frozen state is not an IPC input: preparation never creates/restores
access or activates/clears freeze. A later installer must independently verify
live authority/schema/freeze/configuration/backups, regardless of receipt age.

Future host adoption uses a separate opt-in Ansible bootstrap from approved
checksummed installed code. No ordinary configure/deploy path enables it. Setup
must preserve current release, database, credentials, Caddy/network topology,
backup timers, maintenance provenance and existing recovery controls.

## Acceptance gates

Test anonymous/agent/admin/device bearer refusal; origin/CSRF/password/session
failure; precise form/wire limits; observation/ticket/operation binding; replay,
conflict, busy and history-unavailable cases; absolute deadlines and slot cleanup.
Exercise malformed/tampered/drifting releases, TLS/redirect/authentication failure,
archive bombs/links/traversal, policy mismatch and malicious candidate-code
sentinels. Verify no secrets or upstream bodies reach output.

Inject process loss at admission, each file/receipt publication and acknowledgement.
Exercise quota exhaustion, changed inodes, unsafe modes and child umasks
000/002/022 without weakening production checks or changing global runner policy.
Demonstrate 100 accepted posts and one uninterrupted 100-message SSE stream during
successful and failed preparation, with unchanged application identity/schema/
configuration and no lifecycle/database/freeze calls.

Keep Python 3.13 support, locked dependencies, packaging/publisher regression
tests and function-level complexity/coverage/CRAP gates. No CI workflow privilege,
timeout or skip changes. Real Debian/systemd/Caddy, distinct-UID confinement,
actual least-privilege App credentials and storage isolation require separate
approval and qualification; synthetic local results are not those proofs.

## Application settings and controller distribution

The bus receives only a protected socket path and operator bounds, never GitHub
App identifiers, signing-key paths or tokens. An unset/empty socket setting keeps
the feature disabled. An absolute local path must be outside application-writable
data/runtime/backup paths; Linux socket address-length limits also apply.

| Environment setting | Default | Permitted range |
| --- | --- | --- |
| `STRUGGLEBUS_UPDATER_SOCKET_PATH` | Unset (disabled) | Protected local socket path |
| `STRUGGLEBUS_UPDATER_CONFIRM_SESSION_PER_MINUTE` | 3 | 1-3, applied per session and source |
| `STRUGGLEBUS_UPDATER_CONFIRM_GLOBAL_PER_MINUTE` | 6 | 1-6 |
| `STRUGGLEBUS_UPDATER_REVIEW_SECONDS` | 300 | 1-300 |
| `STRUGGLEBUS_UPDATER_REVIEW_TICKETS` | 8 | 1-8 per application process |

Review tickets are not worker receipts. They disappear on application restart,
expire independently of the worker observation and cannot be used by a new
session. A retained worker receipt remains inspectable after fresh login; it
does not renew a review or confer installation authority.

The existing canonical five-asset support allowlist and qualification receipt/
helper-digest algorithms remain unchanged. New opt-in bootstrap controller
tooling is separately qualified against its exact approved source tree; it is
not silently included in an old support archive or downloaded/executed from a
candidate. Its distribution and real-host adoption remain explicit later gates.

## Later self-update adoption

This document remains the authority boundary for the unprivileged updater worker:
**Prepare still never installs or activates a release.** A later approved design
adds a distinct root-owned VM-local maintenance supervisor. When separately
adopted, the operator portal can request a manual installation or configure a
daily automatic window through that supervisor; it does not expand the worker's
permissions.

The supervisor independently validates the prepared five-asset bundle, creates
versioned application and updater environments, and invokes the existing
maintenance lifecycle under the release and freeze-transition locks. It posts a
fixed five-minute `#announce` notice, preserves freeze state, snapshots before
migration and stops with evidence on post-migration failure. The worker remains
unable to read the database, control services, change the active release or
influence the global freeze.

`deploy/playbooks/self_update_adopt.yml` is the separate host-adoption boundary.
Without that play and the application setting
`STRUGGLEBUS_MAINTENANCE_SOCKET_PATH`, all behavior in this document remains
prepare-only.
