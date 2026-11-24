# Security testing

CI remains useful because it repeats the repository's behavioral and security
contracts on a clean Python 3.13 environment - the deployed interpreter - before
merge. The qualification workflow also clean-installs the exact published wheel
on Python 3.13 before a release.
The existing
pytest suite exercises:

- hashed, one-time API-key issuance, constant-time admin authentication,
  immediate revocation, credential redaction, and duplicate-header rejection;
- persistent fail-closed access-freeze state, bounded transition audit,
  idempotent concurrent local controls, authorization ordering, transactional
  mutation refusal, restart persistence, and unreadable-state failure;
- authentication before request-body parsing, bounded bodies and models,
  strict pagination, trusted-proxy handling, and atomic rate limits;
- REST and MCP authorization failures, shared identity and state, safe errors,
  global message ordering, conflict handling, concurrent clients, stable
  freeze denial, health/dashboard policy, and prompt terminal SSE shutdown;
- transactional, versioned SQLite migrations, unknown-version refusal,
  integrity-checked backups, rollback on failure, and serialized startup; and
- production configuration defaults, protected systemd credential files, safe
  application composition, and offline deployment/recovery contracts;
- failure injection for every named disposable production-smoke phase, atomic
  bounded diagnostics, exact marker cleanup after partial/success/failure paths,
  and the Ansible `always` cleanup/report ordering;
- Linux and WSL/Windows CA export confinement, unsafe owner/mode/ACL and
  symbolic-link/reparse refusal, no-clobber targets, atomic rollback, public
  certificate fingerprint output, and signing-material exclusion; and
- the real-server v0.1 acceptance flow, release artifact contents, a fully
  hash-locked production dependency export, deterministic canonical release
  manifests/support archives, and clean exact-wheel Python 3.13 installs.

The deployment job additionally checks `requirements.lock`, builds and inspects
the distributions, installs the wheel into an isolated Python 3.13 environment,
starts it with the production Uvicorn target and hardening flags, syntax-checks
and renders the Ansible playbooks, validates provisioning inputs and public
keys, and exercises SQLite backup and restore. These tests
establish expected behavior; they complement rather than replace security
scanners.

Release tests cover annotated-tag/ref confusion, repository-owner and exact-current-
main enforcement, required successful CI jobs, disabled immutable-release refusal,
canonical generation, replay/idempotency and conflict contracts, duplicate/missing/
unexpected assets, hash/size tampering, source commit/tree mismatch, schema/package
downgrade, protocol/guide/freeze incompatibility, incomplete downloads, and the
undefined-by-default Ansible verified-directory input with its explicit active-
version downgrade boundary. The owner-approved qualification workflow builds once
on Python 3.13, validates the same staged bytes on Python 3.13, and the
tag-triggered publication workflow builds nothing at all. Both serialize every
release run under one repository-wide concurrency group. That serializes workflow
writers only; it does not prevent external owner mutation. Immediate
pre-publication checks narrow but do not eliminate that race, so the operational
boundary is a trusted sole owner who creates one annotated tag on exact reviewed
current `main` and abstains from tag deletion/movement and draft edits during the
run. A failed unpublished immutable-release attempt permanently consumes its
annotated version tag: recovery requires a version bump and a new annotated tag
on corrected, reviewed, CI-green `main`, never tag movement, deletion, or
recreation. Versions `0.2.5` and `0.2.6` are disqualified for production
deployment and permanently consumed; their artifacts may not be relabelled,
promoted, or deployed. Version `0.2.28` is likewise disqualified after its
application module omitted the validator-visible freeze-capability export.
Version `0.2.31` is disqualified after its updater rejected the protected
`current` release symlink before application activation. Version `0.2.32` is
disqualified after its maintenance runtime confused the updater version with the
active application version and prevented update discovery before activation. The
clean-install qualified release is `0.2.8`.

Deployment validation also exercises the dedicated first-install action against
a blank release root, an exact idempotent rerun, a partial candidate, a conflicting
active release, and a database that predates activation. Static contracts require
TLS-verified first-release health and fail-closed cleanup without any cutover
operation, previous-release identity, or pre-stage digest. Offline template tests
render internal, compatible dual-site external, and dedicated external-only
Caddy/systemd configurations; the external-only case must contain one
external-certificate site, no `tls internal`, and no `bus.lan` application
host/origin entry.

Canonical wheel tests prove that two builder wheels differing only in embedded
timestamps and in `0644` versus `0660` member modes normalize to byte-identical
canonical wheels, that every normalized member carries one fixed, ZIP-safe,
even-second timestamp and mode `0644` with no extra fields or comments, and that
member order, member names, and exact uncompressed payloads survive
normalization. They validate wheel `RECORD` hashes and sizes before and after
normalization and reject unlisted members, missing or self-hashed `RECORD` rows,
duplicate member names, absolute or traversing names, directory entries,
symlinks, setuid members, out-of-range timestamps, destination clobbering, and a
`--source-date-epoch` that does not match the wheel. A fresh `uv build` wheel is
normalized twice from different timestamps and compared byte for byte.

Qualification tests cover the owner-bound dispatch gate (actor, approver, exact
approval phrase, `refs/heads/main`, repository, tag format, workflow/commit
identity, exact current main, and successful main CI) and the canonical
pre-upload receipt that binds the exact five asset names, sizes, and digests, the
run and attempt, the expected artifact name, the owner approval, the tool
identities, and the expiry. Release-bundle tests build the exact five assets in a
real temporary git repository that has no tag at all, proving that explicit
pre-tag qualification mode succeeds against a supplied exact commit and tree
while the default mode refuses a missing tag, refuses a lightweight tag, accepts
a real annotated tag, and still refuses tracked dirty state, wrong trees,
unknown commits, and non-exact identities. Workflow tests require the
qualification run to upload exactly one artifact and the publication run to
download exactly one artifact, and require both workflows and the publisher to
contain no second evidence artifact at all.
Publication tests prove the tag workflow performs zero builds and refuses, before
the first draft, upload, or publish call, a wrong or missing qualification run,
zero or multiple qualification runs, an expired artifact, a foreign workflow run,
a wrong artifact ID, name, size, or digest, a receipt that names the wrong run or
artifact, a drifted canonical-wheel helper digest, an expired or future-dated
receipt, a missing or non-canonical receipt, and any asset hash, size, or
file-set drift. Every negative case asserts zero release mutations.
Each clean-install run resolves its requested major/minor with
`uv python find --no-project`, accepting either a uv-managed or system
interpreter. It rejects missing or non-executable selections, and the selected
interpreter independently verifies its exact requested major/minor before any
artifact installation.
The workflow `GITHUB_TOKEN` remains read-only in both release workflows. Only the
publishing job receives the
protected App secrets and mints a masked installation token scoped to the single
repository with Administration read and Contents write. Tests pin the official
token action, require the explicit owner/repository/permission inputs and automatic
revocation, ensure the publication gate alone defers the admin-only setting check,
and require the qualification workflow to hold no App token, no write permission,
and no publication entry point.
There is no attestation, OIDC, PAT, production, or inventory permission.
Publisher contract tests run an absent-release-through-immutable mocked REST
state machine with `gh` absent from `PATH`, exercise partial-draft and exact
immutable replay, and reject mutable/conflicting metadata, duplicate or
unexpected assets, incorrect media metadata, byte substitution, unsafe
redirects, missing content disposition, authorization failures, and oversized
responses. Real `OpenerDirector`/`HTTPSHandler` tests reproduce urllib source-Host
injection and prove that one exact API-to-asset 302 derives a fresh target Host
while stripping authorization, proxy authorization, cookies, API-version, and
arbitrary headers. They reject host suffixes/wildcards, other
`githubusercontent.com` hosts, alternate redirects, chains, loops, relative or
malformed locations, downgrade, userinfo, fragments, and non-443 ports; distinguish
API 404 from sanitized target 404; bound retry/timeout behavior; and enforce
disposition, name, media type, length, size, streamed SHA-256, exact final origin,
no-clobber, and cleanup. Mutation failures reconcile exact observed state rather
than blindly retrying, temporary downloads are removed on failure, and static
workflow contracts prohibit runner `gh` invocation.

The separate recovery-proof tests hard-code the consumed `v0.2.3` tag object,
commit, draft, sole asset metadata, size, and digest. State-machine tests require
matching immutable settings and owner/workflow/current-main identity, exact
before/download/after reads, mismatch refusal, ephemeral cleanup, and bounded
secret-free output. Static tests require no workflow inputs, the shared release
concurrency group, non-root `prox-runner`, short timeout, SHA-pinned actions,
automatic App-token revocation, no `gh`, and only GET-capable probe calls. The
live proof is a post-merge prerequisite on the same exact green `main` commit
before an owner dispatches qualification and creates `v0.2.8`; it is never
dispatched by CI or by the
correction pull request.

GitHub Free does not provide artifact attestations for private repositories.
Authenticated TLS acquisition from the pinned private immutable GitHub Release is
therefore the publisher-authenticity boundary. Offline manifest and SHA-256
validation proves integrity only and must never be reported as a signature or
independent authenticity proof.

The separate `Isolated LAN CA integration` job installs checksum-pinned
`step-ca` 0.30.2 and `step` 0.30.6 into `RUNNER_TEMP`, starts a real CA on
loopback with throwaway test-only material, and exercises the production
certificate scripts. It proves TLS hostname verification of the CA endpoint,
wrong-password rejection, exact `bus.u64.lan` issuance, unauthorized SAN and CA
hostname rejection by server-side policy, exact DER bundle fingerprints,
guest-local generation and key pairing, atomic current-link renewal,
concurrency exclusion, invisible partial issuance, Caddy validation/reload
rollback, and the 12-hour warning / 4-hour critical machine-readable expiry
states. The test never uses Docker, sudo, production connectivity, protected
inventory, or production secrets. A blocking FIFO check-mode fixture proves
Ansible does not open the configured JWK password source.

## Fork policy and manual merge gate

All jobs that checkout and execute repository code remain blocked for
fork-originated pull requests, so untrusted fork code never reaches the
`[self-hosted, prox-runner]` fleet. A separate `Fork policy` workflow uses
`pull_request_target` only to run a static policy decision from the base branch
on the repository-scoped, non-root `[self-hosted, prox-runner]` JIT fleet. The
fork event can allocate a runner, but the base-owned workflow has no permissions,
secrets, checkout, actions, head references, pull-request code, or
attacker-controlled interpolation. Its only commands print static text and fail
the job. It fails for a head repository other than this repository and succeeds
for a same-repository pull request. The one-minute timeout bounds JIT occupancy.
The trigger's narrow inline zizmor suppression is justified by those enforced
constraints; do not broaden it or add any step that consumes head-repository
content.

The current private-repository plan does not provide native required status
checks: branch-protection and ruleset APIs return `403`.
Manual governance therefore requires:

- for a same-repository pull request, merge only after `Fork policy`, every
  applicable `Python 3.13`, `Deployment validation`,
  `Isolated LAN CA integration`, and `Security` check, and the independent
  review are successful and clean;
- for a fork-originated pull request, require `Fork policy` to fail, reject the
  pull request, and never override or treat the skipped prox-runner checks as
  approval; and
- if any expected check is absent, pending, cancelled, or skipped unexpectedly,
  do not merge.

The pull request that first installs this base-controlled workflow cannot
display its policy check because `pull_request_target` reads the workflow from
the base branch. After that bootstrap pull request merges, open a harmless
same-repository validation pull request and prove both `Fork policy` and the
applicable CI checks before declaring the release complete. Do not accept fork
pull requests before that proof.

A plan upgrade is optional. If native required checks become available later,
require the GitHub Actions job checks named `Fork policy`, `Python 3.13`,
`Deployment validation`, `Isolated LAN CA integration`, and
`Security`; the manual review policy still applies.

## Security job

The separate `Security` job is secretless, read-only, limited to ten minutes,
blocked for fork-originated pull requests, and runs on the approved
`[self-hosted, prox-runner]` JIT fleet. It uses:

- pip-audit 2.10.1 against the tracked, hash-pinned production
  `requirements.lock` exported reproducibly from `uv.lock`;
- Bandit 1.9.4 over `src/`, deployment Python, and release validation scripts,
  with no globally skipped
  rules; the fixed-command deployment validator has two line-specific,
  adjacent-rationale suppressions for its shell-free subprocess import/call;
- zizmor 1.29.0 in offline strict-collection mode over local workflow and
  Dependabot configuration; and
- Gitleaks 8.30.1 over reachable Git history, with output fully redacted.

Deployment validation also executes the production release precondition tasks:
verified weekly `vzdump` and explicit missing-backup owner acceptance each pass
alone, while neither or both fail closed before artifact upload or activation.
It validates wheel names with the packaging standard parser and executes the
production immutable-release preflight against fresh, matching, conflicting,
legacy-renamed, ambiguous, and installed-marker-mismatch states. Refused states
must not reach the artifact mutation boundary. Static contracts also require
all wheel-named filesystem entries to be inspected and deploy/rollback actions
to remain inside the process-owned release lock. Executable helper regressions
cover rollback targets that are valid, partial/markerless, tampered,
conflicting, symlinked, root-only, or inaccessible to the configured service
identity; protected-backup tests cover traversal, symbolic-link parent/final
escapes, unsafe modes, hard links, and descriptor-pinned root-owned staging.
Capability regressions cover legacy and `global-v1` marker shapes, runtime
cross-check mismatch, strict read-only v6 freeze inspection, capable/incapable
targets, frozen/unfrozen rollback backups, automatic recovery, check mode, and
refusal before mutation. Static runbook contracts require network exposure to
stop before suspect application/data recovery, listener absence verification,
evidence preservation, and reviewed freeze-capable restoration.
Staging tests also require the database-size-plus-64-MiB capacity margin.
Minimal-guest service-user tests execute the shared deploy/rollback backup
boundary without `sudo`, verify exact `timeout`/`runuser`/`env -i` argv and the
allowlisted child environment plus pinned `/usr/bin/python3.13 -I` invocation,
observe the requested UID/GID through the real
`/usr/sbin/runuser` path when validation runs as root, and prove a privilege-drop
failure cannot reach activation. Raw-byte regressions reject CRLF and byte-order
marks in tracked Python, shell, and deployment templates, require exact helper
shebang bytes, and directly exercise every root-installed Python helper through
Linux kernel execution.
Real `ansible-playbook --check`
regressions cover fresh and existing deploys, valid rollback, partial/tampered
refusal, backup escape refusal, and byte-for-byte fixture immutability. Lock
regressions cover contention, timeout, valid stale-owner recovery, live-owner
refusal, malformed metadata, wrong-owner release, and lease cleanup after
controller loss.

GitHub Actions are pinned to full commit SHAs with release comments so
Dependabot can continue updating them. `setup-uv` also verifies the uv 0.12.7
Linux x64 release archive against SHA-256
`788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21`.
Gitleaks is downloaded from its GitHub release and its Linux x64 archive is
verified against SHA-256
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`
before local execution. Source and findings are not uploaded to a scanner
service.

## Local reproduction

Run the normal gates first (these are entirely offline and do not run the
production smoke or export a production CA):

```powershell
uv sync --locked --all-extras --group security
uv run python scripts/check_requirements_lock.py
uv run pytest
uv build --wheel
uv run python scripts/validate_release_artifacts.py dist
```

On Linux, reproduce the isolated CA job without any production input:

```bash
export RUNNER_TEMP="$(mktemp -d)"
bin="$(bash deploy/tests/install_lan_ca_test_tools.sh)"
PATH="$bin:$PATH" bash deploy/tests/lan_ca_integration.sh
```

Then run the locked Python and workflow checks:

```powershell
uv run --no-sync pip-audit --requirement requirements.lock --require-hashes --disable-pip --strict --progress-spinner off
uv run --no-sync bandit --configfile .bandit.yaml --recursive src deploy scripts --severity-level low --confidence-level medium
uv run --no-sync zizmor --offline --strict-collection .
```

Install Gitleaks 8.30.1 from its official release, verify the archive against
the release checksum file, then run:

```powershell
gitleaks git --redact=100 --no-banner --no-color --timeout 120 .
```

## Triage

Security findings fail CI. Update or remove a vulnerable dependency and refresh
`uv.lock`; fix unsafe Python or workflow behavior; and rotate/revoke any exposed
credential before removing it from content and history. Do not add blanket
skips, vulnerability ignores, or secret baselines. A proven false positive may
use only the scanner's narrowest finding-specific exclusion, with an adjacent
rationale and explicit review in the pull request.
