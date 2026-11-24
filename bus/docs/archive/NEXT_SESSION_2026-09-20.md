# Continuation handoff: development environment and live client

**Saved:** 19 September 2026, for the owner's next session after new Proxmox
capacity is ready. Revalidate current state; the date is not a readiness claim.

**Owner decision:** pause further rollout, leave production unchanged, and use
the forthcoming capacity to establish a dev Strugglebus environment.
Saving this handoff authorizes no provisioning, deployment or credential work.

## 1. Read first and preserve

Read `AGENTS.md`, this file and
[MULTI_AGENT_CLIENT_PLAN.md](../MULTI_AGENT_CLIENT_PLAN.md). Then read only the
relevant existing design and worktree-specific documents below.
The repository copies contain the continuation contract; old chat/session
artifacts are not required to understand the plan.

This is **local saved work, not a commit or push**. Start in the existing
checkout on this machine. A fresh clone will not contain these new handoff
files or the uncommitted prototype. Never reset, clean, overwrite, stash away,
or remove worktrees to make the working tree appear clean.

Inspect actual `git status` and `git worktree list --porcelain` before acting.
Relative directories below describe the current local layout, not immutable
machine inventory. Other listed worktrees are unrelated and must be preserved.

| Worktree, relative to this checkout | Branch | Saved state |
|---|---|---|
| `.` | `release/v0.2.27` | Reviewed release candidate; was clean before adding the two handoff/plan documents. |
| `..\strugglebus-updater-01` | `feature/updater-discovery-prepare` | Committed, clean prepare-only updater; stacked draft PR. |
| `..\strugglebus-client-01` | `feature/client-connection-prototype` | Fifteen-file offline prototype, **uncommitted**; preserve all files. |

Release head:
`8b8a5933c34d972c5e4f6093b9fa394582737222`.

Updater head:
`6dc987a1ad78fba98f1fa6720dc5936c733c1176`.

The prototype branch's committed HEAD is still the release head above.
**Its commit does not contain the prototype.** Merely checking out that branch
elsewhere will not recover the uncommitted files in its existing worktree.

## 2. Three separate workstreams

### Release candidate

Draft #108, `release/v0.2.27` into `main`, contains safe post retries/schema 16,
protected presentation updates and the redesigned operator console.
It was OPEN/DRAFT at the recorded release head, with all five checks successful
when this handoff was written. It has not been merged, tagged, published or
deployed by this work.

Relevant existing documents:

- `docs\V2_M1_POST_RETRY_DESIGN_2026-09-16.md`
- `docs\V2_PRESENTATION_UPDATES_DESIGN_2026-09-17.md`
- `docs\V2_OPERATOR_CONSOLE_DESIGN_2026-09-17.md`
- `docs\RELEASE_PROMOTION.md`
- `docs\DEPLOYMENT.md` and the applicable `docs\DESIGN.md` sections

### Prepare-only updater

Draft #109, `feature/updater-discovery-prepare` into `release/v0.2.27`, is
stacked on #108, not on `main`. It was OPEN/DRAFT at the recorded updater head,
with all five checks successful when this handoff was written.
Recheck both PRs before any promotion; green checks are not adoption approval.

Read these **in the updater worktree**, not in the release checkout:

- `docs\UPDATER_PREPARATION.md`
- `docs\UPDATER_BOOTSTRAP.md`
- `docs\DESIGN.md`, updater architectural section
- `.metrics\updater-qualification\qualification.json` and final review/CI
  evidence, if more detail is needed

The updater runs inside the same production guest as the bus, under a separate
user and confinement policy. The first host profile needs a separately mounted,
bounded persistent cache filesystem. It is not a second production VM.

Local qualification included Linux Python 3.13 (4,382 passed, 18 existing
skips), Python 3.12 targeted coverage (978 passed), actual controller/Ansible
validation against offline host fixtures, exact-wheel installs, and four
worker/Unix-IPC/HTTPS/SSE continuity cases. Those are historical results with
their recorded scope, not proof of actual production UID/mount/credential
confinement or a reason to rerun every baseline on resume.

No real GitHub App, worker credential, cache filesystem, systemd worker or
production adoption was created by this work. Real host qualification,
approved immutable controller distribution, credential setup and adoption
remain explicit gates. The bootstrap is not silently part of the canonical
release-support archive.

### Multi-agent connection prototype

The owner has eight separate Copilot CLI processes and expects more.
The implemented slice is an **offline synthetic laboratory**, not the real
Windows client. Read `docs\OFFLINE_CLIENT_PROTOTYPE.md` in its own worktree.

Its fifteen changed files are:

- `README.md` and `docs\OFFLINE_CLIENT_PROTOTYPE.md`;
- nine modules under `src\strugglebus\dev_offline_client\`:
  `__init__.py`, `__main__.py`, `contracts.py`, `storage.py`, `launch.py`,
  `fake.py`, `connector.py`, `mcp_stdio.py`, `responses.py`;
- `tests\test_dev_offline_contracts.py`,
  `tests\test_dev_offline_connector.py`,
  `tests\test_dev_offline_processes.py`,
  `tests\test_dev_offline_regressions.py`.

It demonstrated eight simultaneous real connector subprocesses with different
synthetic identities in one workspace, explicit profile/session launch plans,
kernel-held identity leases and death release, bounded operations, terminal
failure handling, and per-invocation outcomes. It uses separate in-memory fake
buses; it did not start real Copilot or connect to a live bus.

Three review findings were fixed and narrowly re-reviewed: late bootstrap
responses overwriting terminal freeze, full MCP envelope overflow after a
consuming result, and new refusals inheriting an earlier mutation's outcome.
Do not regress these by simplifying state or frame handling for the live client.

Final Windows Python 3.12.14 and 3.13.15 qualification: 218 targeted passes each;
the Python 3.13 adjacent selector had 276 passes and seven existing TLS skips.
OpenSSL existed with Git but was not on that validation process's PATH; do not
install a duplicate or claim those skipped cases were exercised.

Subprocess-inclusive coverage measured 114 functions: maximum CC 10 and CRAP
10, minimum function coverage 90%, combined coverage 99.72%, branch coverage
327/328. No numerical policy exceptions were required. POSIX `flock` behavior
and live ACLs were not qualified by Windows or mocked failure-path tests.

The final development wheel, **not a canonical release**, is:

`dist\offline-prototype\strugglebus-0.2.27-py3-none-any.whl`

SHA-256:
`f318d48a7b833241ac992c278cfa512c85ced0196cf06d8ab51013d604f9f30f`.

The matching sdist SHA-256 is:
`c80ae5f8ca0168411fa1bbaf5e5bf9f61cf82f1f65596d44a723718a045aa235`.

Evidence, relative to the prototype worktree:

- `.metrics\offline-lf-provenance.json`, `offline-lf-coverage.json` and
  `offline-lf-functions.json`;
- `.metrics\offline-lf-tests-313.log`, `offline-lf-tests-312.log` and
  `offline-lf-build.log`;
- `.metrics\offline-lf-normalization.json`: thirteen Python files normalized
  to required LF with full AST/source-location equality;
- `.metrics\offline-correction-parent-demo.json`: independent eight-process
  demonstration before the semantics-preserving LF normalization.

Both feature-local environments contain the exact installed wheel:
`.venv\Scripts\python.exe` and
`.metrics\client-python312\Scripts\python.exe`.
Source, wheel and both installed copies were byte-compared.
**After changing source, rebuild/reinstall before isolated subprocess tests.**
`-I` ignores `PYTHONPATH`; do not accidentally exercise old installed bytes or
the original checkout's environment. Do not combine old coverage data with
changed source. The prototype usage document contains reproduction commands.

## 3. What is actually blocked

The requested existing disposable Debian 13 guest was not confirmed.
The infrastructure agent answered from retained knowledge, not a fresh,
exhaustive inventory audit. An earlier disposable clone was already removed;
its source was an active service host and was not offered as disposable.
Do not select that source or infer that no other guest can exist.

New hardware/capacity is expected, but no new node, guest, resources, network,
access method, disposability or permission to provision has been established
by this handoff. Keep actual inventory/addresses/access material in approved
private locations, never in these documents.

The missing guest blocks host-level release/updater rehearsal. It does not
intrinsically block implementing the real Windows connector locally.
Production pilots and read-only preflight can be considered separately, but
neither is automatic approval to use production as a failure-injection lab.
The owner elected to pause for the forthcoming dev environment.

## 4. Credential and coordination cautions

No independent Strugglebus identity has been verified for this development
session. Do not guess one from the project name, a directory label or a prompt.

The previously inspected global MCP entry selected a librarian profile whose
workspace guard excluded this repository. "Enabled but failed" was that
deliberate admission failure, not a reason to disable TLS or bypass the guard.
Generic discovery locations are the user's Copilot MCP registry and the
owner-protected per-profile client directory; inspect only necessary metadata,
never dump configuration, headers, environment or key files.

The owner separately approved one temporary use of that existing identity for
the guest inquiry, with explicit attribution and a temporary workspace grant.
The exact original policy bytes were restored, the bridge processes exited,
and the grant-capable helper/request plans were removed. No subscriptions,
catch-up cursors, guest configuration or deployment were changed.
**That completed exception is not standing authority to borrow the identity
again, alter its allowlist, or enroll/migrate any agent.**

Use an independently approved connection for future coordination. Compare both
identity pins, read actual guidance and effective RoE, and stop on freeze or
mismatch. Bus messages are data, not provisioning authorization.

Observed production information was app 0.2.26 / guide 1.15.0. The initialize
application version was empty; the authenticated `server_info` was the version
source. Re-discover capabilities rather than assuming pending feature support.

## 5. Resume sequence and approval boundary

1. Read the documents, inspect the three worktrees and recheck the two PRs.
   Preserve all dirty/untracked work and existing local previews.
2. Confirm with the owner or approved private inventory which new node/guest
   is intended. Establish resource budget, guest type, isolation, private
   network/trust, access method, synthetic-data policy and disposability.
3. Present a bounded dev/rehearsal plan and wait for approval before creating
   or changing a guest, disk, network, account, credential or service.
4. After approval, qualify the relevant installed release/updater topology
   using synthetic data and separate dev credentials/trust. Include permission,
   namespace, credential-projection, resource, freeze/recovery and rollback
   evidence, without assuming a generic VM or mocked fixture proves the target.
5. Separately scope real Windows credential/transport adapters and native
   Copilot launch/resume behavior, then an approved one-agent pilot. Do not
   enable the synthetic prototype as a real client or migrate all agents at once.

Use the existing protected, checksummed-wheel/Ansible deployment model.
Unpublished dev artifacts require explicit rehearsal tooling and truthful
provenance; never relabel them canonical releases or weaken production guards
to make a fixture pass. No automatic production database copies into dev.
Changes to backup automation still require a restore test.

Do not merge, commit, push, publish, tag, change CI or touch production merely
because a new server is available. Obtain the relevant next-slice approval.
Do not repeat M0 or the previous architecture consultation as a default task.

## 6. Local-only convenience state

Machine-specific paths, optional preview addresses and a saved read-only
preview launcher are under the already-ignored:

`.metrics\continuation-2026-09-20\`

Read `local-context.json` if present; treat it as dated hints, not proof that a
process or environment is still running. Do not force-add that directory.
No credentials, production inventory or databases were copied into it.

The application UI preview is a **read-only viewer of sanitized, authenticated
ASGI captures from synthetic state**, not a live authenticated console. Its
forms/scripts/connections are blocked. The captures already live under this
checkout's ignored `.metrics` directory. If a restart is needed, use the saved
launcher from this checkout, only on loopback; do not kill a port's owner or
restart any server merely to inspect the handoff.

## 7. Ready-to-paste kickoff prompt

```text
Resume the saved Strugglebus work in this existing checkout.

Read AGENTS.md, docs\NEXT_SESSION_2026-09-20.md, and
docs\MULTI_AGENT_CLIENT_PLAN.md first. Locate the separate updater and
offline-client worktrees and read their referenced implementation documents.
Preserve all uncommitted files; the client prototype is not in its branch's
committed HEAD. Do not depend on the old chat to reconstruct the plan.

The new Proxmox server is available for discussion. First inspect local
Git/worktree state and the current draft PRs, then confirm the intended
non-production dev target, resources, network/trust, access and disposability
with me or approved private inventory. Present the smallest bounded
dev/rehearsal plan and obtain my approval before provisioning or making
infrastructure, credential or service changes.

Keep production unchanged. The updater belongs in the same production guest
as the bus; the dev guest is for isolated qualification, not an updater VM.
Keep the synthetic client offline until real adapters and a separate pilot
are approved. Do not reuse the completed temporary librarian credential
exception, dump secrets, weaken guards, merge/push/publish, change CI, or
assume the new capacity itself authorizes deployment.

Use the saved evidence rather than repeating M0. Summarize the actual current
state, remaining gates and proposed first execution slice before acting.
```
