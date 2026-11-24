# Early M5 slice: presentation updates without a bus restart

**Date:** 17 September 2026. **Status: G1 approved; locally implemented.**
**Local readiness review:** complete. Not released, deployed or production-qualified.
This pulls one outcome forward from M5, alongside the D6 operator-console
redesign. It does not implement all updates, complete M5, move the repository,
change CI workflows, publish a release or authorize production changes.

## Owner decisions and first outcome

The owner wants short development-to-feedback cycles, proportional delivery
paths and hidden implementation machinery, not a full outage for every visual
change. The owner selected:

- **Website controls in this first slice:** prepare, review, confirm and activate.
- **Verified, locally staged candidates first.** Automatic release acquisition
  is a later slice; the website is not yet a complete release downloader.
- **Redesign the whole current console:** board, activity, channels, roster,
  administration and login, not only administrative forms.

After readiness review the owner selected `approve-and-implement-locally`,
approving this contract and separately authorizing local implementation.
This grants no publication or deployment approval.

**First demonstration:** after an explicitly approved bootstrap, an operator
uses the website to activate a compatible stylesheet. A fresh page uses its
new immutable URL and visibly changed styling. The running application identity
is unchanged, existing agent requests continue and an already-open SSE
connection is not restarted by the update. Existing pages can still fetch
their original stylesheet. Invalid candidates leave the selected presentation
unchanged.

This is **no update-induced bus restart or agent disconnection**, not a promise
that every existing browser tab repaints immediately, that natural SSE lifetime
expiry stops applying, or that an unrelated host failure becomes impossible.
Browser refresh is an acceptable way to see the change.

## Current evidence and reusable boundaries

The starting checkout is HEAD `d8c51f6769aef5e609fa1512797593f7e98267dd` plus the
preserved local [M0](V2_M0_BASELINE_2026-09-16.md),
[P0](V2_P0_CAPABILITY_PROBE_2026-09-16.md) and implemented
[M1 retry slice](V2_M1_POST_RETRY_DESIGN_2026-09-16.md).

| Current surface | Evidence and implication |
|---|---|
| Stylesheet | `src\strugglebus\dashboard.py:71,433-436`: 11,074 UTF-8 bytes embedded in Python, with a URL derived from its SHA-256 prefix |
| Asset serving | `api.py:2473-2483`: the registered route returns that in-process constant; swapping a file today does not update the served CSS |
| Asset admission | `api.py:3236,3266,3427-3431`: an exact path set identifies human assets; host validation and source-rate admission apply, but operator cookies are not required |
| HTML rendering | `dashboard.py:759-829` and `operator_web.py:41-63`: shared pages and the minimal login/error renderer embed the stylesheet reference |
| Cache/security policy | `dashboard.py:459-485`: HTML is `no-store`; content-addressed CSS is public-cacheable for one year and immutable; no inline styles or JavaScript |
| Edge policy | `deploy\roles\caddy\templates\Caddyfile.j2`: Caddy preserves the same restrictive policy and proxies to the loopback application |
| Operator authority | `operator_auth.py:382-403,438-467`: bounded password verification, current sessions and CSRF checks already exist |
| Privilege boundary | `deploy\roles\systemd\templates\strugglebus.service.j2:65-94`: the application remains unprivileged with strict filesystem protection and dedicated writable data/runtime/backup paths |
| Artifact trust | `scripts\release_bundle.py:580-672`: qualified wheel, requirements, deployment support, manifest and checksums form the existing fixed release asset set; checksums alone do not prove publisher identity |

A visible UI change is not necessarily an asset-only change. Server-rendered
markup, application logic, API contracts, authority and host settings retain
their own delivery paths. This slice introduces no JavaScript, SPA, external
fonts/images, arbitrary templates or CSP relaxation.

## Architecture: installation is not selection

Use two separate operations with deliberately different authority:

1. **Protected staging:** the existing trusted release/Ansible path installs
   verified, immutable presentation candidates into a dedicated root-owned
   catalog/object area that the web service can read but cannot modify.
2. **Website selection:** the unprivileged application prepares and selects an
   already-staged compatible candidate by updating bounded presentation state
   in a dedicated subdirectory of its existing writable data area.

The website gets no shell, sudo, systemd control, package installation,
repository credential or write access to application code, staged CSS, the
catalog, TLS configuration or credential files. It does not invoke the general
maintenance installer. Selecting CSS does not require a new privileged daemon
merely to execute a file switch.

Staging must have a narrowly reviewed presentation-only path. Do not invoke a
whole configure/deploy play and assume that its handlers will happen to be
no-ops. Its permitted mutations are the presentation objects and catalog;
there must be no current-release-link change, service restart, candidate
application startup or database migration.

The readiness review confirmed that the full release role is not this path:
`deploy\roles\release\tasks\main.yml` admits only its existing release actions
and imports safety helpers through an interpreter. Its asset resolver is also
guarded by those action names and currently pins schema 16. Reuse the reviewed
offline validation logic, not the full role with a new label or assumptions
that unrelated tasks will be skipped.

The proposed payload is CSS plus a small versioned descriptor packaged inside
the qualified wheel. Ansible derives the installed objects from exact verified
wheel members without importing or executing candidate application code.
Application deployment remains checksummed-wheel/Ansible based. A sixth public
release asset, new publishing workflow and automatic acquisition are not
required for this local-candidate slice.

Publisher/manifest acceptance and markup compatibility are separate gates.
The first stager must retain the existing supported release/manifest checks.
If it cannot verify a future source release, refuse staging even when that
release claims a matching markup contract. Do not silently skip a schema,
provenance or helper check to obtain its CSS; extending supported source-release
formats is a separately reviewed compatibility change.

The catalog binds each opaque candidate ID to the exact source release/wheel
identity, presentation revision, markup contract, CSS byte length and full
SHA-256. Its layout and descriptor version must be strict and bounded.
Unknown fields/versions, duplicate identities, unsafe archive members and
untrusted provenance are refused. A browser supplies a candidate ID, never a
URL, filesystem path, wheel member name, CSS text or claimed trust/impact flag.
Catalog/descriptor labels and source/actor metadata remain untrusted display
data: bound and escape them for HTML and structured logging. Provenance does
not make arbitrary strings safe to interpolate.
The stylesheet is strict UTF-8 text with no NUL, served as its exact verified
bytes; do not repair or normalize it after hashing. Browser-based checks assess
CSS rendering, not a homemade regular-expression claim of full CSS safety.

This explicitly leaves **candidate distribution** as a separate step for now.
The website's Prepare action validates local material; it does not claim to
download or install a newly published release.

## Compatibility and rendering contract

Introduce one explicit markup/presentation contract, provisionally
`operator-console-v1`, compiled into the running backend and included in each
candidate descriptor. It covers the current console's semantic markup,
required selectors, safety notices, form/control states and accessibility
affordances. It is not the application version, database schema or agent
coordination protocol version.

An asset-only activation requires an exact supported contract match, verified
bytes and a reviewed visual/accessibility result. A matching label alone does
not prove a stylesheet safe or usable. CSS is trusted presentation code:
only qualified publisher content is eligible, not user-supplied themes.

The running backend supplies its contract; the browser cannot choose it and
an on-disk release link is not proof of which code is currently running.
An application restart invalidates outstanding preparations. Later changes
that break the markup contract are application updates with a coordinated
presentation plan, not hot stylesheet updates.

Each HTML response uses one immutable presentation snapshot for its stylesheet
URL and any displayed presentation version. No response may mix references
from two selections. Wire every shared, login, error and administrative render
path; do not style only the dashboard while leaving recovery pages behind.
Keep state/cache ownership per application instance, not a mutable process-wide
replacement for `DASHBOARD_STYLESHEET_PATH`.

New stylesheet URLs use the full digest. Preserve the existing legacy URL
mapping to its original bytes; do not change the contents behind an immutable
URL, accept arbitrary shortened-hash aliases, or automatically delete assets
needed by existing pages. If bootstrap styling changes, retaining the old URL
requires retaining the old bytes too.

Asset routing and middleware admission share one strict path grammar. This
must not turn `/assets/` into a general file server or bypass host/source-rate
checks. CSS remains same-origin `text/css` with `nosniff`, immutable caching
and the current restrictive CSP. Unknown/unapproved objects are not served.
HTML remains `no-store`. Caddy's strict policy is not weakened.
Serving a retained immutable stylesheet is not permission to activate it:
old approved objects may still be needed by old pages even when their markup
contract is no longer eligible for a new selection.

Expose **application identity and presentation identity separately** in the
authenticated console. A stylesheet switch must never announce that the
application, schema or agent protocol has been upgraded.

## Website flow and authority

Proposed operator-only HTML flow, using ordinary forms rather than JavaScript:

| Operation | Behaviour |
|---|---|
| Open presentation controls | Show selected/effective presentation, health, current markup contract and a bounded local candidate list |
| Prepare | Authenticate, enforce CSRF/admission, validate candidate bytes/contract and bind a short-lived preparation to the operator session and current selection generation |
| Review | Show exact candidate identity, impact, compatibility and recovery information using the **current** trusted styling |
| Preview | Open a separate inert specimen document with candidate CSS; no live forms, credentials, action links or real bus data |
| Confirm and activate | Require fresh operator-password proof in this request, revalidate current authority and candidate, then atomically compare-and-set the selection |
| View operation status | Distinguish accepted operation, current selection, superseded preparation, rejection and unknown outcome |
| Restore previous/bundled styling | Use the same prepare/confirm/activate path and compatibility checks; this is not application or database rollback |

The preview is not a themed copy of live administrative controls. It must not
make a real revoke, grant or freeze action look like a harmless demonstration.
The confirmation page does not adopt candidate CSS before activation.

Reuse the current operator session, exact-origin form handling, CSRF and
bounded password-verification implementation. Add a named, bounded presentation
confirmation rate family rather than silently consuming the existing
`device-enroll` budget inside `OperatorAuth.reauthenticate`. Do not remember
"recently reauthenticated" as permission for later activations.

Only current operator authority is accepted. Agent API keys, bus messages,
mobile monitor credentials and containment grants confer no presentation
activation authority. Callers cannot supply the deciding actor identity.
Revalidate the session after asynchronous work and immediately before the
selection write; the existing database-operation wrapper does not by itself
protect a new filesystem mutation.

The final active-session check, after candidate verification and under the
selection-operation lock, is the **authorization decision point**. Logout or
expiry that wins before that check denies the operation. An operation already
authorized there may finish publication after logout; it is not cancelled
retroactively. The response guard may consequently deny the response even
though selection changed, which is an unknown caller outcome to reconcile.
Do not hold the shared operator-authentication lock across filesystem I/O to
manufacture a stronger ordering guarantee: synchronous users of that lock
could otherwise block the ASGI event loop and unrelated agent traffic.

Presentation selection can remain available while agent access is frozen:
it neither creates/restores access nor changes containment. The same freeze
state and audit history must remain intact. This does not authorize backend
installation while frozen or allow the presentation path to mint credentials.

## Selection state, concurrency and recovery

Prefer a small, versioned JSON control record, separate from the bus database.
**No bus SQLite schema change is proposed.** The record contains an incarnation
ID, monotonically increasing selection generation, selected/previous references
and bounded recent operation receipts with deciding operator identity.

The presentation module owns locking, validation, atomic replacement and cache
publication. Keep these details out of route handlers. Reuse the repository's
descriptor/identity checks and atomic-publication patterns where applicable,
without borrowing credential-file permissions or Linux guarantees blindly.

New human HTML snapshots must observe the authoritative control record, not
only a last in-process assignment. Coordinate bounded reads with publication
and protected local reconciliation, outside the ASGI event loop. Immutable
verified CSS bytes may be cached, but a cache hit is not proof of the currently
selected generation. A local recovery operation must be visible to the next
fresh render without requiring a timer or restarting the application.

The local file probe below found that an ordinary open Python reader prevents
replacement on Windows. Readers and writers therefore need a compatible,
bounded coordination protocol; do not assume POSIX old-file-descriptor
replacement semantics on every supported development platform. The selection
lock is independent of bus database, agent-request and operator-auth locks.
All authorized selection writers, including local recovery, participate.

Activation must:

1. Require current operator authority, CSRF and fresh password proof for the
   activation POST, without holding the selection lock during password work.
2. Acquire the bounded selection lock and reread validated current state.
3. Resolve a matching retained operation receipt first, if present; do not
   require a still-live preparation for a completed operation's reconciliation.
4. Only for a new operation, validate the live session-bound preparation,
   incarnation, expected generation, candidate identity and markup contract;
   revalidate the exact immutable CSS object from its safe descriptor.
5. Perform the final current-authority check, then publish the complete next
   control record and receipt atomically with required durability checks.
6. Publish/invalidate the in-process snapshot before acknowledging activation.

Write a complete bounded temporary record and verify its identity before
publication, including first initialization. Do not copy the direct initial
credential-file write in `operator_local._publish_private` into a concurrently
read selection record. A failure after replacement must never delete the
possibly published destination as though it were merely a temporary file.

A request that began before activation may finish using its original snapshot.
A fresh request after successful activation must resolve the new selection
without a process restart or a polling delay. Existing asset URLs stay valid.
Disk work and hashing must not block the shared ASGI event loop or create an
unbounded queue that can starve agent requests.

Two operators preparing against the same generation do not overwrite each
other: one activation wins, the other must review again. Every activation has
an operation ID bound to its exact intent. Replaying a retained receipt does
not reactivate an old stylesheet; status separates what that operation did
from what is selected now. Conflicting reuse is refused. Once an old receipt
has aged out, an uncertain request cannot become a fresh activation: expired
preparations and stale generation/incarnation checks require reconciliation.
Record no-op outcomes consistently too.
Every newly accepted operation advances the control generation, including a
no-op selection; a no-op leaves the previous-presentation reference unchanged.
Replaying a retained receipt is read-only and advances nothing. This prevents
a consumed no-op from becoming eligible again merely because its receipt was
later evicted.

Receipts retain enough non-secret binding data to compare a replay after its
preparation has been consumed or the application has restarted: operation ID,
preparation ID, candidate/digest, requested incarnation/generation, outcome,
resulting generation, time and deciding actor. A mismatch is a conflict.
Neither an operation ID nor a receipt grants authority.

`OperatorAuth` currently creates a new actor ID for each login, not a durable
per-human account. A newly authenticated operator can inspect recent operation
status without possessing the old session, while the recorded deciding actor
remains unchanged. This is the current single operator-authority model, not
approval for a future multi-user visibility rule. Read-only reconciliation
does not activate anything or transfer authorship of the old operation.

Do not report that nothing happened merely because the response or a
post-replacement durability step failed. Report an unknown outcome and
reobserve the exact operation/current state. No automatic new operation ID,
forced overwrite, service restart or database restore is a recovery strategy.

Reject a damaged candidate without disabling other verified candidates. A
catalog fault blocks external-candidate activation; an unreadable selection
record blocks all compare-and-set mutations. Expose a bounded operator-visible
fault rather than silently skipping invalid catalog data.

Use the packaged recovery stylesheet when the selected presentation cannot
safely be served, with an explicit **selected versus effective/degraded**
distinction; never rewrite the selection silently. If the selection record is
valid, an operator can still explicitly prepare/confirm trusted bundled
styling, or a verified compatible previous candidate, as applicable.

Provide a known safe-appearance recovery view that always uses packaged CSS,
even when a validly hashed but visually broken selected stylesheet hides the
normal controls. Its unauthenticated path uses the existing login flow with a
fixed bundled-style rendering mode, not weaker authentication or an arbitrary
return URL. The mode changes no persisted selection. Confirmation/recovery
forms still require current authority, CSRF and fresh password proof.
Login validation errors retain that safe mode, and successful safe-mode login
leads only to a fixed local recovery view rather than back to broken styling.

Anonymous login may show a generic presentation warning, not catalog, actor
or filesystem details. Only expected presentation faults enter this recovery
mode; do not catch arbitrary application errors or disguise a backend failure
as a styling problem. The bus and protected operator/local recovery paths
must not be taken down merely to repair styling.

This fault isolation does not relax normal rejection of unsafe deployment
configuration. Changing catalog/state paths, enabling the feature or changing
host permissions belongs to the bootstrap/configuration lane, not a stylesheet
activation. Existing application, credential, listener and SQLite startup
validation remains fail-closed.

A malformed/unreadable control record that cannot safely participate in
compare-and-set requires a protected local reconciliation path, not a
browser-provided force flag. That path changes only presentation state.
The bus's existing unknown/failed SQLite schema checks remain unchanged.
Reconstructing damaged state establishes a fresh incarnation so old
preparations cannot match a reused generation. Report prior operation history
as unavailable when it cannot be validated; never invent a receipt or silently
reattribute an old decision.

Bootstrap initializes selection state create-only under its existing approved
deployment authority. Repeated provisioning and later catalog staging must
not reset a valid operator selection or its generation/receipts.

No automatic CSS/catalog garbage collection is introduced. Enforce an
installation budget and refuse further staging when it is exhausted rather
than evicting an old page's assets unexpectedly. Recent operation receipts
have explicitly bounded retention; this does not change board or freeze-audit
retention. Backup automation and its seven-daily/four-weekly policy remain
unchanged.

## Approved limits and observable errors

These approved bounds are implemented; they are not measured production SLOs.
The current stylesheet is 11,074 bytes.

| Resource | Default / approved bound |
|---|---|
| Candidate CSS | 256 KiB, exactly one stylesheet per presentation descriptor |
| Descriptor | 8 KiB, strict versioned fields and duplicate-key rejection |
| Installed catalog | 256 entries / 256 KiB; no recursive directory discovery |
| Installed CSS objects | 64 MiB total; no automatic eviction in this slice |
| Selection record | 256 KiB with the latest 128 bounded operation receipts |
| Preparations | 16 globally, 2 per operator session, 300-second lifetime |
| Presentation file work | At most 2 concurrent verification/file jobs, including activation checks and fresh snapshots; separate bounded admission, no unbounded waiter queue |
| Selection-lock wait | At most 1 second; timeout is an explicit failure |
| Confirmation admission | Default 3/minute per session and source, 6/minute globally, in a dedicated presentation family; bounded configuration ranges are documented in DEPLOYMENT.md |
| Confirmation input/KDF | Existing form/password byte bounds and bounded KDF workers; no remembered reauthentication window |

Expose typed failures for invalid input, unknown candidate, incompatible
contract, expired/superseded preparation, current-auth failure, capacity,
unavailable storage and unknown activation outcome. Map them through the
existing safe operator error conventions; do not disclose secrets, raw
password-bearing forms, unsafe filenames or arbitrary exception text.
An unreadable catalog is **not** "no updates available."
Cancellation or an HTTP timeout must not release a still-running worker's
capacity slot or imply that a publication was cancelled. Prefer authenticated
status reads over repeated password-bearing POSTs to reconcile an uncertain
result. Configured bounds must remain finite and validated.

## Whole-console redesign brief

The owner confirmed the whole current console as the redesign scope. Develop
its information architecture and visual direction alongside this delivery
boundary, but review them separately before implementation.

- Make board/activity/channel/roster browsing clear and distinguish it from
  administrative actions. Navigation visibility is never authorization.
- Keep frozen, unavailable, empty and stale states visibly distinct.
- Make dangerous actions, their actual scope and fresh confirmation legible.
- Use consistent components, alignment, spacing, responsive layouts, keyboard
  navigation, visible focus and reduced-motion behaviour.
- Show application and presentation versions without filling every page with
  deployment machinery.
- Use isolated previews with synthetic data for rapid feedback. Do not use
  the live bus as the first visual or interaction test environment.

No palette, frontend framework or final wireframe is approved by this note.
New human member/admin accounts remain M2 work. New interaction capabilities,
server-rendered copy/markup changes and CSP changes need their own reviewed
application slices, even when motivated by the redesign.

## Required implementation evidence

These are the approved acceptance requirements. The local evidence below
identifies what was exercised and which platform/production gates remain.

| Case | Required assertion |
|---|---|
| Initial bootstrap | Existing UI remains usable; legacy CSS URL returns original bytes; disabled/unconfigured external presentation support is explicit |
| Prepare/review/preview | No live selection change; candidate preview has no live forms or bus data; confirmation retains current trusted styling |
| Successful activation | New HTML uses the verified new digest URL and reports its presentation identity; application/release/schema identity is unchanged |
| No update-induced outage | One existing SSE connection remains open without a reconnecting client wrapper; 100 correlated agent operations span activation within configured rate/lifetime bounds with zero unexpected failures or missing/extra messages |
| Visible result | Browser computed styles demonstrate the intended small CSS change, not merely a new filename; relevant controls remain legible, operable and aligned |
| Existing pages | Old immutable URLs keep their old bytes after activation and restoration; concurrent responses never mix presentation snapshots |
| Authority | Missing/expired sessions, bad CSRF/origin, wrong password and non-operator credentials fail without selection change; logout-before-final-check denies, while an already-authorized publication follows the documented unknown-outcome rules |
| Frozen system | Operator controls and CSS remain usable; agent denials continue; no freeze, access-restoration or audit-state change results from activation |
| Concurrency/retry | One generation winner; stale and conflicting operations refuse; lost responses reconcile without overwriting a newer selection |
| Receipt lifetime | A consumed/expired preparation does not hide a retained completed receipt; accepted no-ops advance generation without replacing the previous reference; replay/conflict/eviction cannot silently become a new activation |
| Snapshot/local recovery | Coordinated readers see a complete generation; a fresh render observes protected local reconciliation; Windows sharing failures cannot become partial publication or event-loop blocking |
| Filesystem failures | Partial staging, wrong hashes/sizes, duplicate/unsafe members, symlink/hardlink substitution, torn records, permission errors and lock timeouts fail explicitly |
| Unknown outcome | Failure around replacement/durability acknowledgement does not imply no change; status truthfully identifies observed selection and operation |
| Fault isolation | Bad presentation state blocks activation and exposes degraded recovery styling without restarting the bus or concealing the fault |
| Safe appearance | A visually broken but correctly hashed candidate cannot hide the bundled-style login/recovery route; entering that view grants no authority and makes no persistent selection change |
| Limits | Exact byte/count/lifetime boundaries and one-over cases; queued/cancelled work cannot exceed the worker/KDF limits |
| No extra privilege | Website cannot write staged assets/source or invoke host commands, migrations, dependency installers or arbitrary URL acquisition |
| Packaging/staging | Verified wheel members and catalog agree; presentation staging touches only permitted presentation paths and triggers no restart handlers |
| Staging scope | No candidate imports/entrypoints or full release-role execution; an unsupported source-release format is refused rather than weakening its validator |
| Compatibility | Unsupported markup contract is refused; later backend-contract changes require an application update plan, not an asset-only label |
| Recovery | Previous and bundled selections remain operator-confirmed and compatible; no database rollback or unsafe file deletion |
| Platform honesty | Python 3.12/3.13 behaviour plus Linux ownership, durability, confinement and trusted-TLS browser/host qualification before production claims |

The no-outage fixture is not a production load/latency certification. Keep it
within the existing SSE lifetime and request limits; distinguish natural expiry
and deliberate containment from update-induced interruption. Preserve real
authority/stream behaviour instead of masking reconnection in a mock.

## Ownership, quality and stopping gate

Implementation/integration owner: this Copilot CLI session for B1, with bounded
core, B2 rendering and B4 staging assignments under the owner's authorization.
No cross-repository implementation or factory run is implied.

| Surface | Expected change |
|---|---|
| New cohesive presentation module | Catalog/object verification, request snapshots, preparation and atomic selection/recovery contract |
| `dashboard.py`, `operator_web.py` and thin presentation routes | Consistent stylesheet references, version/fault display and operator workflow; reuse current rendering/auth patterns |
| `api.py`, `app.py`, `config.py` | Strict asset admission/serving, per-application wiring and bounded configuration |
| `operator_auth.py` | Preserve fresh-proof semantics while adding a dedicated presentation confirmation budget |
| Packaged CSS/descriptor and `pyproject.toml` package-data settings | Immutable wheel-contained presentation resources; no speculative dependency |
| Existing release/Ansible validators and a narrow staging entry point | Verify and install only approved presentation objects; preserve helper checksums, non-writable source and the five-asset release contract |
| Focused browser/service/filesystem/staging tests and documentation | Demonstrate the single outcome and preserve current behaviour |

Do not move asset lifecycle or filesystem logic into the already large request
middleware. Its measured complexity is C=115, and `create_app` is C=18 before
this slice. Any material changes still use whole-function coverage/CRAP
denominators and need meaningful simplification or explicit scoped review/
exception evidence. M1's cleanup exception does **not** apply here.

**G1 reviewed** artifact/catalog trust, the selection-only website authority,
fresh-password and rate-budget changes, markup compatibility, request/cache
consistency, atomic state/receipt retention, fault/recovery semantics, limits,
file ownership and the acceptance matrix. The protected local recovery path
must remain sufficient; no requirement is waived merely to accelerate feedback.

G1 approval and separate implementation authorization are recorded in
`DESIGN.md` section 14, preserving all preceding content. The bootstrap is a separately qualified, approved
application deployment and may require a restart; only subsequent compatible
presentation activations use the no-restart path.

**Original design-only change:** this document. The subsequently authorized
local implementation and its file inventory are recorded below. The existing
M0/P0/M1 reports and artifacts remain intact. Automatic acquisition, repository
publication, backend updating and the full visual redesign remain separate work.

## G1 readiness review evidence

The local review rechecked the existing operator-session locks and response
guards, initial/replacement file-publication helper, release-role action guards
and fixed-schema offline validation. It resolved four readiness gaps:

- Define logout/publication ordering honestly without blocking the shared
  event loop on a global authentication lock.
- Reconcile retained receipts independently of expired/consumed preparation
  tickets and preserve the original per-login deciding identity.
- Require coordinated authoritative snapshots, including local recovery and
  Windows reader-sharing behaviour, rather than relying on an in-process cache.
- Keep CSS staging separate from the full release role and preserve existing
  source-release validation instead of bypassing it for a compatible CSS label.

An isolated standard-library file probe ran on Windows with CPython **3.13.15**
and **3.12.14**, using the existing portable backup-directory lock primitive
only inside private disposable probe directories. On both interpreters:

| Probe | Observed result |
|---|---|
| Replace a record while an ordinary Python reader holds it open | Refused with `PermissionError` / Windows error 5; the original record stayed complete |
| Coordinate the reader and writer through the existing lock primitive | Reader retained generation 1; after it closed and released the lock, the writer published generation 2 |
| Two independent writers compare against generation 2 | Exactly one accepted generation 3; the other explicitly reported superseded |

The probe did **not** implement application selection, authenticate an operator,
exercise SSE/browser behaviour, establish Linux ownership/directory-fsync
guarantees or prove power-loss durability. It is evidence about usable local
primitives and a portability constraint, not the final no-outage demonstration.
No dependencies were installed; disposable probe directories/processes were
cleaned up.

Reproduction and evidence are session artifacts:

```powershell
uv run --locked python 'C:\Users\DevUser\.copilot\session-state\cbe2d0fd-0ce6-4bc9-a341-89c0fd8b7f4a\files\presentation_g1_file_probe.py' --output 'C:\Users\DevUser\.copilot\session-state\cbe2d0fd-0ce6-4bc9-a341-89c0fd8b7f4a\files\presentation-g1-file-probe-313.json'
```

The adjacent `presentation-g1-file-probe-312.json` and
`presentation-g1-file-probe-313.json` include interpreter versions, outcomes
and the fixture SHA-256. The Python 3.12 run used the already-existing isolated
M1 test environment.

Only this proposal was revised in the checkout during the readiness review.
The owner subsequently approved the reviewed contract and separately
authorized local implementation. The approved decision is appended to
`DESIGN.md` section 14. That implementation decision did not itself approve a
quality exception, CI change, publication, repository move or production
action. The later, separate scoped quality decision is recorded below.

## Local implementation and outcome

The approved slice is implemented with external presentation selection
**disabled by default**. It includes strict wheel/catalog/CSS verification,
bounded independent filesystem workers, coordinated atomic selector/receipt
publication, per-request rendering snapshots, operator HTML controls, inert
preview, fresh-password activation, status reconciliation and bundled recovery.
The protected local selector CLI pins setup and permanently drops to the
service identity before selector writes. No bus migration or new dependency
was added.

The complete safe flow preserves the exact `appearance=bundled` query through
prepare, review, confirmation and operation status. The fixed recovery entry
also accepts a single preparation or operation ID for reconciliation. A
correctly hashed stylesheet that hides every normal control was exercised
through this recovery flow; no authority bypass or persisted mode change is
used.

The original served CSS is exactly **11,074 bytes**, without outer newlines:
the previous Python literal used `.strip()`. Its SHA-256 remains
`7388d6a6d7d059f9808c6a731982c1911a7e6b468d60145f153c6315a8a9205c`.
The packaged resource, scoped Git newline attribute and legacy immutable URL
preserve those exact bytes.

Staging uses independently supplied release pins and explicit qualified,
authenticated immutable-acquisition assertions, then the existing full
release-envelope validator. It extracts only the two fixed wheel members.
`deploy\playbooks\presentation_stage.yml` invokes a reviewed **already
installed** bootstrap stager and publishes data only; it does not configure
the service, initialize its selector or execute candidate Python.
See staging and bootstrap prerequisites (removed PRESENTATION_STAGING.md) and
[optional deployment configuration](../DEPLOYMENT.md#presentation-only-updates-development-bootstrap-contract).

### Demonstrated continuity and visible effect

`tests\test_presentation_live.py` used a real loopback TLS listener, explicit
certificate trust and hostname verification. It completed the normal agent
identity proof and actual operator login/prepare/password-confirm/activate
HTTP flow. There was no reconnecting SSE wrapper or bypass of production
authentication checks.

| Assertion | Observed local result |
|---|---|
| Raw stream | One GET/open SSE connection across activation |
| Correlation | 100 REST posts, 100 matching stream events and 100 matching stored messages; sequences 1-100 |
| Concurrent work | Four agent requests overlapped the activation request in the recorded Python 3.13 run |
| Unexpected failure/loss/duplication | Zero |
| Runtime identity | Same process, package 0.2.26, development release identity and schema 16 |
| Containment | Freeze state unchanged |
| Assets | New full-digest CSS bytes served; old immutable URL retained its original bytes |
| Python compatibility | Real TLS continuity also passed on Python 3.12 |

The synthetic candidate appended a visible blue button outline to the
original CSS. Separate **Edge 153.0.4234.32** rendering of captured synthetic
HTML/CSS measured the change from no outline to a solid 3px
`rgb(42, 110, 240)` outline at 1440px and 390px viewports. Controls remained
visible, enabled, inside the horizontal viewport and keyboard-focusable; screenshots and
computed geometry are retained.

This browser check was an explicitly read-only rendering fixture, not a claim
that a browser submitted the real TLS activation. Playwright's configured
Chrome was unavailable, so existing Edge was driven through its local
debugging protocol with Node's standard library and a disposable profile.
No browser installation, system trust-store change, ignored certificate error
or TLS-verification bypass was used. Fixture servers, browser processes and
profiles were cleaned up.

### Validation and scoped quality decision

The locked sync, build, wheel/sdist validation, unchanged production-lock
check, clean installed-wheel check and static deployment contract passed.
The final branch-instrumented complete suite recorded **2,859 passed,
468 skipped and one failed**, in 678.69 seconds. The sole failure remains
`test_ca_anchor.py::test_redemption_recipes_quote_url_and_generate_valid_json[linux]`:
the same Windows System32 Bash failure recorded in M0 and M1. It was not
suppressed or fixed as part of this slice.

The ordinary complete `uv run pytest` gate ran before the final 22 extra
failure-path cases: 2,837 passed, 468 skipped and that same one failure.
All final cases were included in the complete instrumented run. Separate
Python 3.12 runs covered core/local recovery (139 passed, one host skip),
staging/release validation (140 passed), console/parent integration/live TLS
(168 passed), and the final parent failure paths (67 passed). These selections
overlap and are not presented as an additive test count.

All **212 new/changed whole functions** have at least 90% branch-exit coverage
or the documented branchless statement fallback; 211 meet all score targets.
The owner selected `approve-scoped-exception` for:

| Exception | Function | C | Branch coverage | Adapted CRAP |
|---|---|---|---|---|
| PRESENTATION-admission-01 | `api.py::RequestBodyLimitMiddleware.__call__` | 115, unchanged | 91.23% (104/114) | 123.93 |
| M0 comparison | Same existing function | 115 | 89.47% (102/114) | 130.42 |

The exception covers only the existing middleware's complexity/CRAP debt for
the strict asset-classifier and safe-login-destination call changes. It must
be re-reviewed at the next semantic change to that function **and before
production qualification**. It waives no authorization, containment, coverage,
body/rate limit, failure-path or platform requirement. M1-cleanup-01 remains
separate and unchanged.

The baseline reporter still exits 2 for eight unchanged globally unscorable
entries; this is not represented as a passing repository-wide quality gate.
Every function selected for this slice is measured explicitly. Evidence is
under `.metrics\presentation-2026-09-17\final`, with live and visual evidence
in adjacent `live-final` and `visual` directories. The session's
`presentation_final_evidence.py` consolidates exact function identities,
coverage and preservation fingerprints into `changed-quality.json` and
`implementation-files.json`.

After the complete coverage run, the separately executed live fixture was
tightened to read actual SQLite `user_version` before and after activation.
It passed again on both Python versions. No application source changed after
coverage collection; the original run snapshot is retained rather than
rewritten to hide that test-only refinement.

Final local package hashes (version 0.2.26, **not published**):

| Artifact | SHA-256 |
|---|---|
| `strugglebus-0.2.26-py3-none-any.whl` | `9c142120ea940ce33587afa420415ff41e5015268c42feb54021d9562c66dc2e` |
| `strugglebus-0.2.26.tar.gz` | `1db26c3a400dd279a20a835e290aaa49aabbb38a94c28039058355058e676850` |

Linux ownership, directory durability, confinement, supported-host Ansible
execution and an actual trusted-TLS browser/host qualification remain
outstanding. Running `deploy\validate.py` on this Windows host stops at the
POSIX-only `grp` import; no substitute was installed to manufacture a pass.
The initial production bootstrap, publication and rollout still require
separate qualification and owner approval.

### Changed-file summary

This implementation changes **19 existing files and adds 22 files**. Of the
316 files present before G1 review, the other 297 remain byte-for-byte
unchanged. The complete preceding `DESIGN.md` and `DEPLOYMENT.md` content is
preserved; their new sections are appended. Existing README, M0/P0/M1 design
and evidence records, `uv.lock`, `requirements.lock` and CI workflows remain
unchanged.

| Area | Changes |
|---|---|
| Core/data | New presentation types, safe file/state operations, service, local recovery and protected stager |
| Web | New presentation routes and ASGI integration; consistent dashboard/operator rendering; two existing admission call sites |
| Configuration/auth | Bounded optional settings, dedicated fresh-confirmation budget and cohesive configuration validators |
| Packaging/staging | Exact CSS/descriptor wheel resources, scoped newline attribute, trusted extraction script and data-only Ansible entry point |
| Bootstrap contracts | Optional systemd settings/validation, example inventory and offline deployment-contract coverage |
| Tests/docs | Core, files, authority, rendering, staging and actual TLS/SSE regression coverage; approved architecture, deployment and staging documentation |

No commit, push, release publication, repository move, CI workflow edit,
production mutation, automatic acquisition or full visual redesign was made.
