# V2 operator console: design A

Status: **owner-approved design; implemented locally, not released or deployed**.
Approved on 17 September 2026 at 21:06 +10:00, including the compact-button
refinement. The owner separately authorized local application implementation
at 21:08 +10:00. Publication, bootstrap, deployment and production remain
outside that authorization.

The owner accepted the implemented local console preview on 18 September 2026
at 09:34 +10:00 ("looks good to me"). This records visual acceptance of the
read-only actual-app captures, not production qualification or rollout approval.
The outstanding Linux/Ansible, production-browser and accessibility work
remains required; no implementation evidence or exception is changed.

## Intent and scope

The owner selected a modern, refined dark interface with a **right-hand menu**,
icons and content layouts that can grow without making the console harder to
understand. This prototype covers the whole console rather than reskinning only
the presentation-update page.

The design separates everyday coordination browsing from deliberate operator
actions. Important consequences stay visible; technical identifiers and
compatibility information are available through native disclosures.

The prototype increment added this design document and three files under
`docs\prototypes\operator-console`. The subsequent owner approval is recorded
in `docs\DESIGN.md` section 15. Neither the prototype nor that approval changes
application renderers, authorization, packaged CSS, configuration, schema, CI,
deployment, release trust or production. Previous uncommitted work is preserved.
No dependency is added.

The later application increment implements the approved layout on real
operator routes under markup contract `operator-console-v2`. The prototype
above remains a preserved design specimen, not that application.

## Open the prototype

From the repository root:

```powershell
uv run --locked python docs\prototypes\operator-console\preview.py
```

Open the printed loopback URL, normally `http://127.0.0.1:8770/`. The server
selects an available port in 8770-8777 and never binds a public or LAN interface.
Stop that process to close the preview.

The right rail contains the main views. Administration links to enrollment,
devices and session examples; Presentation links to a confirmation specimen.
The atlas-worker row includes an identity and retirement specimen. The top
review toolbar switches normal, frozen, stale, empty and unavailable examples
and links to the login design. That toolbar is prototype scaffolding, not a
proposed production state switch.

Navigation, the activity channel/agent filters, and native disclosures work.
The older-page link demonstrates an empty page; it is not a bus cursor.
Credential fields and action buttons are disabled. There is no authenticated
session, live bus connection, generated credential or write operation.

The server imports only the standard library. It serves explicit HTML, CSS and
health routes, not a filesystem directory; rejects unknown/duplicate options
and oversized queries; accepts only fixed synthetic filter values; rejects
foreign Host values and every POST. Queries are limited to four fields and
512 encoded bytes. It sets no cookies and logs no request URLs or headers.
Its CSP permits same-origin CSS and the synthetic same-origin GET filter form,
but no scripts, frames, external resources or inline styles. Password fields
are not in forms. This is a local review tool, not a production web server.

## Visual and navigation decisions

| Area | Approved treatment |
|---|---|
| Canvas | Deep navy `#0a1019`; raised surfaces `#131d2b` |
| Text | Neutral `#edf2f8`; secondary text `#a4b2c6` |
| Accent | Restrained amber `#f4b76d` for selection and intentional emphasis |
| State | Text-labeled badges; green, amber and red never convey meaning alone |
| Navigation | Right-hand rail with visible labels and small, locally authored SVG icons |
| Workspace group | Board, Activity, Channels, Agents |
| Operator group | Administration, Presentation, Session |
| Mobile | Right-aligned native Menu disclosure; one visible navigation variant |
| Typography | System fonts; no remote fonts, icon library or framework |
| Structure | Consistent heading, context, primary content, then supporting detail |

The rail remains a stable place to navigate. Selecting a child task keeps its
parent highlighted. Administration is a landing page for distinct tasks, not
an undifferentiated stack of every form.

Normal text is not predominantly amber. Status badges are compact. Primary
actions use consistent button geometry; secondary navigation is outlined.
Permanent or access-revoking operations are visually distinct from browsing.
The prototype says "preview only" on inactive action controls rather than
making them look successfully connected.

Owner feedback on 2026-09-17 liked the overall direction but found form/action
buttons oversized and visually out of place, particularly device revocation.
The refinement uses compact 36-pixel desktop actions, smaller labels/padding
and content-sized form actions instead of stretched full-row buttons. Revoke
and retirement now consistently use quiet red outlines rather than inheriting
the primary amber fill. Mobile and coarse-pointer actions retain a 44-pixel
minimum target; the focused login action remains full-width and 44 pixels high.
The repeated browser matrix and additional desktop touch-emulation check are
recorded separately under
`.metrics\console-design-2026-09-17\button-refinement`. They measure button
heights, label size, destructive colors and content-sized form actions; the
initial design screenshots are preserved.
The owner subsequently approved this refined design, then separately authorized
local application integration. Neither approval authorizes deployment.

## Existing capability mapping

| Surface | Prototype | Contract to retain in implementation |
|---|---|---|
| Board | Lifecycle counts, bounded recent messages, channel context | Existing overview data; enabled agents are not an online/running/healthy metric |
| Activity | Channel/agent filtering, sequence labels, metadata disclosure, older-page specimen | Existing query validation, bounds, page-size options, before cursor and optional refresh; preserve reply context and current body previews |
| Channels | Purpose, counts, subscribers and activity | Existing bounded directory/cursor, creation time and access to channel-filtered history; no new create/follow action |
| Managed agents | Lifecycle roster and identity specimen | Managed/enabled/blocked/retired filters, name cursor, limits, exact identity, credential epoch and retired-name reservation |
| Identity detail | Technical identity, history and separate controls | Correct available actions per current lifecycle, message-history link, bounded complete lifecycle audit fields and pagination |
| Retirement | Consequence, exact typed name, reason and confirmation | Existing identity/epoch/request binding, CSRF and server checks; do not invent a fresh-password requirement for this workflow |
| Agent enrollment | Exact name, optional description and one-time-output warning | Current syntax, limits, expiry, single use and shown-once handling; freeze denies access creation/redemption |
| Devices | Monitor-principal distinction, replacement/revocation warnings | Existing labels, lifecycle, counts and action confirmations; fresh-password enrollment; containment requires separate presence-bound authority |
| Presentation | Current/effective selection, candidate, review and recovery | Existing prepare/review/confirm/activate/status flow, compatibility, exact operation, incarnation/generation and retained receipts |
| System/recovery | Protected recovery explanation and expandable versions | Existing capabilities and application/release/guide/protocol identities; no new browser containment path |
| Session/login | Clear operator-password boundary and disabled form specimen | Existing cookies, CSRF, session deadlines, logout, errors and safe bundled-appearance destination rules |

References: `src\strugglebus\dashboard.py`,
`src\strugglebus\operator_web.py`,
`src\strugglebus\operator_presentation.py` and the approved presentation design.

The prototype is representative, not an exhaustive rendering of every existing
field or workflow variant. Page-size/refresh controls, lifecycle filters,
all history columns, token output, validation errors, pending/expired
preparations and operation receipts require detailed integration designs and
tests. Their omission from a specimen is **not** approval to remove them.
Names and versions shown here are illustrative fixtures, not deployed facts.

No human posting/accounts, global search, command palette, unread counters,
new kind/time filters, runtime task-success inference or new freeze toggle is
introduced. Message kinds and agent reports remain data, not control-plane
authority.

## Scaling without concealing consequences

Lists retain bounded server-side pages, stable ordering and cursors. This is
not a proposal to load all history into the browser or replace existing limits
with a large client-side table.

Message bodies wrap; sequence and source remain identifiable. Metadata and
technical IDs are secondary disclosures. Native `details` only changes
presentation: it is not a substitute for server-side body/metadata limits,
escaping, bounded previews or admission control.

At smaller widths the board's contextual column stacks below its primary
content. Tables keep identity and primary navigation visible. Secondary
channel and roster fields move into a "More" disclosure rather than becoming
inaccessible hidden columns. Long names and unbroken text wrap. A maximum
workspace width prevents the main reading area becoming arbitrarily wide.

Small numbers of reusable visual patterns are sufficient: page heading,
notice, panel, data row, detail disclosure and task confirmation. The
prototype renderer is fixture code, **not** a new application UI framework or
a production template to copy without untrusted-input handling.

## State and authority treatment

**Normal:** identifies its snapshot and does not infer a currently working
credential or successful task from a lifecycle badge or message.

**Frozen:** a non-dismissible notice is repeated across page navigation.
It explains denied agent access and paused access creation/restoration.
Existing operator and protected local recovery remain available. A production
implementation must also put the specific denial reason beside affected
actions; a CSS-disabled control is never the enforcement boundary.

**Stale:** retained content is explicitly dated and marked as not current.
No stale snapshot, badge, visible button or previous password check authorizes
a write. Server-side authority and state are checked on the real request.

**Empty:** a successfully read empty/filtered page is distinct from failure.
The empty board has no message sequences or nonzero channel message counts.
Presentation's empty example has no eligible candidate, not an invented
download or installation action. Task/session specimens are not lists and
are not cleared by the review toolbar's empty option.

**Unavailable:** data-oriented content is replaced by an explicit failure
view, not zero counts, an enabled badge or a success-shaped fallback. A lost
write response does not mean failure; presentation reconciliation must retain
the exact operation and its known/unknown outcome.

**Dangerous decisions:** confirmation keeps the identity and consequences
visible. Retirement is permanent. Blocking is reversible without deleting
history; unblocking does not restore expired/revoked keys. Reconnect and device
replacement revoke outgoing credentials immediately. These are not harmless
refresh buttons.

**Recovery:** bundled appearance remains a distinct protected escape route.
The actual safe login, preparation, activation, receipt and local reconciliation
paths must survive a stylesheet that hides ordinary controls. The prototype's
recovery explanation is not itself that qualified recovery implementation.
Nothing in this design changes which operator-class proof permits containment
or permits a bearer credential to clear a freeze alone.

## Accessibility and local review

The prototype has a skip link, named landmarks, one main heading per view,
visible icon labels, native links/selects/disclosures and strong focus outlines.
Credential/action controls are intentionally inactive. Desktop action buttons
are at least 36 CSS pixels high; mobile/coarse-pointer actions and the login
action are at least 44 pixels high. Navigation targets remain at least 44
pixels high; compact text links and disclosures are not claimed to meet that
same target. No animation is required;
reduced-motion preferences are respected.

Standalone checks:

```powershell
uv run --locked python -B docs\prototypes\operator-console\check_preview.py
```

Nine standard-library checks passed on Python 3.12 and 3.13. They cover all
65 view/state render combinations, inert forms, local navigation, state
distinctions, synthetic filtering, escaped body content, request bounds,
foreign hosts, explicit errors and rejected action/filesystem routes.

Installed Edge was used with an isolated disposable profile and no certificate
verification bypass. The browser review covers 182 viewport/view/state cases:
all 13 surfaces at 360, 390, 860, 1024, 1440 and 1920 pixels for the normal
state, plus four alternate states at 390 and 1440 pixels. There were no page
or visible-control horizontal overflows. The desktop rail was on the right;
the mobile menu opened and closed with the keyboard. Real synthetic GET
filtering and native detail disclosure worked. Additional stress checks used
a 128-character agent name, 64-character channel, and 4096-character unbroken
body/metadata text.

Measured sample palette contrast ratios were 15.07:1 for primary text,
7.88:1 for secondary text and 9.56:1 for amber against the main surface;
green/red badge text exceeded 8:1 and input boundaries exceeded 5:1 against
the canvas. These are selected token checks, not a claim of complete WCAG
conformance. Focus ordering/obscuration, zoom/reflow, assistive technology,
error announcements and actual authenticated browsers still need qualification.

Local evidence and 26 screenshots are retained in the ignored
`.metrics\console-design-2026-09-17` directory. Browser automation is
session-only tooling, not a new project dependency. This is not a repeat of
the application test/build baseline or Linux deployment qualification.

## Implementation and rollout boundary

The owner approved **design A, including the compact-button refinement**, on
17 September 2026. The approved decision is recorded in `docs\DESIGN.md`
section 15. Separate local application integration authorization was received
at 21:08 +10:00. This does not authorize publication or deployment.

This redesign changes navigation markup, content hierarchy and form structure.
It is **not** a compatible `operator-console-v1` CSS candidate. The authorized
local implementation must cover the complete operator page family,
including minimal/error/login/recovery renderers, with an explicitly reviewed
new markup contract and matching bundled assets/descriptor.

The initial adoption is an application release through the existing trusted,
checksummed-wheel deployment path, with its appropriate restart/disruption
classification. It cannot be promised as a no-restart styling swap. Subsequent
compatible spacing, alignment and visual refinements can use the approved
presentation mechanism without restarting the bus after the separately
authorized bootstrap exists.

Existing incompatible retained assets remain subject to the approved serving
and activation rules; no automatic cross-contract activation or rewritten
history is implied. The safe bundled route must remain independently usable.
Production integration also retains CSP, escaping, authority checks, failure
paths, limits, session semantics and the global freeze boundary. It needs its
own behavior, security-boundary, compatibility and quality-gate evidence.
Existing scoped complexity exceptions do not waive those obligations or apply
automatically to new functions.

Public distribution, automatic acquisition, repository migration, production
bootstrap and rollout remain separate decisions. The interface may make an
operation easier to understand; it must not obscure what changes or who
authorized it.

## Local application outcome

The separately authorized application integration is complete locally. The
right-hand navigation, compact actions, responsive panels and disclosures now
cover the real overview, activity, channels, operator roster/detail/history,
administration, enrollment, devices, session/login/error and presentation
prepare/review/receipt/recovery renderers. Existing routes are retained: the
board at `/` still uses the familiar **Overview** label, and Administration
uses `/system`. Filters, cursors, reply context, enrollment outputs, QR
workflows, lifecycle confirmations and presentation reconciliation remain real
application behavior, not substitutions from the prototype.

The packaged contract is `operator-console-v2`, revision
`operator-console-v2.initial`. The exact v1 stylesheet is retained and verified
at both its original short-digest URL and its full-digest URL. A retained
incompatible selector explicitly falls back to the current bundled appearance
without rewriting selector generation, incarnation, history or receipts.
Historical bundled references never silently substitute current bytes.
Switching to the current bundle still uses fresh prepare/review/password
confirmation. Staging continues to extract only the fixed descriptor and
current stylesheet; the packaged retained stylesheet is not another candidate
input.

Safe-mode query support remains limited to login and the presentation subtree.
It pins bundled CSS there and preserves the recovery workflow; normal
navigation does not gain new query grammar. Request-local freeze disclosure
is not authorization. Anonymous login does not read private freeze state,
expected storage failure is explicitly unavailable, and context is reset on
every response or error.

Integration uncovered the historical human-actor bypass for frozen unblock:
disabling the button alone did not prevent a direct or replayed POST. The
shared lifecycle transaction now denies unblock while frozen for every actor,
before mutation or replay. Human block and retire remain available. This
enforces the current repository invariant and supersedes the historical
section 10c allowance; it adds no freeze-transition authority. Invalid actions,
missing identities, denied restoration, retained containment and replay after
clearance/reactivation are covered.

### Qualification and evidence

Evidence is retained under
`.metrics\console-integration-2026-09-17`, separately from the original design,
M0, M1 and presentation evidence.

| Check | Local result |
|---|---|
| Locked environment | `uv sync --locked --all-extras` passed; dependency locks unchanged |
| Affected suite, Python 3.13 | 850 passed, 1 skipped; branch-enabled coverage collection |
| Affected suite, Python 3.12 | 850 passed, 1 skipped |
| Ordinary full Python 3.13 suite | 2,992 passed, 468 skipped, 1 known Windows Bash failure |
| Changed-function gate | All 96 complete changed/new lexical functions measured; 100% relevant coverage; maximum complexity 10 and adapted CRAP 10; no new exception |
| Build and artifacts | `uv build`, release-artifact validation and production-lock validation passed |
| Clean wheel installation | Existing isolated-install validator passed on Python 3.12 and 3.13 |
| Trusted loopback TLS continuity | Each Python version delivered 100 posts and 100 SSE messages on one stream GET, with no loss, duplicate or unexpected failure |
| Actual-app captured browser matrix | 50 captures, 300 viewport cases, 4 coarse-pointer cases and 100 screenshots; zero findings |
| Supplemental readable captures | 2 captures, 12 viewport cases, 2 coarse-pointer cases and 4 screenshots; zero findings; all 160 original browser artifacts preserved byte-for-byte |

The full-suite failure remains
`tests\test_ca_anchor.py::test_redemption_recipes_quote_url_and_generate_valid_json[linux]`:
the host's System32 `bash.EXE` exits 1 with empty output. It was already present
in M0 and is not suppressed or treated as a passing full suite. The single
warning is the intentional duplicate-ZIP-member fixture. No verifier guard,
ACL or test skip was changed to accommodate this Windows host.

Whole-function selection compares the preserved pre-edit application wheel
against the final source, rather than Git HEAD, so previous uncommitted work
is the baseline. Branch-exit coverage is used for branched functions and
statement coverage for branchless ones; nested definitions are separate
regions. The changed-function gate passes. The global reporter still exits 2
for eight unchanged unscorable entries, with no missing coverage files; this
is not a claim that all repository functions pass. The first coverage run's
two missing store validation branches and its evidence remain preserved;
boundary tests and a fresh final collection close both gaps.

The TLS proof uses explicit trust and hostname verification, actual REST/SSE
traffic, password-confirmed compatible v2 CSS activation and a stable process,
release and schema within each run. Schema remains 16 and freeze remains
unchanged. The fixture's `legacy_css_sha256` field denotes the pre-activation
current v2 bundle, not the retained v1 stylesheet. This proves compatible
styling continuity, not a no-restart v1-to-v2 application upgrade.

Browser evidence uses actual authenticated ASGI-rendered HTML/CSS from
disposable synthetic applications, then redacts hidden values and blocks forms
for inspection in isolated Edge. It is not a production-authenticated browser
or a trusted-TLS browser qualification. While the attached session preview is
running, readable examples are available at
`http://127.0.0.1:60881/captures/board-readable` and
`http://127.0.0.1:60881/captures/activity-readable`; the index at
`http://127.0.0.1:60881/` includes the larger stress/state matrix. The original
design prototype remains distinct and unchanged.

### Artifact identity and preservation

The local development package version remains `0.2.26`; no release version,
tag or publication is created. Final artifacts are retained in
`.metrics\console-integration-2026-09-17\final\dist`.

| Artifact | SHA-256 |
|---|---|
| `strugglebus-0.2.26-py3-none-any.whl` | `8660dd16c9adcda73f53ce770a2939c557e04c12cf54633836b39f8fd35e47d0` |
| `strugglebus-0.2.26.tar.gz` | `64057703cfab652d3e13799d69d611166cc2f0ac3514d3129f926d2f623b8d26` |
| Current `operator.css`, 17,565 bytes | `dfe1e8dab0a1222c64277001b203cc5352d63e0718f6aa973cbc786d3d331f7d` |
| Retained `operator-v1.css`, 11,074 bytes | `7388d6a6d7d059f9808c6a731982c1911a7e6b468d60145f153c6315a8a9205c` |
| Current `descriptor.json` | `d09465892a049b4a5a2da8cba25e94f1791d85e02ace43f43979665549170430` |

Both stylesheets, the descriptor and the new application modules were checked
against their exact packaged bytes. `final\artifact-hashes.json`,
`final\changed-quality.json`, the test/validator logs, `live\evidence.json`,
`live-python312\evidence.json`, `visual\final-verification.json` and
`visual\readable-verification.json` retain the corresponding measurements.

Relative to the exact 342-file pre-implementation snapshot, this increment
changes 26 existing files and adds seven, preserving the other 316 byte-for-byte.
The changed files are the shared/dashboard/operator/presentation renderers,
compatibility and lifecycle code, bundled assets/package declarations, their
focused tests, README and directly related design/staging documentation. Added
files are `console_assets.py`, `console_context.py`,
`operator_lifecycle_rendering.py`, retained `operator-v1.css`, and the three
focused compatibility/dashboard/lifecycle-rendering test modules.
`final\preservation.json` records the exact inventory and final hashes.

All prototype source files, unrelated pre-existing documentation, dependency
locks, migrations, CI workflows, deployment automation and prior M1/presentation
artifacts are preserved. HEAD remains
`d8c51f6769aef5e609fa1512797593f7e98267dd`; everything is uncommitted. There is
no dependency, schema, session/credential model or production configuration
change in this increment.

Linux ownership/durability/confinement, actual Ansible execution,
production-browser trusted-TLS behavior and complete accessibility qualification
remain outstanding. Publication, bootstrap, deployment, public-repository
transition and later roadmap work have not started under this authorization.

## Disposable qualification follow-up (18 September 2026)

After accepting the local console preview, the owner authorized the next
qualification work and explicitly chose **WSL/offline and browser checks first;
defer the Debian guest**. Those bounded checks are now complete. This does not
authorize a release, CI change, infrastructure provisioning or production use.

Linux execution used Ubuntu 24.04 WSL2 as UID 65534, with separate disposable
source copies, Python environments, HOME/cache/temp directories and localhost-only
fixtures. No root, sudo, Docker, production inventory or credentials were used.
The exact 349-file dirty worktree and prior qualified wheel/sdist were hashed
before starting. To reproduce Git's Linux checkout behavior, only files whose
existing Git attributes specify `eol=lf` were normalized in the disposable
copies: 42 files, including 41 Python files with identical parsed ASTs. The
owner's Windows worktree bytes and both immutable stylesheets were not normalized.

| Check | Result |
|---|---|
| Final full Linux Python 3.13.15 suite | 3,514 passed, 18 skipped; no failures |
| Affected Linux Python 3.12.3 suite | 849 passed, 3 skipped |
| Windows fixture regression suite | 360 passed, 1 skipped |
| Focused smoke/fixture regressions | 33 passed |
| Four changed/new smoke functions | 100% relevant coverage; maximum complexity and adapted CRAP 8; no new exception |
| Locked sync and packaging | Locked environments, Linux build, release-artifact and production-lock validation passed |
| Both qualified wheels | The prior Windows-built wheel and new Linux-built wheel each passed clean isolated Linux installation on Python 3.12 and 3.13 |
| Offline Ansible | Complete `deploy/validate.py` passed with pinned controller dependencies and collection |
| Authenticated Windows Edge | 74 cases, 219 measured keyboard targets and six synthetic workflow/check sequences; no findings |

The Linux full suite also passes the Bash recipe case that remains an existing
Windows-host limitation. Its 18 skips are explicit platform/privilege gates:
Windows-only contracts/tools, absent real Caddy, the root-owned catalog transport
fixture and seven distinct-service-UID cases. There are 60 warnings: one
intentional duplicate-ZIP fixture warning and 59 existing HTTP client
string-CA-path deprecation warnings. Neither skips nor warnings are hidden.

Qualification exposed and corrected two closely related issues:

- Portable presentation workflow fixtures created a non-root-owned catalog but
  then invoked the production root-ownership gate. They now explicitly model
  trusted catalog ownership only within their own fixture subtree, retaining
  real bounds, file identity, permissions and state handling. Three staging
  branch tests now use the appropriate existing fixture boundary. Production
  ownership/provenance code is unchanged, and no failing test was skipped.
- The deployment smoke still required the old `.site-header` layout and only
  the short bundled stylesheet URL. It now recognizes both supported layout
  families and exact same-origin short/full-digest asset forms. Document/CSP,
  escaping, CSS response and authentication checks remain enforced; malformed
  or external stylesheet links are rejected before fetching. Regression tests
  cover both contracts, both authority paths and the rejection branches.

Initial failures are retained rather than overwritten: the original Linux runs
had 76 affected-suite failures and 78 full-suite failures. Controller setup also
exposed Windows line endings, the non-login account's missing default home and
managed Python's missing default CA location. The isolated harness now uses the
Git-declared LF checkout, explicit private Ansible temporary directories and
Ubuntu's existing public CA bundle. No certificate verification, ownership
guard or host setting was relaxed. A complete final controller run passed,
including executable-script, syntax, template, backup/restore and simulated
release/recovery/failure cases; this remains offline execution, not deployment.

Browser qualification used the previously built, hash-verified wheel in an
actual authenticated installed Edge browser over TLS 1.3. A synthetic CA was
trusted only in its disposable browser profile; a second clean profile rejected
the same certificate. No trust bypass or shared trust-store modification was
used. Real login failure/success, filtering, block/unblock, presentation
prepare/review/password-confirm/activate/receipt and logout were exercised.
Presentation activation here is a Windows proof, not root-owned POSIX staging.

Checks covered native menu/disclosures, skip-link focus transfer, accessible
names and landmarks, alert/state distinctions, visible and unobscured focus,
reflow at 320/390/640/1440 CSS pixels and actual 100/200/400-percent browser zoom.
The 400-percent layout also retained keyboard access at 314 CSS pixels. This
is a bounded automated accessibility result, not screen-reader testing, full
WCAG certification or production Caddy/browser qualification. Synthetic secrets,
private keys, application state and browser profiles were disposed; all 169
prior browser artifacts and the read-only owner preview were preserved.

Evidence is in `.metrics\console-qualification-2026-09-18`: original/corrected/final
input manifests, `linux-final`, `linux-python312-final`,
`ansible-controller-retry-40whpt90`, `smoke-changed-quality.json`, Windows
regression logs and `browser\qualification-verification.json`. Earlier failed
attempts remain separate. `preservation.json` records the final changed-file
inventory and unchanged prior artifacts.

The Linux checkout build is separate from the original Windows artifact:

| Local Linux artifact | SHA-256 |
|---|---|
| `strugglebus-0.2.26-py3-none-any.whl` | `a2c837184d1c0677720bd594d9ad1aa56f40b5b122f570b46c092718810cbf99` |
| `strugglebus-0.2.26.tar.gz` | `17e37c8036617e87bbbc05cd64c2b304ad76a46238166f521751c5de5619537c` |

No application package source, stylesheet, schema, dependency lock or workflow
changed during this follow-up. The smoke-helper correction must be included in
any future qualified release envelope; no envelope was published here.

The real Debian 13/systemd/Caddy rehearsal, privileged catalog ownership and
confinement proof, distinct-service-UID recovery and remaining assistive-technology
review are still outstanding. The Debian guest is explicitly deferred by the
owner, not silently counted as passing. Publication/bootstrap/deployment remain
separate approvals.

## First release-readiness review (18 September 2026)

**Decision:** the owner selected a combined planned **v0.2.27**, including
schema 16, rather than a UI-only backport. **Status: scope agreed; not ready
to publish or deploy.** This is an incremental operator/reliability release,
not completion of the full v2 roadmap or a general application updater.
The review authorizes no version edit, commit, push, qualification-workflow
dispatch, tag, publication, provisioning or production access.

The subsequent [static-gate cleanup](#static-gate-cleanup-18-september-2026)
resolved the Bandit blocker locally. The review below records the findings
as observed before that cleanup; the other release/adoption gates remain.

### Candidate contents and identity

The planned increment includes the first M1 safe-post-retry slice and migration
16, the redesigned operator console, verified presentation staging/selection
capability, the frozen-unblock correction, associated operational compatibility
and smoke changes, tests and directly related documentation. M0 metrics tooling
and pinned coverage/radon dependencies remain development tooling. Existing
planning/probe documents do not imply that later M1-M5 capabilities are shipped.

| Identity | Planned value or observed state |
|---|---|
| Repository | `NZCypher819/strugglebus`, currently private; no repository move |
| Proposed package/tag | `0.2.27` / `v0.2.27`; version has not been changed |
| Schema / guide / protocol | 16 / `1.16.0` / 1 |
| Markup | `operator-console-v2`, revision `operator-console-v2.initial` |
| Latest published release observed | `v0.2.26`, targeting `cb1324106812fe6f74db0ad38481e87e4324beaf` |
| Local and remote main observed | `d8c51f6769aef5e609fa1512797593f7e98267dd` |
| Uncommitted review input | 52 modified tracked files and 45 untracked files; 349 source files fingerprinted |

No matching `v0.2.27` tag existed at review time. This is not a reservation;
availability must be rechecked before publication. The published baseline is
not an observation of the running production version or schema. The four
already committed dependency/workflow updates between the published tag and
current main are inherited baseline work, not new workflow changes in this
increment.

All existing local wheels still identify themselves as `0.2.26`. They are
development evidence only and must not replace the immutable published assets.
After the blockers and separate source/version/commit approvals, the existing
release process must bind a new exact main commit/tree to the chosen version,
pass its actual CI gates, build the canonical wheel and exact five-asset release
envelope, and create the owner-bound qualification receipt. Publication must
reuse those exact qualified bytes, not rebuild or rename the development wheel.

### Review result and immediate blocker

The runtime review covered retry intent/replay and migration, current authority,
frozen lifecycle transitions, presentation validation/locking/publication/
receipts/recovery, request bounds, console workflows and retained assets. It
found no additional significant runtime defect. Its fresh execution compiled
21 changed/new runtime modules in memory, checked both CSS identities and
applied migrations through schema 16 to an in-memory database with integrity
checks. It did not rerun the whole test/browser suite or qualify a real host;
the preceding platform evidence remains separate.

The release/controller review checked schema and guide pins, helper checksums,
candidate-configuration probing, the fixed release envelope, pinned bootstrap
requirements, optional configuration, staging separation and maintenance/
recovery restrictions. Existing dependency-lock reproduction, production
dependency audit and offline Actions static checks passed.

**At review time, the existing Bandit CI gate failed with 13 new low-severity
findings; clean HEAD had zero.** No parse errors occurred. This was a real policy-gate failure,
not a claim that all 13 findings are exploitable vulnerabilities:

| Location | Findings | Assessment |
|---|---|---|
| `scripts\quality_baseline.py`:12,154,157 | 5: B404, B603 and B607 | Subprocess import and two fixed, shell-free, read-only Git calls; narrow disposition is required |
| `src\strugglebus\presentation.py`:169,194,326 | 3: B101 | Type-narrowing assertions follow explicit raising validation |
| `src\strugglebus\presentation_files.py`:38,56,63,132,221 | 5: B101 | Type-narrowing assertions follow explicit raising validation |

The eight assertions are not sole input/authority checks: the preceding
`require(...)` calls remain effective under Python `-O`. Nevertheless the
current configured gate must pass before release. Resolve the findings in a
focused follow-up with appropriate regression/quality evidence; do not disable
rules globally or change CI to manufacture a pass. No source fix was made in
this review. README's historical "M0 has not started" wording and Board versus
the current Overview label also need release-facing documentation cleanup.

### Production-impact and recovery plan

Review itself changes nothing in production. The eventual first adoption is
an explicitly approved application/maintenance operation, not a CSS-only swap.
It may migrate an older supported database to schema 16 and needs a verified
pre-migration backup. Existing messages, identities, credentials, retry bindings,
freeze state and audit history must be preserved. The actual installed version,
schema, clients, outstanding maintenance state and backup/restore evidence have
not been inspected or inferred from GitHub.

Plan a restart window with client reconnect/retry handling and fresh operator
login afterward. Its duration is not yet qualified. An interrupted or uncertain
operation must be reconciled using its exact recorded bindings; it is not
permission to retry a different candidate, clear freeze or restore an older
database. Once candidate startup or newer accepted history may have occurred,
use the reviewed forward-recovery rules. Do not decrement `user_version`, discard
accepted messages/retry identities or safety transitions, or claim that the
manifest's predecessor schema permits ordinary rollback.

External presentation selection remains disabled unless its separate bootstrap
is approved and completed. The existing configuration tasks validate/render
optional settings; they do not provision the root-owned catalog or initialize
the service-owned selector. The staging playbook deliberately requires that
bootstrap to exist. A repeatable, idempotent bootstrap procedure and rehearsal
must cover protected ancestry/ownership, create-only selector initialization,
verified catalog publication, the pinned installed stager/controller and local
recovery. Enabling a setting alone does not complete that gate.

### Remaining release gates

Before publication: resolve the static findings, finish release-facing
documentation, approve the version/source change and commit scope, pass exact
main CI and owner-dispatched canonical-artifact qualification, and obtain
separate publication approval. The local review is not a substitute for the
future commit's CI, history-secret scan or isolated LAN-CA job. The existing
15-minute CI job budgets need evidence on their real runners; a concurrent WSL
timing result is not a runner qualification.

Before production adoption: explicitly revisit the deferred Debian 13/
systemd/Caddy rehearsal, real root-owned catalog and distinct-service-UID
recovery, complete the remaining assistive-technology review, re-review the
existing scoped complexity exceptions, agree current-client/migration/backup/
recovery evidence and a maintenance window, then authorize the exact deployment.
No deferred gate is waived by agreeing the candidate's scope.

Evidence is retained in `.metrics\first-release-readiness-2026-09-18`, including
the pre-review inventory, current/HEAD static reports, gate comparison, lock/
dependency/Actions results, runtime-review summary, release decision and final
preservation record. Production, package version, source code, tests, locks,
workflows, HEAD and index were left unchanged by this review.

## Static-gate cleanup (18 September 2026)

The owner authorized the next narrow cleanup after the readiness review.
**Outcome: the existing Bandit gate now passes locally with zero findings,
parse errors or scanner warnings.** This closes that specific blocker, not
the remaining release or production-adoption gates.

All eight runtime assertion sites now use explicit conditional
`PresentationError` guards with the same error kinds and acceptance rules.
Disabled catalogs still fail before external reads; missing, expired and
wrong-session preparations still fail; integers still reject booleans and
subclasses. No casts, runtime suppression, authorization relaxation, selector
reset, CSS change or schema change was introduced.

The metrics snapshot resolves Git from the developer's PATH to an absolute
executable and uses only the two fixed read-only argument vectors, explicitly
without a shell and with a 30-second timeout per command. Missing Git, command
failure and timeout fail the snapshot rather than creating a success-shaped
source identity or overwriting the previous record. This is bounded developer
tooling, not executable authenticity verification or a production command lane.

Two partial-path findings were removed by executable resolution. Following the
repository's existing subprocess pattern, three exact-site annotations document
the remaining reviewed usage: one B404 import and two B603 calls. No global
Bandit rule, severity/confidence threshold, scanner scope, CI workflow or
complexity waiver changed. The initial annotation format produced scanner
warnings; the final form and standalone calls remove those warnings. Both
attempts are retained, rather than replacing the first log with a green result.

### Bounded validation evidence

| Evidence | Result |
|---|---|
| Unchanged Bandit CI command/scope | Zero findings, errors and warnings |
| Affected presentation, console-compatibility and metrics suite | 502 passed, 2 existing skips on each of Windows Python 3.12.14 and 3.13.15 |
| Final core presentation/metrics suite, normal execution | 170 passed, 1 existing skip on each supported Python version |
| Final core suite with Python `-O` | 170 passed, 1 existing skip on each supported Python version |
| Nine complete changed lexical functions | 100% relevant coverage; maximum complexity and adapted CRAP both 7 |
| Real repository metrics snapshot | Correct HEAD, worktree and source fingerprints recorded through Git |
| Local wheel/sdist build and artifact validation | Passed; still development version 0.2.26, not publication candidates |

The final core runs and whole-function measurements followed the final
scanner-format adjustment. New regressions cover fixed argv, executable paths
with spaces, shell metacharacters kept in the cwd field, bounded waits,
missing Git, both command failures/timeouts, wrong metadata types and direct
disabled/missing-ticket paths. Existing authority, replay, expiry and size-limit
tests remain in the affected suites.

The skips are the existing Windows symlink-creation privilege limitation and,
in the broader suite only, unavailable OpenSSL for the live TLS continuity
test. No skip was added. Optimized runs produce pytest's expected warning
about non-test assertions being disabled; the negative guard cases still pass.
The earlier full Linux/browser/continuity evidence is not silently rebound to
these new source bytes. No new full-suite, Linux, real-host, browser or
clean-install qualification is claimed by this focused follow-up.

README now distinguishes the completed M0 baseline from its saved kickoff
prompt and uses the actual **Overview** navigation label. The three runtime/
tool files, two test files, README and these two existing design records are
the entire eight-file increment. Evidence and preservation hashes are in
`.metrics\release-static-cleanup-2026-09-18`; prior reports and all eight prior
wheel/sdist artifacts remain intact.

The planned v0.2.27 scope is unchanged. Version/source/commit approval, exact
committed-main CI, canonical-artifact qualification, publication approval,
the deferred Debian/bootstrap/accessibility work, scoped exception re-review
and approved backup/migration/recovery/deployment remain separate gates.
No version bump, staging, commit, push, workflow dispatch, provisioning or
production access occurred.

## Local prepare-only bootstrap (18 September 2026)

The owner selected **prepare and validate the repeatable bootstrap locally
first; keep guest provisioning deferred**. The separate
storage bootstrap (removed PRESENTATION_STAGING.md) is
now locally implemented. This does not enable external presentation selection
or constitute production/guest approval.

The new opt-in playbook verifies independently pinned qualified CSS input and
the exact preinstalled bootstrap modules/assets, refuses unsafe existing
directories, creates only missing protected catalog directories, stages the
initial verified candidate and calls the protected selector `bootstrap` action.
It does not install application code, create an account, change configuration,
restart a service, switch releases or touch database/credential/freeze state.
The existing staging lane reuses the fixed verification/publication tasks but
still cannot initialize storage.

Selector bootstrap permanently drops root before selector work. The directory
creation result comes from the pinned descriptor operation, not a speculative
filesystem probe. Existing directories require a valid selector/lock pair:
automatic bootstrap does not repair incomplete state. An unchanged repeat
preserves the selected CSS reference, incarnation, generation, receipts and
history status. The CLI reports selector publication through `changed` and
honors the configured bounded state size, receipt count and lock timeout.
Explicit local `init`/`reconcile` remain separate recovery decisions.

### Evidence and limits

| Check | Outcome |
|---|---|
| Real Ansible task predicates, ordering, refusal, check-mode and unchanged replay, with synthetic host I/O | Passed; fixture flags were not added to production tasks |
| Both real playbook syntax checks | Passed; no target host connection |
| Final non-root Linux Python 3.13 affected presentation/compatibility suite | 493 passed, 3 existing platform skips |
| Final Linux Python 3.12 local/staging/bootstrap suite | 126 passed, 1 existing platform skip |
| Final Windows Python 3.13 local/staging/bootstrap suite | 127 passed |
| Same core suite on Windows Python 3.12 with `-O` | 127 passed; expected pytest optimization warning |
| Final lock-holder/contender cases on Windows 3.12 and 3.13 | 2 passed on each |
| Actual non-root Linux bootstrap CLI, normal and `-O` | Explicit unauthorized refusal; no stdout or state creation |
| Seven complete changed/new runtime functions | 100% relevant coverage; maximum complexity and adapted CRAP both 5 |
| Existing Bandit policy | Zero findings/errors; no global rule or workflow change |
| Local build and artifact validation | Passed; development 0.2.26 artifacts only |

Linux uses the existing Ubuntu WSL installation and explicit UID/GID 65534,
with new private disposable source/fixture directories and previously installed
isolated dependencies. It is not a Debian guest. The three Linux skips are the
two Windows-only sharing cases and the root-owned live TLS catalog fixture.
The final 3.12 subset skips only the Windows-specific staging sharing case.
No skip was added and no ownership/provenance guard was weakened.

Earlier attempts remain recorded. An extracted controller task initially had
task keywords nested inside command arguments; the executable fixture caught
the error, and now rejects unexpected I/O arguments explicitly. An initial
Bandit warning concerned a negative fixture pathname, not a real temporary-file
operation; the fixture now uses a non-temporary unsupported data path.

Cross-process lock qualification exposed a timing-sensitive test handshake.
Raw filesystem and service lock probes refused contention correctly. An
explicit clean subprocess environment alone did not eliminate the test failure.
The fixture now signals actual lock ownership through a pipe and retains the
lock until the parent closes its release pipe, with bounded readiness, release
and join handling. A new failure case checks holder cleanup. Production locking
and timeouts were not changed. A fixture timeout exception was also corrected
to avoid being mistaken for a filesystem `OSError`; all failed attempts remain
separate from the final passing source snapshot.

Evidence is retained in `.metrics\presentation-bootstrap-2026-09-18`, including
source hashes/Git LF normalization, Ansible results, regression logs, complete
runtime-function metrics, non-root CLI results, artifact hashes and preservation.
Disposable fixture data is cleaned separately from retained source/evidence.
The earlier full-suite, clean-install, browser and continuity proofs are not
silently rebound to these new bytes.

The real Debian/root-owned catalog/distinct-service-UID/systemd/Caddy rehearsal,
remaining assistive-technology review and scoped complexity-exception re-review
still remain. Actual deployment configuration, publisher qualification,
version/commit/publication approval and production backup/migration/recovery
decisions remain separate. No guest was created; package version, HEAD, index,
CI workflows and production were not changed.
