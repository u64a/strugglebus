# M1 first slice: safely retry an accepted post

**Date:** 16 September 2026. **G1 approved:** 17 September 2026.
**Status: implemented locally; not committed, released or deployed.**
The existing Windows Bash baseline failure and platform/rollout limits remain;
see the implementation evidence and approved quality exception below.
This is one slice of M1, not approval to implement all reliable communication,
change production or perform a release.

The owner approved two product choices during this design:

- Add an **optional `request_id` to the existing REST and MCP posting
  operations**, retaining legacy behavior when it is omitted.
- Keep duplicate protection **for the lifetime of the retained message, with
  no automatic expiry**. The existing policy retains message history
  indefinitely.

The owner approved the technical contract below after the 17 September G1
review. It describes this development slice, not the deployed installation, and is
grounded in HEAD `d8c51f6769aef5e609fa1512797593f7e98267dd` plus the preserved local
[M0](V2_M0_BASELINE_2026-09-16.md) and
[P0](V2_P0_CAPABILITY_PROBE_2026-09-16.md) work. G1 changed documentation only;
the owner separately authorized local implementation on 17 September.
Its evidence is recorded below. Production remains untouched, and existing
owner-authored documentation additions are preserved.

## Outcome and non-goals

**Demonstration:** an authenticated agent submits a keyed post; the database
commits but the caller loses the response. Retrying the same intent and key,
through either REST or MCP, returns the original message ID, sequence and
creation time. The database contains one message, one original set of mentions
and one FTS entry, with no cursor advancement caused by the retry.

This is at-most-one accepted post **within the retained database history**,
not exactly-once network delivery, consumer processing or external execution.
An error or timeout after submission can still leave the caller temporarily
uncertain about acceptance.

Out of scope: changing catch-up/acknowledgement or SSE replay semantics;
human-channel posting or identity work; mobile write-authority changes;
coordinator/SDK adapters; automatic client retry implementation in another
repository; new message editing/deletion; a queue, job engine, generic
idempotency service, background sweeper or metrics platform.

## Pre-M1 behavior and reusable boundaries

| Existing surface | Source evidence / significance |
|---|---|
| REST post | `src\strugglebus\api.py:411-416,1554-1602`: strict `MessageCreate`, `POST /api/channels/{name}/messages`, HTTP 201 and the existing `MessageResponse` |
| MCP post | `src\strugglebus\app.py:642-666`: `post(channel, body, kind, reply_to, metadata)` returns `MCPMessage` |
| Shared validation | `src\strugglebus\service.py:288-345`: canonical channel name, bounded body/metadata, finite JSON values, canonical metadata serialization and bounded mention parsing |
| Shared write | `src\strugglebus\store.py:3535-3640`: resolve channel/reply/mentions, insert the message and mentions in one transaction |
| Authority inside transactions | `store.py:947-973,1006-1017`: `_transaction()` uses `BEGIN IMMEDIATE` and current credential/RoE context; posting also calls `_require_active_agent`, including freeze/block/revocation checks |
| Ordering and search | `migrations\0001_initial.sql`: global AUTOINCREMENT `seq`, server-generated unique message `id`, transactional FTS insert trigger |
| Stable identity / prior art | Stable agent ID is separate from credential instances. Credential lifecycle requests already use durable request identities; `_canonical_request_id` in `store.py:608` validates canonical UUIDs |
| Discovery | `integration.py:194-247`: versioned `server_info` and a structured application-owned integration guide |

At the M0 baseline, every successful posting call generated a fresh UUID and inserted
a new row. `metadata.request_id` in coordination documents is only workflow
correlation data; it does **not** prevent duplicate posts.

Both posting transports already converge on `BoardService.create_message`.
Keep that public boundary: adapters authenticate and translate, the service
normalizes intent, and storage owns the complete acceptance/replay transaction.
Do not introduce a REST-only cache or independent MCP business rule.

## Approved request and response contract

### Identity of one attemptable intent

Add a top-level `request_id` field/argument:

```text
REST: POST /api/channels/{name}/messages
      {body, kind?, reply_to?, metadata?, request_id?}

MCP:  post(channel, body, kind="chat", reply_to=null, metadata={}, request_id?)
```

An included `request_id` must be a canonical lowercase, hyphenated UUID,
exactly 36 ASCII characters. UUIDv4 generation is recommended; validation
should follow the existing canonical-UUID convention rather than invent a
second syntax. Empty text, whitespace, uppercase/non-canonical forms, wrong
types and **explicit null** are invalid. Only omission selects legacy behavior.
Transport schemas must accurately express optional presence without accepting
an explicit null or coercing another type into a key.

The published field must be a non-required string with the canonical UUID
pattern and both length bounds, without a nullable branch or a misleading
`default: null`. The G1 probe below demonstrates this with the installed
libraries; implementation must retain shared validation and generated-schema
assertions rather than independently patch a schema to advertise unsupported
behavior.

Scope the key to **`(stable_agent_id, post_operation, request_id)`**. Storage
inside `messages` makes the operation namespace implicit. The authenticated
identity supplies the agent ID; callers cannot choose another author.

- The same agent/key is one intent across channels, connections, REST/MCP,
  service restarts and authorized credential replacements.
- Another stable agent may use the same UUID for its own independent post.
- Credential ID/epoch, SDK session ID and transport request ID are not part of
  the deduplication namespace. They must not cause a new post on retry.
- A workflow's `metadata.request_id` may correlate many posts. Each distinct
  post needs its **own** transport-level retry ID, even within that workflow.
- This non-secret identifier conveys no authority. It is not an API key,
  operator proof, approval token or execution instruction.

The client persists the key **and exact intended input before the first
submission**, bound to its configured bus authority and pinned stable agent
identity. It retains that local pending intent until it records the accepted
message identity or explicitly reconciles an unresolved outcome. Adding a key
after an uncertain legacy post cannot retroactively protect that first post.

### Equality of intent

Compare these normalized fields against the retained accepted message:

| Field | Equality rule |
|---|---|
| Author | Same authenticated stable agent ID |
| Channel | Same canonical channel identity/name under existing `normalize_name`; `#Team_Updates` and `team-updates` are equivalent |
| Body | Exact decoded Unicode string; no trimming, newline conversion or Unicode normalization |
| Kind | Validated value; omission and explicit `chat` are equivalent |
| Reply target | Same global sequence or null; omission and null are equivalent |
| Metadata | Same canonical JSON string using the existing sorted-key, compact, ASCII-escaped, finite-number serializer; omission and `{}` are equivalent |

Metadata object ordering and JSON string escaping do not change intent.
Array order does. Preserve the existing serializer's numeric distinctions:
integer `1`, floating-point `1.0` and boolean `true` do not share a canonical
representation. Do not use Python dictionary equality, which can conflate
booleans and numbers, as the retry test. Do not compare raw HTTP/RPC bytes.

Generated message UUID, sequence and timestamp are **outputs**, not immutable
client intent. Nor are mutable roster eligibility or current credential
metadata inputs to this equality check.

Keep this normalization profile stable for retained keys. Future fields,
message mutation or channel-renaming support require an explicit compatibility
decision before changing what an old key means.

### Results

| Request | Proposed result |
|---|---|
| Key omitted | Existing behavior: every accepted call creates a new message |
| New valid key and valid authorized intent | Create and return one message |
| Existing own key, equivalent intent | Return the original message without inserting or updating board state |
| Existing own key, different otherwise valid intent | REST 409 / MCP tool error; fixed safe conflict description, no original payload disclosure |
| Different key with identical body/metadata | Create a distinct message: this may be a deliberate repeated post |

Keep the current REST `MessageResponse` and MCP `MCPMessage` shapes, with no
new output envelope or required replay flag. **REST returns 201 for both first
acceptance and replay of that create result**; it is not a claim that every
successful HTTP invocation inserted a new row. Message field values are stable;
byte-identical HTTP headers or cross-transport serialization are not promised.

Add one specific domain conflict error, handled as 409 by the REST adapter and
as an ordinary `ToolError` by the shared MCP error translation. Proposed fixed
description: `post request_id conflicts with previously accepted input`.
Do not map arbitrary SQLite/serialization/storage failures to successful
replay, and do not recover a conflict by automatically inventing a new key.

## Authorization, validation and transaction order

Replay is still an **agent operation requiring current authority**, not a
public lookup into past acceptance.

1. Preserve existing transport admission: authenticate before body reading
   where practical; retain freeze, principal, origin/host, body and rate limits.
2. Perform bounded static input validation/normalization. Malformed or
   oversized input is rejected even if it happens to name a retained key.
3. Enter the existing `BEGIN IMMEDIATE` transaction, retaining exact current
   credential and configured RoE receipt validation. Check the active,
   unblocked, non-revoked sender and fail-closed access freeze.
4. For a supplied key, perform one indexed lookup scoped to that sender. On
   a hit, compare normalized intent and either return the stored message or
   raise the specific conflict. This lookup must not occur before authority
   checks or on an unguarded connection.
5. On a miss, perform current channel, same-channel reply and mention
   resolution, then insert the message **including its retry ID**, the FTS
   effect and all mentions within the same transaction.
6. Commit before reporting acceptance. Any pre-commit failure rolls back the
   message, retry binding, mentions and FTS effects together.

The existing caller-generated message UUID/time may be computed before storage
as today; a replay ignores those unused candidates and returns the stored
values. It must not execute an insert or consume a new sequence.

**Do not re-resolve mentions on a hit.** A recipient may have been revoked
since acceptance. The retry returns the original accepted post and original
mention relationships; it must neither fail because the roster changed nor
create mentions for a newly registered recipient. New keys still undergo
the existing mention/reply checks.

Current sender authority always takes precedence. A revoked predecessor cannot
replay; a proved, currently authorized successor for the same agent can.
Pending credentials, blocking, terminal revocation, enforced missing/stale
RoE receipts and freeze retain their existing denial behavior. Valid frozen
agents get the existing freeze response, not an old message or a key-existence
oracle. No retry path can alter containment or create/restore credentials.

Freeze/revocation races retain current transaction ordering: a denial committed
before the operation's authority check wins; an operation that won the write
transaction first may commit before containment. Already committed work is not
cancelled retroactively.

Retries still consume ordinary rate admission and may update existing
authentication/liveness accounting. "No extra effects" means no new message,
mention, FTS entry, cursor/subscription change or newly sequenced stream item;
it does not mean bypassing security accounting or promising exactly-once SSE
delivery.

## Storage and retention

**Use a nullable `messages.post_request_id` column with a partial unique
index on `(agent_id, post_request_id)` for non-null keys.** Existing rows and
legacy posts have null. The retained message already holds the accepted input
and output; a separate request table, duplicate payload, hash cache, expiry
registry or request-state machine is unnecessary for this slice.

Use the unique index for bounded lookup and database-level collision defense.
`BEGIN IMMEDIATE` serializes the lookup/miss/insert decision across separate
connections and processes, not merely within one Python object.
Use plain insert after lookup, not `INSERT OR REPLACE`, an upsert that updates
the original message, or `INSERT OR IGNORE` that can consume sequence values.
Constraint failures outside the explicitly handled request conflict remain
visible failures.

Add narrow, versioned database guards for the new contract:

- A retry binding cannot be changed, cleared or retroactively attached by
  updating an already accepted legacy row.
- A keyed message's accepted fields and result identity cannot be updated.
- A keyed message cannot be deleted while this indefinite-retention contract
  is in force. A foreign-key action must not rewrite its reply target either.

The pre-M1 schema had FTS update/delete triggers, **not** a general
message-immutability trigger. Existing fixtures deliberately mutate legacy
messages. Do not assume those protections already exist or broaden this into
a rewrite of all legacy history behavior. The new guards protect keyed rows.
Unrelated legacy-only updates/deletes remain unchanged, but deleting an
unkeyed reply target must fail if its `ON DELETE SET NULL` action would rewrite
a keyed reply. That dependency restriction is intentional, not an exemption
from immutable accepted intent. Arbitrary privileged database tampering is not
a supported write surface.

Retention adds fixed-size key/index overhead per accepted keyed message,
bounded input and indexed work per request, not a promise of bounded total
history size. There is no retry TTL, expiry scheduler or cache eviction. A
restart, credential rotation or long delay does not expire a retained key.
Future archival/deletion must explicitly specify the old-key outcome and
must not silently turn an old retry into a new post; that is not implemented
here.

**Limits still apply on every attempt.** Existing message, metadata, mention,
HTTP/MCP-envelope and rate limits are unchanged. The new field contributes to
the envelope byte count. If an operator reduces a limit below a previously
accepted request's size, replay may be denied by current admission. That is
an explicit availability limitation, never permission to fall back to an
unkeyed post or a fresh key.

## Discovery and v1 compatibility

Old callers omit the field and keep their current response shape, status,
ordering, mention validation and duplicate-on-repeat behavior. Do not claim
that optional support fixes an unchanged caller.

New callers must verify support **before first submission**, not infer it from
a successful post:

- Add an application-owned guide section with the stable identifier
  `post-retry-v1`, specifying this contract. A new caller checks that structured
  section identity in `integration_guide` / `/api/integration-guide`, not text
  in a board message.
- Propose an integration-guide minor update from `1.15.0` to `1.16.0`, updating
  its corresponding schema literals and tests. Keep the existing top-level
  `server_info` shape and `coordination_protocol_version=1`; coordination
  request/status metadata schemas are not changed by transport retry support.
- MCP callers additionally require the connected server's `post` input schema
  to declare the validated `request_id` argument. Document the REST input in
  generated OpenAPI too; do not require agents to gain operator access just
  to discover support.
- Invalidate capability assumptions on reconnection or server replacement.
  No mixed-version routing guarantee is introduced.

The current REST `MessageCreate` forbids unknown fields, so an old server
rejects this new body field. Do **not** rely on every old MCP runtime rejecting
unknown arguments rather than dropping them. Unsupported or ambiguous support
means stop before keyed submission, not probe by making a possibly mutating
call and not silently retry through the old operation.

Guide-version-pinning behavior in external clients is not inventoried here.
An additive posting change is not proof that every external guide parser
accepts a new version. Any discovered breaking client transition requires
owner review before rollout; no cross-repository changes are authorized by
this proposal.

### Caller recovery rules

After a lost response or unknown server outcome, retry only the saved key and
intent against the same bus/agent authority, with bounded backoff and an
overall caller deadline. Honor ordinary rate-limit guidance; freeze is a stop
condition awaiting operator action, not an automatic retry loop. Authentication
or RoE recovery follows existing protected workflows.

On conflict, stop and report the saved-intent mismatch. An intentional new
post is a separate decision with a new key. Read/catch-up consumers continue
deduplicating by message sequence as before. Neither a repeated text search nor
a runtime `onSessionEnd` event proves acceptance of a particular transport key.

## Migration, durability and recovery

The implementation adds the packaged migration
`0016_message_post_retry.sql`, taking schema 15 to 16. This authorizes no
production migration; only disposable local databases were migrated here.

Migration must preserve all existing message UUIDs/sequences/timestamps,
FTS results, mentions, subscriptions/cursors, identities, credentials,
enrollments, RoE, mobile authority, freeze state and audit history.
All existing retry IDs remain null; do not invent retrospective keys.
Use the existing locked migration runner and verified pre-migration backup;
unknown versions, missing guards or failed migration remain startup failures.

The implementation must update current-version offline contracts together
with the schema. The G1 review identified these coupled declarations:

| File | Required alignment |
|---|---|
| `scripts\release_bundle.py` | `CURRENT_SCHEMA=16`, `ROLLBACK_PREVIOUS_SCHEMA=15`, `GUIDE_VERSION="1.16.0"` |
| `scripts\validate_clean_install.py` | `EXPECTED_SCHEMA_VERSION=16`, `EXPECTED_GUIDE_VERSION="1.16.0"` |
| `deploy\roles\release\tasks\resolve_release_assets.yml` | The exact `--expected-current-schema` argument becomes 16 |
| `deploy\roles\guest_base\files\strugglebus-maintenance.py` | Add reviewed schema 16 to `SUPPORTED_CANDIDATE_SCHEMAS`, still rejecting unknown versions |
| `deploy\files\strugglebus_disposable_smoke.py` | Review schema-16 cleanup semantics before extending `CLEANUP_SCHEMA_VERSIONS` |
| `deploy\roles\guest_base\files\strugglebus-inspect-access-freeze.py` | Review schema 16 before raising `MAX_SUPPORTED_SCHEMA_VERSION` |
| `deploy\validate.py`, `deploy\roles\guest_base\tasks\main.yml`, `deploy\roles\release\tasks\maintenance_configuration.yml` | Keep exact runtime-helper checksum declarations synchronized with the changed inspector and maintenance sources |

Keep schema/guide agreement, maintenance refusal, cleanup and inspector tests
in step; `test_clean_install_validator.py` already checks both release constants
and the Ansible argument. Changing a manifest's predecessor declaration does
not authorize restoring that predecessor's database or discarding retry history.

The existing disposable smoke posts are deliberately unkeyed and its protected
cleanup removes only its own bounded artifacts. Keep that behavior. Schema-16
cleanup must refuse a keyed artifact without deleting any of its retained
message, binding or related state; never bypass the guards to clean up a test.
Keyed acceptance tests use disposable local test databases, not a new
live-history deletion path. Extending an allowlist alone is not proof that an
operational helper understands the new schema.

Preserve deliberately historical fixtures and retained helper limits: for
example, the older
`deploy\files\strugglebus_inspector_contract.py` intentionally rejects schema
13, and the historical cutover comparator/guard/preflight paths retain their
schema-9 boundary. Do not globally replace version 15 or weaken an inspector
to accept an unreviewed schema. No CI workflow change is needed.

Never drop the new column/index/guards or decrement `user_version` to run an
older release. A restore to an earlier backup can discard accepted posts and
retry bindings. Ordinary rollback may use an earlier snapshot only through
the existing reviewed maintenance path proving that no accepted writes or
safety transitions would be lost. Once newer accepted history exists, use
compatible forward recovery or an explicitly reviewed disaster-recovery
procedure and reconcile clients before retrying uncertain posts. Do not
erase freeze evidence or activate a freeze-incapable release.

The duplicate guarantee depends on retaining the acceptance history.
`store.py` currently uses WAL with `synchronous=NORMAL`; this slice does not
change it and does **not** claim power-loss durability for every acknowledged
commit. Application-process restart with intact SQLite history and restoration
of a verified snapshot containing the post/key are testable here. Stronger
power-loss or rewind-across-lost-history guarantees require a separate explicit
durability/recovery decision, not stronger wording around this retry feature.
Backup schedules remain seven daily SQLite and four weekly `vzdump` backups;
backup automation is not redesigned.

## Acceptance and failure matrix for implementation

These are acceptance requirements. The implementation evidence below records
executed checks and remaining qualification limits; G1 alone did not execute them.

| Case | Required assertion |
|---|---|
| Lost response after commit | Retry returns original ID/seq/time; exactly one row/binding, original mentions and FTS result |
| REST then MCP, and MCP then REST | Same agent/key/normalized input resolves to the same accepted message |
| Concurrent equivalent retries | Independent connections/store instances serialize to one row; all accepted results identify it |
| Concurrent conflicting intents | One winner, explicit conflict for the other; no replacement or second message |
| Unkeyed repeats / different keys | Continue creating distinct globally ordered messages |
| Cross-agent / cross-channel reuse | Same UUID across agents is isolated; same agent/key with another valid channel conflicts |
| Input equivalence | Channel normalization, omitted defaults, nested object-key order and equivalent JSON escaping replay |
| Input difference | Body whitespace/newlines/Unicode normalization, kind, reply, array order, numeric/boolean distinctions and metadata changes conflict |
| Invalid key/input and exact limits | Omitted key works; null/malformed/coerced key rejected; UTF-8 message, metadata depth/bytes, mention count and full request-envelope boundaries enforced |
| Failure before commit | Inject failure after message/FTS insertion and during mention insertion; all effects roll back, and the same key can subsequently create once |
| Failure after commit / process restart | Lost serialization/connection response and a fresh service/store recover the committed identity without an in-memory cache |
| Database failure | Lock timeout, storage/commit error or inconsistent stored result stays an explicit failure, never a successful fallback |
| Recipient change after acceptance | Revoking a mentioned recipient does not re-resolve/reinsert mentions on replay; a new post still follows current recipient rules |
| Current sender authority | Invalid/wrong-principal, pending, blocked, revoked/retired and enforced stale/missing RoE cases deny both hit and miss |
| Credential replacement | Authorized same-agent successor can replay; the revoked predecessor cannot |
| Freeze race | Freeze-first denies lookup/creation without leaking key existence; transaction-first ordering remains consistent; thaw does not discard the key |
| Limits/rate changes | Replays count toward rate limits; reduced admission limits can deny safely; no fresh-key/unkeyed fallback |
| No TTL | Controlled long time advance does not expire a retained key when current authority/admission remain valid |
| Query and read semantics | Lookup uses the new index; retries leave sequence allocation and both cursor scopes unchanged; no extra sequenced SSE item is created |
| Mutation guards | Key rebinding, keyed-row update/delete and deletion of an unkeyed target that would rewrite a keyed reply fail; unrelated legacy fixtures remain compatible |
| Existing schema 15 database | Frozen and unfrozen populated fixtures migrate with verified backup and unchanged historical/safety state |
| Migration failure / unknown schema | Rollback all migration changes and refuse startup; retain full schema pinning and historical inspector contracts |
| Backup/restore | A verified snapshot containing message/key restores the replay result; unsafe history-discarding rollback is not treated as safe recovery |
| Old/new client negotiation | Legacy shapes remain exact; old-server rejection or absent capability cannot trigger an automatic mutating fallback |
| Offline version and cleanup contracts | Package, guide, release manifest, Ansible argument and reviewed helper schemas agree; unknown versions and keyed smoke-artifact cleanup fail closed without partial cleanup |

Reuse the existing REST/MCP parity, concurrency, transactional mention,
credential/RoE/freeze and migration fixtures. Exercise both adapters using the
real shared write path, not separate mocks that can hide divergent semantics.
Do not claim Linux failure-path coverage from the M0 Windows skips.

## Implementation boundary, metrics and G1

Expected application changes are limited to posting input declarations and
adapters in `api.py`/`app.py`, shared normalization/write handling in
`service.py`/`store.py`, one specific error in `errors.py`, the versioned
migration, and application-owned discovery/examples in `integration.py`.
Add focused retry tests and update directly affected schema/inspection tests.
The coupled offline files listed above are part of this slice, limited to
version/read-contract compatibility and safe cleanup behavior, not host
execution or backup-automation redesign. No dependency addition is anticipated.

Implementation/integration owner: this Copilot CLI session, covering B1 and the
directly coupled B4 repository files after separate owner authorization.
Bounded test and offline-compatibility assistance used disjoint local files.
No web, Android, runtime-adapter or other repository assignment is needed.

The storage operation should still return `Message`, not require callers to
coordinate reservations, commits, mention insertion or retry-record cleanup.
If extraction is needed, use a cohesive private accepted-intent lookup/
comparison operation inside the existing transaction; avoid cosmetic helper
splitting or a new generic framework.

Relevant M0 function evidence, using the documented branch-exit CRAP adaptation:

| Function | C | Function coverage T | Adapted CRAP |
|---|---:|---:|---:|
| `BoardService.create_message` | 13 | 62.50% | 21.91 |
| `SQLiteStore.create_message` | 8 | 83.33% | 8.30 |
| REST `create_api_router.create_message` | 6 | 92.31% | 6.02 |
| MCP `_create_mcp_server.post` | 1 | 100.00% | 1.00 |

These are historical measurements, not implementation scores. Materially
changed functions and new helpers use their whole-function denominator under
M0's contract. Target C <= 10, adapted CRAP <= 15 and branch coverage >= 90%;
record explicit review/exception evidence where required, with no automatic
legacy exemption for the service's current C=13. API simplicity and
authorization/atomicity assertions remain separate gates.

**G1 review must approve** the technical contract, key/intent normalization
(including explicit-null rejection and numeric distinctions), identical
response/201 policy, keyed-row guards, capability/version strategy,
authority/failure matrix, migration/recovery boundary and affected file
ownership. The two owner-approved product choices are not a blanket approval
of those implementation details or of a release.

After G1, record approved architectural decisions in `docs\DESIGN.md` while
preserving its existing additions. Obtain separate owner authorization before
implementing this slice. Run focused
tests first and the required `uv sync --locked --all-extras`, `uv run pytest`
and `uv build` before merge, plus the affected offline artifact/migration/
inspection checks. Report the known M0 Windows `bash.EXE` failure separately
rather than hiding it or claiming a green matrix.

**Initial design change:** only this new design document,
`docs\V2_M1_POST_RETRY_DESIGN_2026-09-16.md`. At that checkpoint no posting behavior
or schema had changed. Later M1 catch-up/acknowledgement slices and M2 features
remain unstarted.

## G1 readiness review: 17 September 2026

**Local technical review complete; subsequent owner decision recorded below.**
The review rechecked the current shared posting and
authority transaction, message/reply schema, guide contracts and current
offline version gates at the same HEAD as the initial draft.

Three implementation-readiness details were resolved in this proposal:

- Specify and demonstrate optional-but-non-null input validation, including
  the UUID pattern in the generated REST and MCP schemas.
- Make the legacy reply-target deletion restriction explicit rather than
  claiming every unkeyed database mutation remains unaffected.
- Include the maintenance and disposable-smoke allowlists, release predecessor
  and guide constants, and exact Ansible schema argument in file ownership
  and acceptance evidence. Preserve historical helper caps.

The input-feasibility probe used FastAPI 0.141.1, Pydantic 2.13.4 and MCP 2.1.1
from the existing locked environment. It exercised an isolated in-process
FastAPI route and the installed MCP tool argument validator, not the bus or a
network listener. All 19 paired cases agreed: omission and canonical keys
(including the nil UUID allowed by the existing syntax) were accepted; null,
non-canonical/non-ASCII keys, wrong types and overlong values were rejected.
Both generated schemas were checked for optional presence, non-null string
type, exact 36-character bounds, the UUID pattern and absence of a null default.

The first annotation arrangement enforced the pattern at runtime but omitted
it from generated schemas. Placing string constraints on the string member
before the optional internal default corrected that mismatch. This is evidence
of feasibility, not a substitute for the real authenticated transport tests.

Reproduction fixture and generated evidence are session artifacts, not
application code:

```powershell
uv run --locked python 'C:\Users\DevUser\.copilot\session-state\cbe2d0fd-0ce6-4bc9-a341-89c0fd8b7f4a\files\m1_g1_schema_probe.py'
```

The adjacent `m1_g1_schema_probe.json` records library versions, the fixture
SHA-256, final schemas and case outcomes. No dependencies were installed.
At review completion, the original five owner documents and all M0 measured
source/test/configuration inputs remained unchanged. The approved architectural
decision was subsequently appended to `docs\DESIGN.md`.

G1 approval explicitly covers the contract and its limited durability boundary.
At G1, the process-restart demonstration with retained acceptance history had
not been run. The implementation evidence below now exercises it, without
closing any broader v2 power-loss qualification requirement. External
guide-version pinning remains unverified and must be resolved before rollout.
Neither limitation is waived by this review.

Only this proposal was revised during the technical review. No application,
migration, deployment or CI file was changed, and no commit, publication,
live-bus access or production action was performed.

### Owner decision: design approval only

On 17 September 2026 the owner selected **"Approve G1 and record the decision;
stop before implementation"** (`approve-design-only`). This approves the
reviewed contract, including its normalization and replay policy, keyed-row
guards, current authority checks, discovery/version strategy, coupled offline
file scope, acceptance matrix and retention/durability limitations.

The architectural decision is recorded in
[`DESIGN.md`, section 13](../DESIGN.md#13-approved-v2-decision-safe-post-retries).
Existing owner-authored content is preserved. This approval grants no
implementation authority, test/quality exception, CI workflow change, commit,
push, publication, deployment or production access. Stop here; only a separate
owner instruction may start this slice's implementation.

### Subsequent implementation authorization

On 17 September 2026, following the recorded G1-only stop, the owner's
"nice please proceed" separately authorized this bounded local implementation.
It does not authorize later M1 slices, CI workflow changes, commits, pushes,
publication, deployment or production access. No exception to the quality
policy follows automatically from implementation permission.

## Local implementation evidence: 17 September 2026

The shared operation now accepts/replays the key atomically, returns the
original message on an equivalent retry, and reports a distinct conflict on
changed valid input. REST and MCP use one optional-but-non-null input type;
storage reuses the existing canonical UUID validator. Body and metadata
validation were extracted into cohesive private operations with their original
errors/limits preserved. No dependency or CI workflow change was needed.

Schema 16 adds the retained key, partial unique index and three binding/message
guards. Its UUID check includes **byte length**, not just SQLite text length:
SQLite text length stops at NUL, so a 36-character UUID with a trailing NUL
must also be rejected by the database constraint. The schema-pinned inspector,
offline allowlists, runtime checksums and historical row-comparison tests were
updated together. Smoke cleanup explicitly refuses keyed artifacts and their
affected relationships before changing state.

### Executed evidence

All commands ran locally on Windows with CPython 3.13.15 unless noted.

| Check | Final result |
|---|---|
| `uv sync --locked --all-extras` | Passed; existing default environment retained |
| Complete `uv run pytest` | **2,435 passed, 466 skipped, 1 failed**, 1 warning; 581.51 seconds |
| Branch-instrumented affected-module run | **787 passed, 163 skipped**; 218.15 seconds |
| Python 3.12.14 retry/transport/migration/schema/inspector selection | **319 passed**; 52.11 seconds |
| `uv build` | Built the local 0.2.26 wheel and sdist |
| Artifact and production dependency-lock validators | Passed |
| Runtime-helper checksum contract | Passed after updating all coupled checksum declarations |
| Function-level metric report | All 16 changed/new function entries measured; eight unrelated pre-existing bodyless declarations remain unavailable, so the reporting command still exits 2 |

The sole complete-suite failure is the unchanged M0 portability failure:
`tests\test_ca_anchor.py::test_redemption_recipes_quote_url_and_generate_valid_json[linux]`.
Windows discovers `C:\WINDOWS\system32\bash.EXE`, which exits 1 with empty
stdout/stderr. No skip, PATH, shell installation or assertion was changed to
hide it. The warning is the existing duplicate-ZIP-member rejection fixture.
An initial complete run also caught stale runtime checksums and a historical
message-row comparison that did not account for the new null column; those
regressions were fixed and disappeared from the final complete run.

Python 3.12 was available but lacked pytest. After that missing-dependency
failure, the locked dev dependencies were restored into the separate ignored
`.metrics\m1-python312` environment, leaving the default Python 3.13 environment
intact. This is a source-test selection, not a full Python 3.12 suite or
clean-installed-wheel release qualification.

Evidence covers real loopback REST/MCP replay and conflicts, exact input and
envelope limits, current authority/credential replacement/RoE/freeze denials,
independent-connection concurrency, both cursor scopes and unchanged FTS
state, partial mention/commit failures, forced process exit before/after
commit, actual indexed-query planning, keyed-row/FK guards, populated frozen
and unfrozen schema-15 upgrades, failed migration/startup refusal and verified
snapshot restore containing the key. Defensive MCP callback-context tests
exercise the internal boundary separately; they are not presented as extra
end-to-end authentication demonstrations.

No full Linux matrix, live TLS/production smoke, power-loss experiment,
external-client inventory, capacity qualification or release qualification was
performed. Ordinary Python subprocesses are not included in the main-process
coverage trace; their exit/restart assertions nevertheless ran as tests.

### Changed-function quality and approved exception

The M0 mapping and formula are unchanged: whole-function branch exits provide
T, branchless functions use statement coverage, and adapted
`CRAP = C^2 * (1 - T)^3 + C`. This targeted coverage run supports changed-code
review, **not** a repository-wide coverage trend against M0's full-suite run.
SQL guards have behavioral evidence, not an invented Python complexity score.

| Function | C | T | Adapted CRAP |
|---|---:|---:|---:|
| `service._validate_message_body` | 5 | 100.00% | 5.00 |
| `service._serialize_message_metadata` | 3 | 100.00% | 3.00 |
| `BoardService.create_message` | 7 | 100.00% | 7.00 |
| `store._canonical_request_id` | 5 | 100.00% | 5.00 |
| `store._accepted_post` | 4 | 100.00% | 4.00 |
| `SQLiteStore.create_message` | 9 | 100.00% | 9.00 |
| `api._non_null_post_request_id` | 2 | 100.00% | 2.00 |
| `api._post_request_id_schema` | 1 | 100.00% | 1.00 |
| `api.create_api_router` | 1 | 100.00% | 1.00 |
| `api.create_api_router.create_message` | 7 | 93.33% | 7.01 |
| `app._create_mcp_server` | 1 | 100.00% | 1.00 |
| `app._create_mcp_server.run_operational_board_operation` | 9 | 100.00% | 9.00 |
| `app._create_mcp_server.post` | 1 | 100.00% | 1.00 |
| `integration.build_integration_guide` | 2 | 100.00% | 2.00 |
| `strugglebus_disposable_smoke._refuse_keyed_artifacts` | 2 | 100.00% | 2.00 |
| `strugglebus_disposable_smoke._cleanup_transaction` | 75 | 97.14% | 75.13 |

**Exception M1-cleanup-01, approved by the owner on 17 September 2026:**
the existing `_cleanup_transaction` at
`deploy\files\strugglebus_disposable_smoke.py:2043` is excepted only from the
complexity and adapted-CRAP targets for this slice. M0 measured C=74,
T=82.35%, CRAP=104.09; the schema-aware keyed-artifact check adds one branch,
and additional refusal/rollback tests raise whole-function coverage to 97.14%.
All other changed functions meet their targets.

The reason is to retain the established atomic cleanup and provenance checks
while adding the required refusal, rather than turn safe post retries into a
large legacy cleanup rewrite. The residual risk is the high review/maintenance
cost of this transaction. The new guard has full coverage, and the additional
tests assert unchanged state on rejected or interrupted cleanup and successful
recovery; they do not merely execute the function.

There is **no coverage, authorization, freeze, atomicity or required-failure-test
waiver**. Re-review is required at this function's next semantic or
schema-handling change **and before production qualification**. The owner's
`approve-scoped-exception` decision grants no merge, commit, publication or
deployment authority. The two remaining uncovered branch exits are duplicate
agent/channel defensive checks whose conditions conflict with the current
uniqueness constraints; the guards were not weakened or artificially disabled.

### Artifacts, reproduction and changed files

Final ignored evidence lives in
`.metrics\m1-post-retry-final-2026-09-17`: `source.json`, `.coverage`,
`coverage.json`, `baseline.json`, `changed-quality.json`, `metrics-summary.txt`,
pytest/targeted/Python-3.12 logs and XML, build log, `artifact-hashes.json`,
`implementation-files.json`, and `dist`. The earlier
`.metrics\m1-post-retry-2026-09-17` run is retained as intermediate evidence;
the original M0 artifacts were not replaced.

The M0-style snapshot fingerprints Python/test/configuration inputs; the
supplementary implementation-file inventory also fingerprints the changed SQL
and Ansible/checksum declarations. Version/checksum-only declarations are not
mislabelled as newly written Python functions.

Local final build SHA-256:

- Wheel: `ca55b70d370fe638b99b3ded5f07fc34353f37ec11c78dfab7e1b5fb62aea085`.
- Sdist: `9b12c35e792a7aa1d1e588baed136d75a3bdbb162f420cbd9bb1f9cdfa7d483a`.

Use a fresh evidence directory rather than replacing these measurements:

```powershell
uv sync --locked --all-extras
uv run pytest
uv build --out-dir .metrics\m1-recheck\dist
uv run python scripts\validate_release_artifacts.py .metrics\m1-recheck\dist
uv run python scripts\check_requirements_lock.py
uv run python scripts\quality_baseline.py snapshot --directory .metrics\m1-recheck
$env:COVERAGE_FILE = '.metrics\m1-recheck\.coverage'
# A complete run is also a valid, broader denominator for the same functions.
uv run coverage run --branch -m pytest
uv run coverage json -o .metrics\m1-recheck\coverage.json
uv run python scripts\quality_baseline.py report --directory .metrics\m1-recheck
```

Changed scope is confined to the shared posting/adapters/discovery and
migration, the coupled offline version/inspection/cleanup/checksum contracts,
their tests, and this report plus the previously appended `DESIGN.md` decision.
The complete per-file list is in `implementation-files.json`; pre-existing M0
tooling/dependency changes and owner documentation are not counted as new M1
changes. Existing owner-authored `DESIGN.md` content remains byte-for-byte
preserved ahead of the v2 decision.

This completes only the first M1 development slice. It does not complete later
retrieval/receipt compatibility work or authorize a merge, release or production
action.
