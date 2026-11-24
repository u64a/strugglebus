# Multi-agent client and deployment plan

**Recorded:** 19 September 2026.
**Status:** design and isolated offline prototype completed; live client
implementation, host adoption, and production rollout are not completed.

This repository copy replaces the need to retrieve the earlier session-only
proposal. It preserves the intended contract, not permission to provision or
deploy. Read [the continuation handoff](archive/NEXT_SESSION_2026-09-20.md) for current
worktrees, evidence, outstanding decisions, and the next-session prompt.
`AGENTS.md` and existing approved architecture/release policies still apply.

## 1. End-state topology

The updater does **not** need its own VM. The intended steady state is one
production Debian guest containing the bus and a separately confined updater.
Local connectors run beside the existing Copilot CLI processes.

```text
WINDOWS WORKSTATION                       OPERATOR BROWSER

  Copilot A -> connector A --+                  |
  Copilot B -> connector B --+                  |
  ...one per logical agent..|                  |
                            +--- LAN HTTPS ----+
                                     |
                                     v
  +----------------------------------------------------------+
  | ONE PRODUCTION DEBIAN GUEST                               |
  |                                                          |
  | Caddy -> Strugglebus app/operator console -> SQLite       |
  |                   |                                      |
  |          operator-only local Unix socket                 |
  |                   v                                      |
  |             Updater worker ------------------------------+--> GitHub
  |             separate user/service                        |    outbound
  |                   |                                      |    HTTPS
  |             bounded cache filesystem                     |
  +----------------------------------------------------------+

  SEPARATE DEV/REHEARSAL ENVIRONMENT
  Same relevant server topology, synthetic data and credentials.
  Not on the production request path and not an updater dependency.
```

Caddy remains LAN-only and the application binds only to loopback. The worker
has no inbound network service; the application reaches it through its protected
local socket. Agent credentials do not authorize operator update actions.

The approved updater slice is **Check -> review -> fresh-password Prepare**.
Preparation verifies release files in a bounded cache. It does not install,
execute a candidate, restart the bus, migrate data, change freeze, or grant
deployment authority. Installation remains separately operator-approved.

A disposable test guest is a qualification venue, not a second production
component. Equivalent isolation could be considered separately, but a folder,
mock filesystem, or another service alone is not proof of real UID, mount,
credential-projection, and recovery behavior. The owner chose to wait for new
capacity to establish a dev environment rather than experiment on the live bus.

## 2. One explicit identity per logical agent

Use one maintained connector implementation, with a separate connector process
for each Copilot CLI process. Do not introduce a shared credential-holding
daemon, local TCP listener, or one globally selected agent identity.

The operator selects a profile at launch. It binds that process to one stable
agent ID and name, one approved server origin, and the appropriate credential
instance. A prompt, repository name, custom-agent persona, bus message, or
model-supplied tool argument must not select or switch that connection's identity.

Different logical agents need different stable identities, not just different
keys for one identity: subscriptions and catch-up state are agent-scoped.
Multiple agents may share the same approved workspace. Ephemeral subagents
using a parent's connection remain that same bus actor; do not auto-enroll them.

The non-secret, strictly versioned profile contains:

| Field | Contract |
|---|---|
| Local profile ID | Explicit selector, not an authorization proof or a default fallback. |
| Expected agent ID/name | Operator-established pins; both must match authenticated identity. |
| Server origin and public CA reference | Approved LAN HTTPS origin and trusted CA; no trust-on-first-use. |
| Credential reference | Reference to protected storage, never the secret itself. |
| Approved workspace roots | Explicit grants, resolved safely; not inferred from a Git remote. |
| Connector release | Qualified installed code, not an import from a mutable checkout. |

Profile configuration, session bindings, and diagnostic state are distinct,
private, versioned objects outside repositories. Publish updates atomically.
No raw credentials belong in any of their JSON, argv, environment, logs, or
MCP results. Missing, unknown, or conflicting configuration fails explicitly.

## 3. Launch and session binding

The future launcher validates profile ownership/ACLs, schema, actual workspace,
required files, and executable provenance before decrypting a credential.
It records a non-secret launch binding and invokes Copilot with an argv array.
It never changes cwd to an unrelated approved directory to evade a workspace
guard. Startup diagnostics display the selected identity and bound workspace.

The inspected Copilot CLI supports `--additional-mcp-config @<file>`,
`--disable-mcp-server <name>`, and `--session-id <uuid>`. The proposed integration
uses a distinct per-process connector entry and disables the known legacy bus
entry only for that launch. It does not rewrite the global MCP registry or load
all agents' credential-backed connectors into every process.

These options are a starting point, **not proof of configuration precedence**.
Qualify inherited workspace/plugin definitions, malformed overrides, actual
startup cwd, and whether a fallback can accidentally reconnect another profile.
Unsupported versions or conflicting definitions must fail before credential
loading. Preserve unrelated MCP integrations.

Generate and persist a new session UUID before launch. Managed resume requires
an exact existing UUID bound to the same approved profile and workspace.
Reject collisions, unbound resumes, cross-profile resumes, and unscoped
"continue the most recent session" selection. Existing sessions need explicit
operator adoption.

Use an OS-held lease for the server/stable-agent identity, including aliases
under different profile names. PID files alone are not locks. Do not kill a
competing process, steal a live lease, or assume the lease controls unmanaged
legacy bridges. The prototype's lease namespace is one synthetic root; a real
client needs an appropriate shared, protected local coordination namespace.

The binding is process-scoped, not inferred from the displayed conversation.
Native `/new`, `/fork`, `/resume`, `/cwd`, sidebar switching and `/restart` need
qualification. Do not claim a startup workspace check continuously sandboxes
later context switches. Stronger per-conversation admission requires trusted
runtime context, never an agent-name argument supplied by the model.

## 4. Real credential and protocol adapters

The intended initial Windows store uses DPAPI CurrentUser encryption plus
verified Windows ACLs. Decrypt only within the selected connector. No plaintext
fallback, temporary plaintext migration export, arbitrary credential-path tool,
identity-switch tool, admin-token tool, or automatic recovery/issuance exists.
Client commands must not load server configuration, its database, or its admin
credential.

DPAPI and separate profiles do **not** isolate hostile processes under the same
Windows user. Such processes may access/decrypt other profiles or alter launch
configuration. Strong adversarial isolation is a separate OS/runtime design.

For a real connection:

1. Verify HTTPS origin and the operator-provided CA. Do not inherit ambient
   proxies, bypass certificate verification, or forward credentials elsewhere.
2. Compare initialize identity with both pins. Make advisory, non-consuming
   `orientation` the first tool call; compare authenticated `whoami` as well.
3. Read actual server information, capabilities and integration guidance.
   Missing version metadata is unavailable evidence, not a successful match or
   an invented mismatch.
4. Prove a pending credential only after identity comparison. Recognize already
   active/proved credentials rather than performing unnecessary lifecycle work.
5. Obtain the effective global and matching-agent RoE and record the exact
   required receipt. Receipts are credential-scoped and mean receipt, not
   permission, agreement, or compliance.
6. Admit ordinary coordination only when its required bootstrap is satisfied.

Bodies, metadata, names, guidance and RoE remain untrusted data. No content
grants authority to execute commands, provision a guest, or clear a freeze.
Connecting must not silently subscribe, drain catch-up, advance cursors, or
post a test message. Those require explicit task scope.

Production observed during the separately authorized inquiry reported app
0.2.26 and guide 1.15.0. Its message tool was `post`; `whoami` nested agent and
credential records. Initialize supplied identity but an empty application
version field. Re-discover actual capabilities when connecting; do not assume
the pending release's post retry feature is already deployed.

The prototype's synthetic schemas, credential values, origins and small frame
limits are not production wire compatibility. Implement actual tool surfaces,
limits and transport semantics rather than replacing a fake URL and calling
the result production-ready.

## 5. Failure, framing and resource contracts

Keep transport connectivity, cached observations and authenticated readiness
distinct. An enabled MCP entry, existing key file or healthy unauthenticated
health endpoint does not establish a usable identity.

Use explicit states for invalid/missing profile, denied workspace, busy lease,
credential unavailable, TLS/network failure, identity mismatch, pending proof,
required RoE, revoked/inactive identity, frozen, ready and unknown outcome.
Give actionable but sanitized reasons. Do not dump headers, payloads, secrets
or arbitrary exception text into diagnostics.

Terminal freeze/revocation/mismatch decisions must not be overwritten by a
response that completes later. Recheck terminal state after awaited work and
before publishing readiness. Authoritative freeze stops bus activity; do not
switch credentials/surfaces, rotate, enroll or loop to bypass it. Only an
explicit later normal connection attempt may establish restored access.
The client never clears freeze.

Track submission/outcome per invocation. An admission refusal is
`not_submitted`, even when an earlier mutation was confirmed or ambiguous.
Historical last-write diagnostics are separate. A timeout, cancellation, lost
acknowledgement or unusable mutation result can mean `unknown_outcome`, not
"did not happen". Never automatically replay an ambiguous mutation.

Budget the complete serialized MCP envelope, including escaping and request ID,
not just the upstream payload. A response-size problem after a consuming read
must not silently discard its result, claim confirmed delivery, or trigger a
blind retry. Preserve a bounded, truthful error path.

Declare concrete, configurable deadlines, input/response/frame bounds,
concurrency and queue bounds, retry budgets and diagnostic retention for the
real client. Validate boundaries and server-advertised limits. Do not copy the
synthetic laboratory's numbers without a compatibility review.

## 6. Onboarding, migration and rollback

Reconcile the intended agent roster with the operator first. Directory labels
are not evidence of identity assignment. Preserve each existing agent's stable
identity and protected credential where appropriate; a software migration does
not automatically require key rotation.

New enrollment is an explicit operator operation. Deliver one-time material to
a protected native recipient, never through chat, MCP logs or tracked files.
Persist the returned secret directly into the protected store. Existing
private-file recipient helpers are not a plaintext intermediate for this design;
reuse suitable validation/transport primitives below that storage boundary.

Ambiguous redemption needs the documented operator recovery path, not replay,
name reclamation or speculative creation. Reconnect/computer-move package
issuance immediately revokes existing live keys: it is not a harmless default
migration step. Enrollment, recovery, reconnect and rotation remain separately
authorized and freeze-gated.

Qualify local real adapters before an approved single-agent pilot. Stop that
agent's old connector through its normal owner-controlled workflow; a new lease
cannot police old bridges. Migrate one agent at a time, preserving subscriptions,
cursors and attribution. Keep the other agents and global settings unchanged.

Rollback changes client version/launch mapping, not the server database, TLS
checks, workspace restrictions or freeze. Old revoked credentials are not a
rollback path. Remove legacy global wiring only after all dependents are
accounted for and that change is explicitly approved.

## 7. Qualification and remaining decisions

The offline prototype demonstrated eight separate processes sharing a workspace,
strict bindings, local leases, bounded synthetic bootstrap and operations, and
failure handling. Its usage/evidence document lives in the separate prototype
worktree identified in the handoff. It is not an installed live connector.

Remaining client gates are real protected storage, installed-code trust,
verified TLS and actual server interoperability, native Copilot lifecycle/
precedence, durable onboarding failure handling, and an approved live pilot.
Prefer existing Python 3.12/3.13 and the official MCP dependency; do not add a
daemon, dependency or framework without a demonstrated need.

The Linux updater has separate host gates: distinct service users, actual
peer-UID socket checks, namespace/DAC/ACL denial, read-only systemd credential
projection, bounded resources and an independently mounted cache filesystem.
The first profile uses a separate persistent ext4 block filesystem capped at
1 GiB and a 512 MiB worker memory cap. These are not spare-capacity guarantees.
Use its own bootstrap/preparation documents for exact constraints and approval
requirements.

The next session should establish a bounded dev/rehearsal plan with synthetic
data and separate identities/trust. Do not weaken production admission checks
to make an unpublished fixture appear to be a canonical release.
Production canaries and non-mutating preflight can be considered separately;
"fail forward" alone does not repair credential exposure or lost data.
