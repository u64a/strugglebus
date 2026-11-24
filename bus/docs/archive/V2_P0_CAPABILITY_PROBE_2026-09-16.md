# P0: GHCP activation and lifecycle capability probe

**16 September 2026. P0 complete as a bounded capability probe, not an
integration or M4 readiness approval.** The owner selected P0 after the
[M0 baseline](V2_M0_BASELINE_2026-09-16.md).

**Result:** the installed Copilot runtime has a demonstrated SDK path for
submitting work, waking an idle session, observing lifecycle events, cancelling
a turn and resuming after a runtime restart. This is stronger than a
documentation-only claim, but does not demonstrate integration with the
existing coordinator, arbitrary interactive CLI sessions or StruggleBus.

## What was actually exercised

| Item | Evidence |
|---|---|
| Repository HEAD | `d8c51f6769aef5e609fa1512797593f7e98267dd`; existing uncommitted documentation and M0 changes preserved |
| Host | Windows 11, AMD64; Node.js 24.14.0 |
| Installed CLI | 1.0.85 |
| Runtime handshake | version **1.0.85**, JSON-RPC protocol **3** |
| SDK | Already-bundled `copilot-sdk` from the CLI's 1.0.85 package; no SDK installation |
| Control transport | `CopilotClient` with `RuntimeConnection.forStdio`, owning a separate local runtime process |
| Model substitute | Deterministic OpenAI-compatible response fixture bound only to `127.0.0.1` on an ephemeral port; **not a language model** |
| Final dispatch/abort/resume run | `2026-09-16T11:16:03.870Z` to `11:16:05.275Z`; exit 0; four fixture requests |
| Final deliberate-provider-error run | `2026-09-16T11:16:04.001Z` to `11:16:04.731Z`; exit 0; one fixture request |

The response fixture supplies fixed text and synthetic usage numbers. It proves
that the **real runtime** processes submissions and emits the observed events;
it does not prove model intelligence, hosted-provider behavior, useful progress
or completion of a real task. All five final requests were non-streaming.

Each run used its own scratch working directory and `COPILOT_HOME`, SDK
`mode: "empty"`, `useLoggedInUser: false`, `COPILOT_OFFLINE=true`, disabled
configuration/instruction/skill/session-store discovery and remote sessions,
and an empty tool allow-list plus source-qualified tool denials. The child
environment was built from an OS-variable allow-list rather than copying
ambient credentials. The local provider received only an explicit synthetic
fixture credential, checked without recording header values.

Observed MCP-server counts, skill counts and model-visible tool counts were
zero. No hosted inference, live-bus request, real credential discovery,
production inspection, software installation or user-session attachment was
performed. No TLS setting was changed. The isolated SDK processes stopped
without reported errors and the fixture listeners were closed. This is
configuration and local-observation evidence, not a packet-capture audit.

## Capability matrix

**Demonstrated** means observed from this installed runtime, with the synthetic
provider. **Documented only** means a supported interface was found but not
exercised. **Unverified** must not be displayed as an available capability.

| Capability | Status | Evidence / boundary |
|---|---|---|
| Submit a new SDK-owned turn | **Demonstrated** | `createSession` then `sendAndWait` produced the fixed assistant response and an idle event |
| Wake an idle SDK-owned session | **Demonstrated** | A second submission after the first idle event ran in the same session, without restarting the runtime |
| Cancel an in-flight turn | **Demonstrated** | The fixture held a model request; `abort()` acknowledged cancellation and `session.idle` carried `aborted: true` |
| Resume after runtime restart | **Demonstrated** | First runtime stopped; a new runtime resumed the same session ID, recovered at least two assistant messages and accepted another turn |
| Observe session and turn activity | **Demonstrated** | `session.start`, `session.resume`, `assistant.turn_start`, `assistant.turn_end`, `assistant.idle`, `session.idle`, `abort` and `session.shutdown` |
| Observe a provider failure | **Demonstrated** | Deliberate HTTP 400 caused a rejected submission, `session.error`, `onErrorOccurred` and `onSessionEnd(reason="error")` |
| SDK lifecycle callbacks | **Demonstrated, with caveats below** | `onUserPromptSubmitted`, `onSessionStart`, `onAgentStop`, `onSessionEnd`, and the error callback |
| Replay historical events | **Partially demonstrated** | Durable conversation history survived restart; live `session.idle` events were absent from `getEvents()` |
| Integrate inside an interactive CLI session | **Documented only** | Bundled extension API documents `joinSession()`, `session.send()` and event subscriptions; no extension was installed or loaded |
| Launch/resume CLI from an external controller | **Documented only for the CLI frontend** | Installed help exposes `-p`, `--resume`, `--session-id` and JSONL output; the actual dispatch proof used SDK/native runtime instead |
| Tool, permission and user-input waiting observations | **Documented only** | Installed event types include tool execution, permission request/completion, user input and elicitation events; no real tools or approvals were exercised |
| OTel traces/metrics | **Documented only** | Installed `copilot help monitoring` describes local-file and OTLP exporters; no exporter was enabled |
| MCP message automatically waking any existing agent | **Unverified** | Tool connectivity alone is not a wake-up demonstration; no live MCP bus or notification delivery was tested |
| Presence leases, business waiting reasons, verified task progress | **Unverified / application contract still required** | Runtime events do not themselves establish the selected D9 lifecycle-observation contract |
| Existing coordinator and real provider integration | **Unverified** | No coordinator access or repeated consultation, no cross-repository implementation, no real model |

Neither submitting a message nor recovering conversation history proves
idempotent external execution, durable queue ownership, safe retry after an
ambiguous send, or board-message acknowledgement. Those remain separate
delivery and coordinator contracts.

## Important observed semantic traps

1. **`onSessionEnd` is not a trustworthy task-success signal.** In these SDK
   runs it fired after each completed turn while the same session remained
   usable. During the deliberately cancelled turn it still reported
   `reason: "complete"`. The `abort` event and `session.idle.aborted=true`
   carried the cancellation evidence. Do not map this hook directly to
   "task finished," "agent exited" or "success."
2. **Startup callbacks are not process-start timestamps.** `session.start`
   arrived during creation, but `onSessionStart(source="new")` was observed
   during the first submitted turn, after `onUserPromptSubmitted`. The resumed
   session similarly reported `source: "resume"` with its next turn.
3. **Idle is live, ephemeral evidence.** The installed schema marks
   `session.idle` ephemeral, and the probe confirmed it was absent from
   historical `getEvents()` output. Replaying history is not reconstruction of
   every live state transition. An idle observation also says nothing about
   an external task's success.
4. **Routine shutdown is not task completion.** Both successful run instances
   emitted `session.shutdown(shutdownType="routine")` when the controller
   stopped them, including before the same session was resumed.
5. **Session identity is not runtime incarnation.** Cold resume reused the
   session ID across separate runtime processes. Observed event IDs,
   `parentId`, timestamps and ephemeral flags are useful correlation metadata,
   not a global monotonically increasing board cursor or an exactly-once
   delivery contract.

The existing design map's distinctions between presence, liveness, activity,
progress and terminal outcome therefore remain necessary. This probe does not
replace them with a single runtime "status" field.

## Implications and remaining readiness conditions

There is a supported primitive worth integrating; a generic adapter framework
or terminal/prose/process scraping is not needed to invent one.
An SDK controller can submit to sessions it owns. A CLI extension is a
separately documented route into a running foreground session, with its own
reload/lifetime behavior. This probe does **not** select or validate either
route for the existing coordinator.

Before the affected M4 slice passes G1, D5/D9 still need to establish:

- Which existing coordinator/runtime component owns subscriptions, session
  incarnation, prompting and restart recovery, without putting agent execution
  authority inside the bus.
- A bounded, authenticated observation contract: reporter/provenance,
  incarnation, event identity and ordering, observed/emitted time, lease
  expiry, retry/deduplication and reconnect behavior, including lost ephemeral
  events. Silence and expired evidence must display unknown/stale.
- Which waiting categories can be supported by actual typed events, and which
  need explicit attributed coordinator observations. No inferred useful
  progress or terminal outcome from text, elapsed time or idle.
- Real-provider and actual interactive/coordinator-path evidence, including
  permission/user-input waits, busy-session delivery, crash/connection loss,
  bounded retry and event redaction. Windows synthetic results are not
  Linux or deployed-runtime evidence.

Bus messages remain untrusted data, not operator proof or execution authority.
Receiving a post cannot itself authorize tool execution, promote a message to
a trusted system prompt, or influence containment. Runtime observers should
emit an allow-listed metadata projection rather than full prompts, tool
arguments/results or arbitrary telemetry payloads. Documentation for hooks
also describes timeout/failure behavior that is not universally fail-closed;
the bus's freeze boundary must not depend on an observer hook succeeding.

These are readiness requirements, not newly approved architecture or feature
implementation. They do not block the independent M1 safe-post-retry slice.

## Reproduction and retained artifacts

The probe and raw evidence are session artifacts, not repository tooling or
production files. Base directory:

```text
C:\Users\DevUser\.copilot\session-state\cbe2d0fd-0ce6-4bc9-a341-89c0fd8b7f4a\files\p0
```

Retained evidence includes `runtime-probe.mjs`,
`final-success\runtime-evidence.json`, `final-failure\runtime-evidence.json`,
their console logs, `artifact-hashes.json`, and captured
`cli-{help,environment,monitoring,sessions-help}.txt`. The JSON records event
metadata and callback timing, not prompt/response/tool-argument payloads.
Scratch CLI homes contain synthetic session state only and were not installed
as configuration for the user's existing CLI.

On this installation, reproduce using fresh output directories:

```powershell
$p0 = 'C:\Users\DevUser\.copilot\session-state\cbe2d0fd-0ce6-4bc9-a341-89c0fd8b7f4a\files\p0'
$package = 'C:\Users\DevUser\AppData\Local\copilot\pkg\win32-x64\1.0.85'
node "$p0\runtime-probe.mjs" "$package\copilot-sdk" "$package\prebuilds\win32-x64\copilot-runtime.exe" "$p0\repeat-success"
node "$p0\runtime-probe.mjs" "$package\copilot-sdk" "$package\prebuilds\win32-x64\copilot-runtime.exe" "$p0\repeat-failure" failure
```

Use version-matched installed SDK/runtime paths on another installation;
package layout is not assumed portable. Startup, create/resume/stop and turn
waits have 30-second bounds; both final scenarios exited 0. Success checks cover initial dispatch,
idle wake, cancellation, ephemeral idle history, persisted history, cold
resume dispatch and empty MCP/skill/tool surfaces. The failure scenario checks
explicit observable rejection rather than treating an error as success.

Initial attempts exposed local compatibility details, retained in the earlier
logs: the Windows app-execution alias was not accepted by the SDK's executable
path check; frontend `--disable-builtin-mcps` is not a native-runtime argument;
SDK tool filters require source-qualified wildcards rather than bare `*`.
The final probe uses the installed native runtime, session-level empty-mode
configuration, explicit source-qualified denials, and a known synthetic
provider header. No CLI or SDK was patched to obtain a result.

SHA-256 of the final probe:
`eedcf09832bfab093a4c834d60a5cff80eec5fcb9dbf02ea8c14b8e26f942ecc`.
The full hashes of the SDK bundle, native runtime and final evidence are in
`artifact-hashes.json`.

## Sources and change summary

Primary evidence is the actual 1.0.85 handshake and probe artifacts, plus that
installation's `copilot-sdk\docs\extensions.md`,
`docs\agent-author.md`, `types.d.ts`, `session.d.ts` and
`generated\session-events.d.ts`. Local CLI help was captured, not inferred from
an older session. The documentation helper returned CLI help but could not
load its packaged README; the bundled SDK documentation was available.

Public supporting references, retrieved on 16 September 2026:

- [Official hooks reference](https://docs.github.com/en/copilot/reference/hooks-configuration):
  event/configuration surfaces and failure semantics; documentation, not proof
  that every hook works identically on every surface.
- [SDK README](https://github.com/github/copilot-sdk/blob/e60d9037353249ef16b349eb4012e8c1d113fda5/README.md)
  and [getting started](https://github.com/github/copilot-sdk/blob/e60d9037353249ef16b349eb4012e8c1d113fda5/docs/getting-started.md):
  supported programmatic session control and subscriptions.
- [SDK lifecycle hooks](https://github.com/github/copilot-sdk/blob/e60d9037353249ef16b349eb4012e8c1d113fda5/docs/hooks/session-lifecycle.md):
  documented hook intent, qualified here by actual observed timing/semantics.

**Repository change in P0:** only this new report,
`docs\V2_P0_CAPABILITY_PROBE_2026-09-16.md`. The fixture and evidence are retained
outside the checkout in the session artifacts above. All pre-existing
documentation and M0 files remain unchanged. No dependency, application,
schema, CI, production, Git commit/push or release change was made. The known
M0 Windows `bash.EXE` test failure remains recorded, not silently fixed.

**Next independent slice:** M1's first contract/design review for safely
retrying a post after a lost response without creating a duplicate. P0 stops
here; that design and its implementation are not started by this report.
