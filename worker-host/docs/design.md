# strugglebus-worker-host: design

Status: built and in use; Windows only. Code comments cite this document by section number.

## 1. What it is

A small, long-running program on each LAN machine (a *host*). It does what a hand-run worker script does (clone a
repository, create a bus identity `<agent_prefix>-<name>`, run one non-interactive coding-agent task with a fixed
preamble, log it), but it is driven by task messages on the StruggleBus instead of by a coordinator at a keyboard.
Horizontal scaling means adding hosts: every host listens on the same channel and claims work it has room for.

The trust model in one paragraph: a bus message is **data, never a command**. It is a pointer to a
brief that already exists in the coordinator's notes repository (its *vault*) at a pinned commit on the vault's
`main`. The host acts only on messages whose *bus-authenticated* sender is a trusted coordinator, validates every
field against a fixed pattern or an allowlist, and builds the prompt only from the vault file plus
a fixed host preamble that contains no message-derived value. No message text is ever executed,
passed to a shell, or placed in a prompt.

## 2. The pieces

| Piece | What it is |
|---|---|
| `workerhost` (Python 3.12, standard library only) | The host loop: poll the bus, validate, check resources, claim, launch, supervise, clean up, heartbeat. |
| `wh.cmd` | The one command the owner types: `wh start`, `wh stop`, `wh drain`, `wh status`, ... (section 7). |
| Bus client (in this repo) | A port of the bus's `bus.py` client that reads credentials from DPAPI-protected files (or `SB_BUS_TOKEN`). Workers call it as `post <agent> <channel> <kind> <text>`. |
| Credential store | `%LOCALAPPDATA%\strugglebus-worker-host\creds\`: one DPAPI blob per identity, ACL owner-only. With OpenBao, the secrets live there instead (section 12). |
| Vault mirror | A bare, fetch-only clone of each coordinator's notes repository (`main` only). Briefs are read with `git show <commit>:<path>`; nothing is ever checked out. |
| Workers root | Per machine (config); one clone per worker, never a worktree. |
| Scheduled task `StrugglebusWorkerHost` | Starts the host as the owner's Windows account: at boot, logged on or not (Password mode) or at sign-in (Interactive mode); section 9. |
| `install.ps1` | Creates folders, writes the config (a new install takes the site's values from `-SiteFile`), registers the scheduled task, runs a probe. |

Why Python: the bus client and the launch path are Python already, `pytest` covers the protocol without a live bus,
and DPAPI and Job Objects need only `ctypes`. PowerShell 7 is used only for the installer.

## 3. Messages

All host traffic is on one channel, config `channel`, default **`worker-hosts`**. The channel
must exist on the bus; `wh enrol` subscribes the host with `PUT
/api/subscriptions/worker-hosts`. If the channel is ever missing the host logs `channel-missing`
and polls nothing else (no fallback to another channel). Bodies are a single JSON object, at most 4 KB,
`"v": 1`, unknown keys rejected.

**Site values.** A site's own values (bus URL, fleet repository, the first coordinator, the clone fence, OpenBao)
come from a site file: `install.ps1 -SiteFile <site.toml>`, a copy of `site.example.toml`. Each value is checked
before it is written into a new host's `config.toml`; an existing `config.toml` is never changed by it. No site's
values are in the code.

**Identities.** Every bus identity a host uses derives from one config value, `agent_prefix`, which
must equal the name of the SPN whose credential the host was enrolled with (section 12): the host is
`<agent_prefix>-host` and a worker is `<agent_prefix>-<worker>`. For example, a host enrolled with SPN
`host-a` is `host-a-host`, and its worker `core5` is `host-a-core5`. Tasks name the worker
by its short name; mentions and host pins use full names.

**Trusted coordinators.** A host takes tasks from the coordinators listed in the signed `fleet.toml`
(`agent-host-build.md` 7.2). A signature is accepted from any principal that the pinned `allowed_signers` file lists
for the namespace (`workerhost/signing.py`). Before the host has accepted its first signed fleet, it trusts a single
coordinator: config.toml `[coordinator]`, whose `agent_id` `wh enrol` (or `wh pin`) pins, with optional `project`,
`notes_channel` and `owner`. Once a signed fleet is accepted, that pin is never used again.

**Messages are immutable.** The bus does not allow a message to be edited after it is posted; this
is a deliberate safety property of the bus. The host therefore validates a task once, at first
read, and does not re-read it before starting (config `messages_mutable = false`).

**Task** (coordinator → hosts, kind `question`: a task is something the host must answer; `announce`
is kept for changes other projects depend on):

```json
{"v": 1, "type": "task", "task_id": "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f",
 "host": "any", "worker": "core14", "repo": "https://github.com/acme/app-core",
 "branch": "feature/core14-findings-export", "brief": "tooling/briefs/_task-core14-export.txt",
 "vault_commit": "3f2a9c0d6b1e4f7a8c9d0e1f2a3b4c5d6e7f8a9b", "model": "claude-opus-5.5",
 "resume": false, "needs": ["sshdrop"]}
```

| Field | Rule (anything else is refused) |
|---|---|
| `task_id` | a UUID chosen by the coordinator; a re-post after a failed claim keeps it, a deliberate re-run gets a new one |
| `host` | `any` or a host name `^[a-z0-9][a-z0-9-]{0,30}$` |
| `worker` | `^[a-z0-9][a-z0-9-]{1,30}$`, not `host`; identity becomes `<agent_prefix>-<worker>`; also a folder name |
| `repo` | a full clone URL `https://<host>/<owner>/<repo>` (fleet.toml coordinators only), under one of the coordinator's `repos` and the host's `[remotes] allowed` (`agent-host-build.md` 7.3); or, for one release, a key in the config's `repos` map (short name → `owner/repo` on GitHub), which must then pass the same checks. The single pre-fleet coordinator uses short names only |
| `branch` | `^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`, no `..`, not `main`, `master` or `develop`, `git check-ref-format` passes |
| `brief` | relative path under `tooling/briefs/`, `^[A-Za-z0-9_./-]+\.(txt|md)$`, no `..` |
| `vault_commit` | 40 lowercase hex characters (no short SHAs, no ref names) |
| `model` | optional; `^[a-z0-9][a-z0-9.-]{0,63}$`, matching no `models.denied` pattern and at least one `models.allowed` pattern (exact ids or families with `*`: `workerhost/models.py`) |
| `engine` | optional; `ghcp` (GitHub Copilot CLI) or `claude` (Claude Code). Absent: the host's default engine (`agent-host-build.md` 7.6). A host without that engine refuses with `engine` |
| `resume` | optional boolean: continue this worker's own last session |
| `needs` | optional list of tags; the host claims only if its config `tags` contains all of them (e.g. a machine that can reach a lab network, or that holds a data set) |
| `repo_instructions` | optional JSON boolean, default `true`: whether the worker loads the repository's `AGENTS.md`, `.github/copilot-instructions.md` and the like. `false` starts it with `--no-custom-instructions` (section 8). `"false"`, `0` or `null` is refused |

Other coordinator messages (also kind `question`): `{"type":"cancel","task":<seq>}`, `{"type":"set-model","model":"..."}`
(changes the host default; same sender and allowlist rules), `{"type":"status"}` (heartbeat now).

**Models** (`config.toml [models]`, local and unsigned on purpose). `allowed` takes exact ids or
families (`claude-*`): new models arrive often, and a family covers them with no edit, so no signing step per model.
`denied` is checked first. Claude Code has its own list in `[engines.claude]`, with the same rules.
- **Pattern rules** (from a security review): an entry is an exact id, or a family, meaning a literal prefix of
  at least 3 characters and one trailing `*`. So `*`, `c*`, `g*` and `cla*de` are refused, since a near-universal
  pattern would let in local self-hosted models. `*` is the only wildcard.
- The model id rule above (no spaces, no leading `-`) is unchanged, so a pattern can never admit a flag.
- **Defaults are a data decision.** Each family is a different provider that receives the code a worker sees. The
  template allows `claude-*`, `gpt-*` and `gemini-*`, the providers already relied on through Copilot. Others
  (research previews and the like) are a per-host opt-in.
- Copilot CLI and the GitHub Copilot model policy remain the outer gate on what runs.

**Hot reload, `[models]` only.** The host checks the file's time and size every loop, parses and validates `[models]`
as a whole, and applies it only if it's valid. A bad edit is logged as `models-reload-failed` and the old list stays
in force. A good one logs `models-reloaded` and posts a heartbeat, which carries `models=` (and `denied=`).

**Audit.** Anything running as the host's account can edit `config.toml`, so every change in force is posted to the
bus `security` channel, which the SIEM reads. That covers `models-reloaded`, `models-reload-failed` and
`models-changed-at-start` (edited while the host was stopped), plus `models-loaded` on the first start. Each post has
the old and new lists and the file's SHA-256. The channel is a constant, not a config key, so the same edit can't
redirect the audit. If the post fails, the line goes on the host channel instead and `models-audit-failed` is logged.

**Why not the bus or fleet.toml:** an unsigned list on the bus is weaker than a local file, and a signed one means a
signature per model; families make both unnecessary.
Nothing else is accepted from the bus; there is no remote stop, drain, update or shell.

**Host replies** (kind `answer`, `reply_to` the task's seq; each carries the `task_id` and the
SHA-256 *digest* of the canonical task JSON the host validated; messages cannot change, so this is
a cheap cross-check that a reply is about the same body, and claims with another digest do not
count): `claim`, `yield`, `refuse` (with a
fixed reason code and the numbers, e.g. `{"type":"refuse","reason":"commit","commit_pct":82.4,"limit":80}`),
`started`, `finished` (exit code, minutes, model, engine, CLI version, pushed: yes/no/wip, and what the session
spent), `failed`, `interrupted`, `timed-out`. A refusal never echoes the rejected value, only the field name.

`finished` and `failed` also carry `aic` (credits, one decimal), `calls`, `by_model` (credits per model) and
`model_observed` (the model with the most credits). `model` stays the model asked for; the observed figures can
differ (a different-model review, a router). They are summed from the `session.usage_record` events in the
session log, `%USERPROFILE%\.copilot\session-state\<session_id>\events.jsonl` (`totalNanoAiu` / 1e9), read once
and streamed. If the log is missing the keys are left out (never null) and the host log gets `usage-missing`;
a log problem never fails a finish. The keys are additive, so the envelope stays `"v": 1`. A Claude Code
worker reports its own cost figures instead (`usd`, `by_model_usd`), never added to `aic`.

**`pushed: wip` and `wip_branch`.** Before posting `finished`, `failed`, `timed-out` or a `wh stop`
`interrupted`, while the clone is still there, the host inspects the worker's clone (only the one it prepared
for this task: `.ds-worker.json` names this worker and clone, and `state.json` records the task for it). If the
working tree has uncommitted changes or the current branch has commits not on origin, it commits the tree
(`git add -A`, message `WIP (timeout): <worker> <task_id>`, or `WIP (exit)` for any other end, with the trailer
`Worker-Host: wip`, using the clone's own git identity) and pushes that branch to origin (never forced, 120 s
timeout). The envelope then carries `"pushed": "wip"` and `"wip_branch": "<branch>"`. On `develop`, `main`,
`master` or a detached HEAD nothing is committed, the envelope says `"pushed": "no"` and the host log has
`wip-skipped reason=on-<branch>` (or `detached-head`). A failed commit or push is logged (`wip-failed`,
`wip-push-failed`), never raised, and the envelope says `"pushed": "no"`: the finish always posts. A clean
tree already on origin is left alone and `pushed` is what it was before (on `timed-out` and `interrupted`,
absent). Additive keys: the envelope stays `"v": 1`.

**Validation of a task**, in order; the first failure refuses (posted) or ignores (not posted):

1. Sender: the message's `agent_id` **and** `agent_name`, as returned by the bus, equal a trusted
   coordinator (above). Text in the body that claims a sender is meaningless.
   Wrong sender: ignored and logged, never answered (no oracle for a stranger). Kind not
   `question`: ignored. No coordinator trusted: everything is ignored.
2. Shape: JSON object, known keys only, every field passes its rule above.
3. Age and replay (new tasks; a resume re-validates everything else): seq not already in the host's handled list; `created_at` within 2 hours;
   `task_id` not already finished, failed or timed out here (kept 30 days). On a first start with
   no cursor the host begins at the newest message, so history is never replayed.
4. Vault (the sending coordinator's notes repository): a fresh `git fetch` of `main` succeeds (no fetch, no new task); `git rev-parse <commit>^{commit}` equals the commit;
   `git merge-base --is-ancestor <commit> origin/main` (a commit on a side branch or a PR ref does
   not run); `git ls-tree <commit> -- <brief>` shows a regular blob (mode `100644`, not a symlink or
   submodule) of at most 24 KB of UTF-8. The blob is copied to the host's state folder with its
   blob SHA; that copy, not the vault, is what runs and what any later resume re-uses.
5. Resources (section 5).
6. Uniqueness: no worker of that name running or reserved here (a per-worker lock taken before
   claiming), and no `started` for that worker or `task_id` from any host in the last 24 hours
   without a terminal reply (`finished`, `failed`, `timed-out`, `interrupted`) from **the same
   host identity** with the same `task_id`.

Executable-looking text (`; rm -rf`, `$(...)`, backticks, `&&`, a leading `-`, a flag as a model
name) fails step 2. Even text that passed could not run: every process gets an argument list (no
shell), git puts `--` before paths, and the prompt is a **fixed** preamble plus the brief blob; the
worker reads its identity, repository and branch from `.ds-worker.json` (written by the host,
git-excluded), so no message-derived value is part of the prompt.

## 4. Claim protocol

1. Coordinator posts a task (seq *T*).
2. Each host that passes validation and has room posts `claim` replying to *T*. A loaded host waits
   `2 s × running workers` first, so idle hosts tend to win. A host named in `host` claims alone.
3. Each claimer waits the **settle window** (default 20 s, at least twice the poll interval), then
   re-reads every reply to *T*. Claims count only if they carry the same `task_id` and digest and
   come from a known host, pinned by `agent_id` and name (the signed fleet's hosts, or before it the config
   `[[hosts]]` list; a retired host is removed), so a stray identity can at worst delay a task, never take it.
   `wh enrol` prints the entry for a new host, e.g. `[[hosts]]` `agent_name = "host-a-host"`, `agent_id = "<uuid>"`.
4. The claim with the **lowest seq wins**. The winner re-checks resources and that no `cancel`
   arrived, posts `started`, and launches. Losers post `yield` and release their reservation.
5. If the re-read fails, the host does **not** start (fail closed) and posts `yield` when it can.
   If the winner cannot start after all (resources changed), it posts `refuse`; the coordinator
   re-posts the task. The coordinator treats "no `started` within 5 minutes" the same way.

**Where it can still double-run.** (a) The bus may make a lower-seq claim visible *after* a higher
one if inserts commit out of seq order; a host whose re-read ran in that gap starts too. The settle
window makes this unlikely, not impossible. (b) A host loses the bus after posting `started`, the
coordinator sees silence and re-posts; the original worker is still running. (c) Someone re-posts
a task with a new `task_id` while the first still runs. (d) A configured host identity posts a
false terminal reply; this needs that host's credential, which any worker on that host can read
(section 12). In each case two workers run the same brief on the same branch, on different
machines. **Consequence:** duplicated compute and interleaved commits on one branch. Because
workers never force-push, the slower one's push is rejected and it must pull or rebase, so nothing
is overwritten, but the history and the PR can be confusing. Step 6 of validation catches (b) and (c) while the original host is still
posting. The real fix is a bus-side compare-and-set claim (open question 4). On one machine there
is no race: a named Windows mutex allows one host process, and `state.json` is changed only under
an inter-process lock.

## 5. Resources

Checked before claiming and again before starting. A task that would break a rule is refused with
the reason posted; nothing is queued silently (the coordinator re-posts when it chooses).

| Rule (config) | Default | Meaning |
|---|---|---|
| `max_workers` | 12 (128 GB) / 6 (64 GB) | Concurrent workers on this machine; `install.ps1` picks 12 at 96 GB installed or more, 6 at 60 GB or more, otherwise 2 and asks the owner to set it |
| `max_commit_pct` | 80 | Refuse if (committed + `worker_commit_gb`) / commit limit would exceed this |
| `min_free_ram_gb` | 6 | Refuse if free physical memory minus `worker_commit_gb` would be below this |
| `worker_commit_gb` | 8 | Expected commit per worker (the agent and its tests); tune per machine |
| `min_free_disk_gb` | 40 | On the workers-root drive; below it, idle-clone clean-up runs first, then refuse |
| `guard_commit_pct` / `guard_free_gb` | 85 / 6 | Two samples a minute apart over the line: stop claiming and post `pressure` (running workers are not killed) |
| `pause_while_running` | `[]` | Process names (games, say; the owner supplies the list) that **pause** the host while any runs: no new claims (refused `game`), running workers continue; it resumes when they exit |

Numbers come from `GlobalMemoryStatusEx`. **Heartbeat**
cadence is config: every `heartbeat_running_minutes` (10) while a worker runs, `heartbeat_idle_minutes`
(60) while idle, and at once on a `status` message, one line: `host=dev128 state=running workers=2/6 commit=54% ram_free=71.2GB
disk_free=412GB cpu=38% cpu_max=91% ghcp=1.0.95 model=claude-opus-5.5 models=claude-*,gpt-*,gemini-* clones=14
held_clones=1`. `clones` is counted on disk (every folder with `.git` under the workers root), `held_clones` is how
many of them are held (section 11), and `strays=N` is added when folders without `.git` are there.

`cpu` and `cpu_max` are the average and peak CPU busy share across all processors since the previous heartbeat. Each
reading is `GetSystemTimes` over the ~30 s sample interval; a forced sample less than 5 s after the last is skipped.
They are for **monitoring only**: CPU never refuses a task. On a host with many workers memory can stay well under
the commit limit while workers' builds and tests compete for CPU; these figures show that.
`status.json` has the latest reading as `cpu_pct`.

## 6. States

```
            wh start / boot (if enabled)
 stopped ───────────────────────────────► idle ◄──────────────┐
    ▲                                      │ claim posted      │ lost race / refuse
    │                                      ▼                   │
    │                                   claimed ───────────────┘
    │  last worker ends                    │ won, started
    │                                      ▼
 draining ◄──────── wh drain ────────── running (1..max workers; may claim more)
    ▲                                      │ last worker ends → idle
    └────────── wh drain (from idle or claimed: straight to stopped, claims yielded)
 any state ── wh stop ──► stopped (workers killed)
```

`claimed` and `running` can co-exist with spare capacity; the reported state is the busiest one.
**Paused** (`wh pause`, or a `pause_while_running` process) is a flag over these states, reported as
`paused(running)`: new tasks are refused with `paused`/`game`, running workers continue, and
nothing stops when they finish (unlike drain); `wh resume` or the game exiting clears it.
Maintenance (CLI update, self-update) is a sub-state of `idle` in which claims are refused with reason
`maintenance`. `stopped` is persisted with an *enabled* flag: `wh stop` and a completed drain
disable the scheduled task, so a reboot does **not** bring the host back (for a machine that is also used for
other things); `wh start` enables it again. If the host was enabled, a reboot brings it back with no command.

Per task: `seen → refused | claimed → yielded | started → finished | failed | timed-out | interrupted`.
The task table, cursor, default model and enabled/drain flags live in `state.json`, written
atomically (temp file and replace) at every transition. A terminal status (`finished`, `failed`,
`timed-out`, `interrupted`, `refused`) is written **before** its reply is posted, so a crash between
the two leaves the task terminal, never running, and a restart cannot report it again.

## 7. Commands the owner runs

| Command | Does |
|---|---|
| `install.ps1` | Folders, config from the template and the site file (`-SiteFile`, a copy of `site.example.toml`; needed for a new install), scheduled task (in Password mode asks for the Windows password once, passes it to Task Scheduler, keeps no copy), then a probe run *through the task* that checks the agent CLI, `gh auth status`, `git ls-remote` of the vault and the bus CA. `-PinSigners` (elevated) pins the signing keys. |
| `wh enrol` | Prompts (hidden input) for the SPN credential once, stores it, onboards and bootstraps the host identity `<agent_prefix>-host` (e.g. `host-a-host`), subscribes it to `worker-hosts`, and pins the `[coordinator]`'s `agent_id` (before the first signed fleet). |
| `wh pin --coordinator-id <uuid>` | Pins the `[coordinator]`'s `agent_id` again. |
| `wh start` | Enable the task and start it. |
| `wh drain` | No new claims; running workers finish; then post `stopped`, disable, exit. |
| `wh pause` / `wh resume` | No new claims, running workers continue, the host stays up / accept again. |
| `wh stop` | Stop now: kill every worker, post `stopped`, disable, exit. Answers within 30 s, else kills the host process. |
| `wh status` | Local: state, workers (name, task, model, minutes, log path), resources, held clones. `--post` sends a heartbeat. |
| `wh update-ghcp` | Section 10. Refuses while workers run; `--when-idle` drains, updates, and resumes accepting. |
| `wh update status` / `check` / `now` | Section 10a. |
| `wh set-model <model>` | Change the host default (must be in `models.allowed`). |
| `wh cleanup` | Run the clean-up rules now (section 11); `--dry-run` lists what would go. |
| `wh fleet status [--refresh]` | The pinned signing keys and the signed `fleet.toml` this host accepted (`agent-host-build.md` 7.2); `--refresh` checks main now. |
| `wh fleet entry --host` / `--coordinator ...` | Prints a `fleet.toml` entry for a PR (changes nothing). |
| `wh openbao ...` | Host secrets in OpenBao: `status`, `enrol`, `renew`, `seed-spn`, `rotate-spn`, `migrate` (section 12). |
| `wh panel` | The desktop status window (`workerhost/panel.py`): reads `status.json` and `state.json` only, buttons run the `wh` commands above. `install.ps1` starts it at sign-in from the Startup folder (`-NoPanel` to skip). |

Local commands talk to the running host through a control file in the owner-only state folder, so
they work whether or not the host is mid-poll and survive a restart.

## 8. Launching a worker

`gh repo clone` on first use (else `git fetch`), check out the branch
(track `origin/<branch>` if it exists, else create from `origin/HEAD`: a new feature branch;
`main`/`develop` are refused in section 3), onboard and bootstrap
`<agent_prefix>-<worker>` on first use, then `copilot -p <preamble + brief> --allow-all-tools --no-auto-update
[--no-custom-instructions] --add-dir <home>\app --model <model>` (with `--resume=<id>` for `resume`),
`COPILOT_TASK_WAIT_TIMEOUT_SECONDS=3600`, `gh` on PATH. `--no-auto-update` keeps the CLI at the version the host installed: only the host changes it, with
winget in its own window when no worker is running (section 10), so one worker can never swap the version under the
others mid-task. A Claude Code task (`"engine": "claude"`) runs `claude -p` with the same prompt, clone and identity
(`workerhost/engines.py`, `agent-host-build.md` 7.6).

**The preamble.** Every task gets the same fixed preamble (`workerhost/prompt.py`, `PROJECT_PREAMBLE`). It names the
project, the coordinator, its notes channel and the owner, whose decision merging is. These come from the sending
coordinator's signed fleet.toml entry and the fleet's signed top-level `owner` (else "the owner"); before the first
signed fleet, from config.toml `[coordinator]` (`project`, `notes_channel`, `owner`). The coordinator's
`worker_rules` follow under "Project rules". Nothing in it comes from a bus message.

`--no-custom-instructions` is added when the task says `"repo_instructions": false`. The coordinator decides per
task:
- **Loaded, the default.** The CLI reads the repository's `AGENTS.md`, `.github/copilot-instructions.md` and the
  like. These often hold project rules the preamble does not (for example, which systems a worker must never write
  to).
- **Off.** For a repository whose instructions have grown into process heavier than the product, the coordinator
  turns them off for that task. The preamble, the coordinator's `worker_rules` and the brief are then the worker's
  only instructions.
- **Not a security boundary.** The worker runs the repository's own build and tests anyway; the fence is which
  repositories a coordinator may task (`agent-host-build.md` 7.3).
- **Either way, the preamble keeps the worker to its brief.** It says: "Your brief is your whole task … do not pick up
  further work from NOW.md, a backlog or a queue". Some repository instructions say "take the next task; do not
  wait for the owner".
- **Per project:** a coordinator's fleet.toml entry sets its default (`repo_instructions`) and its always-rules
  (`worker_rules`), which go into its workers' preamble, so "off" never drops a safety rule.

`started` reports `repo_instructions`, so the coordinator sees which way the worker ran.

`--add-dir <home>\app` is there because the bus client the preamble names lives under
`<home>\app`, outside the worker's clone: the CLI treats a shell command that names a path outside its
working directory (and the folders it was given) as needing approval, which `--allow-all-tools` does
not grant, and a worker has no one to approve it, so without it every bus post was refused ("Permission denied
because no interactive user response was available"). Only that one
folder is added. `--allow-all-paths`/`--allow-all` would give the worker the whole machine and are
never passed. The workers root is not added either: checked on CLI 1.0.95, the CLI does refuse the
clone's parent, but the worker needs nothing there (its `TEMP` under `<workers_root>\tmp` is
allowed because the CLI allows the temp folder), and adding it would expose every other worker's
clone. For a resume the host re-reads the original task message from the bus by seq, re-validates it
and re-reads the brief from the vault at its commit (it does not trust its own saved copy), and uses
a session id only if the session record shows this worker's clone as its working directory;
otherwise it starts fresh. The prompt goes on the command line (the
Copilot CLI takes `-p` only; a brief that would exceed the 32 K command line is refused `brief`), so
briefs (which live in git) must hold nothing secret. If the brief names other vault files by
relative path, the pinned commit is exported read-only (`git archive`) and its folder is given in
`.ds-worker.json`, never in the prompt. Each worker runs in a
Windows **Job Object** (killing the host kills its workers, and `wh stop` is one call); each gets
its own `TEMP`/`TMP` under `<workers_root>\tmp\<worker>-<seq>`; the worker's output is streamed into
its log through a redaction filter (bus `sb*1_` secrets, GitHub token prefixes) rather than written
raw; `.ds-worker.json` is listed in the clone's `.git/info/exclude` and kept by clean-up
(`-e .ds-worker.json`); the preamble points at this
repo's bus client, and the environment carries the worker's credential: `SB_BUS_STORE` (the DPAPI store) or, with
OpenBao, `SB_BUS_TOKEN`. The model actually used is written in the log header and in `finished`.

**Checkpoint notes.** A worker is one non-interactive run, but the coordinator can amend its brief
while it runs. The host gives every worker these environment variables: `SB_TASK_SEQ`,
the seq of the task message (also recorded as `seq` in the task's `state.json` entry, so a resume
after a reboot keeps the original value), `SB_COORDINATOR_ID` / `SB_COORDINATOR_NAME`, the coordinator that
sent the task, `SB_NOTES_CHANNEL`, its notes channel, and `SB_PROJECT`. The host never inherits these from its own environment. The bus client's
`notes <agent>` command reads the notes channel from that seq (bus seqs are global across channels). It
keeps only messages whose bus-authenticated sender matches the coordinator on both id and name and whose
body opens with mentions including `@<agent>`. It prints them oldest first with their seqs, or
`no notes`. It counts messages that name the worker but come from another sender, and coordinator
messages that only quote the name, as ignored. It never posts, and it fails closed when a variable
is missing. The preamble tells the worker to run it before it
opens or updates its PR and before its final report. A note wins over the brief, but it can never
lift a hard rule. The final report says which notes were read and what was done about each.

Hosts normally upgrade themselves (section 10a). By hand: `wh drain`, wait for `wh status` to say
`host not running`, `git pull` the source clone, re-run `install.ps1` with the same `-Logon` as
before (it keeps `config.toml`), then `wh start`. A restart ends running workers, so never upgrade
by hand while one runs.

## 9. Running as the owner: scheduled task, not a service

The Copilot, Claude Code and `gh` sign-ins are the owner's and live in that Windows profile, so the host must run
under that account. **Chosen: a scheduled task**, in one of two logon modes (`install.ps1 -Logon`, recorded as
`logon_type` and shown by `wh status`), both with network required, restart on failure every
minute (999 times, the Task Scheduler maximum), no execution time limit, single instance. That
restart covers only a task that fails to launch, not an action that exits non-zero, so the action is
`wh.py supervise`: it runs `wh.py run` as a child in a kill-on-close job object and
restarts it after a non-zero exit (10 s, 30 s, 60 s, then every 5 minutes; back to 10 s after ten
minutes up), logging each restart. Exit code 0 (`wh stop`, `wh drain`, disabled), exit code 3
(another host holds the home) or `enabled = false` in `state.json` end the supervisor instead. Exit code 75 is a
self-update (section 10a). Ending
the task ends the supervisor, its job ends the host, and the host's jobs end the workers. One
supervisor per home (its own mutex); the host keeps its single-instance mutex:

- **Password** (default; a local account with a password): trigger *At
  startup* (2-minute delay), *Run whether user is logged on or not*, logon type Password (not S4U:
  S4U has no password, so DPAPI user keys and Credential Manager, where the sign-ins are kept, are
  unavailable). The owner gives the Windows password once to Task Scheduler; after a change,
  `install.ps1 -UpdatePassword`. The install probe runs through a task with the same logon.
- **Interactive** (Entra ID accounts with Windows Hello for Business, which have no password to
  store, such as a personal PC or laptop): trigger *At log on* of the installing user (1-minute delay),
  *Run only when user is logged on*, no stored password. The task runs in the signed-in session, so
  DPAPI and the sign-ins work; after a reboot the host comes back once the owner signs in. The install
  probe runs in the installing session.

Not a service: it needs a wrapper (`pywin32` or NSSM) and the *Log on as a service* right, and a
disabled task keeps a shared machine quiet after a reboot. **The owner supplies at setup:** the site file, the
Windows password once (Password mode only), the SPN credential once (`wh enrol`), and the existing
agent CLI and `gh` sign-ins on that machine.

## 10. GHCP update

A maintenance action, run daily inside a configured window (default 04:00 to 06:00) and by `wh
update-ghcp`, **only when no worker is running** (otherwise retried every 30 minutes inside the
window, never by stopping workers). The Copilot CLI self-updates in place: `copilot.exe` in winget's
`Links` folder is usually a real file, newer than winget's record, sitting beside `copilot.exe.old-*`
leftovers, a `.copilot-update-*` marker and unrelated portables (terraform.exe and the like). winget's
view can therefore be stale. Steps: record `copilot --version`; read winget's available version
(`winget list --id GitHub.Copilot --exact`) and skip when the live CLI is newer or equal (`ghcp update:
1.0.95-3 newer than winget 1.0.94, skipped`); copy `copilot.exe` and its `copilot*` companions (not
`.old-*` leftovers, not other files) from the folder that holds the real binary to `ghcp-backup\`;
`winget upgrade --id GitHub.Copilot --exact --silent`; run `copilot --version` and a `copilot --help`
smoke test. **The updater never deletes anything** in that folder. On failure a binary that still
answers is kept as is; only a missing or broken one gets the backed-up files copied back over it, then
re-tested. Posts one line: `ghcp update: 1.0.95 -> 1.0.96 ok` or `... failed (exit 1), kept 1.0.95`.
After a failed update the heartbeat and `wh status` line carry `ghcp_ok=False` until the next good
version read.

## 10a. Self-update from signed releases

Hosts update their own code from signed releases, in one nightly window. They announce it first and never
interrupt work without saving it. Code: `workerhost/update.py`; also the host
(`update_tick`), the supervisor's rollback, and `tools/make-release.py` / `tools/sign-config.ps1`.

**A release is `release.toml` on main, signed with a hardware key** (`release.toml.sig`, namespace
`strugglebus-release`, checked against the same pinned `allowed_signers` as `fleet.toml`; any principal listed for
the namespace may sign):

```toml
serial = 3                  # one more than main's, every time (sign-config.ps1 refuses anything else)
version = "2026.11.06"
commit = "<40 hex>"         # the code hosts install: a commit on main
tree_sha256 = "<64 hex>"    # sha256 over "<sha256 of file>  <path>" for each installed file at that commit
needs_install = false       # true: hosts announce it, but install.ps1 is run by hand
notes = "one line"
```

The installed files are the ones `install.ps1` copies: `wh.py`, `config.template.toml`, `README.md` and
`workerhost\*.py`. The hash is over the files themselves, not git's objects, so it does not depend on the git version.

**Making one:**
1. `python tools/make-release.py` takes origin/main (or `--commit`), computes the tree hash the way hosts do, and
   writes `release.toml` with serial + 1. The version is the commit date, `YYYY.MM.DD` (`.2` for a second release
   that day). The notes are the commit subjects since the last release. It opens the PR "release … (to be signed)".
2. The owner signs and merges it with `tools/sign-config.ps1 -Pr <n> -KeyFile ...` on a signing PC. After the merge it
   also creates the GitHub Release `v<version>` for people to read; hosts never read that page.

**On every host, nightly** (config.toml `[update]`, local time; they move to the signed baseline later):

| When | What the host does |
|---|---|
| `check_at` (01:00) | Fetches its repository mirror (the one it keeps for `fleet.toml`) and verifies `release.toml`. If it is newer than what is installed, the host posts on the **announce** channel (kind `announce`), `@`-mentioning every coordinator in the fleet: "host X updates from A to B at 03:00 (by 03:30 at the latest) …". It posts the same as status on its own channel. **From then on it refuses new tasks** (`maintenance`). |
| `window` (03:00) | No worker running → apply. |
| `window` + `grace_minutes` (03:30) | Workers still running: push each one's work to its branch (as a timeout does), stop it, mark it `update_stop`, then apply. After the restart, each such task is reported `interrupted` (cause `update`) and **resumed once**, as after a reboot. |
| an hour after the grace, not applied | The host was off or asleep. It takes tasks again, and the next check announces it again. |

**What "newer" means:** the release's serial is above the installed one (`<home>\app\RELEASE.json`; a hand install
is `manual`, serial 0) and its commit is not the installed commit.

**Applying:**
1. Read `release.toml` and check its signature again.
2. Read the files at `commit` from the mirror and refuse them unless they hash to `tree_sha256`.
3. Stage them in `<home>\app.new` and run the staged code's `wh selftest`: every module imports, `config.toml` loads,
   and the kept `fleet.toml` parses.
4. Copy the current files to `<home>\app.prev`.
5. Write the new files over `<home>\app` **in place**. Processes keep `app` as their working folder, so the folder is
   never renamed. Modules the release no longer has are removed.
6. Record `applied` in `<home>\state\update.json` and exit with code **75**.

**Restart and rollback:**
- The supervisor restarts the host **at once** on the new code.
- The supervisor keeps running the code it started with, which makes it the rollback. If the new host then fails 3
  times in a row, each within the supervisor's stable period (10 minutes), the supervisor puts `app.prev` back and
  records `rolled-back`. That release is never retried on this host.
- The new host, once it has run 3 minutes with the bus reachable, records `done` and announces "updated from A to B;
  taking tasks again". A rollback, or an update that was not applied (signature, tree, selftest), is announced as well.
- The supervisor's own code changes at the next start of the scheduled task (a reboot or `wh start`).

**By hand:**
- `wh update status`: what is installed, the window, and the update in progress.
- `wh update check`: fetches and verifies now, and changes nothing.
- `wh update now`: announces a newer release and applies it as soon as no worker is running, without waiting for the
  window.

**Not covered:** a release that changes what `install.ps1` sets up (the scheduled task, the panel shortcut, config
keys a host must have) carries `needs_install = true`. Hosts announce it and wait for `install.ps1`.

## 11. Clean-up

After each worker ends its temp root is deleted. Its clone is cleaned (`git clean -ffdx`) only
when the run `finished` with exit 0, the unpushed-commit check below passes, and any untracked
non-ignored files fit in a zip in `salvage\` (cap 50 MB, kept `salvage_days`); their names are
logged. Otherwise (failure, timeout, `stop`, `interrupted`, salvage too big) the clone is held as
it is for resuming or for the owner to inspect; a new (non-resume) task for that worker is refused
`clone-dirty` while it holds uncommitted or stashed work.

The sweep runs every `sweep_hours` (6), and at once on disk pressure. It runs inside the host loop, so
it stops after `sweep_budget_minutes` (5); whatever is left is counted `deferred` and the next sweep comes
15 minutes later, until the backlog is gone. `wh cleanup` with the host stopped has no budget. It deletes worker logs older
than `log_retention_days` (14), `pytest-of-<user>` roots under the system temp older than 2 days, run
temp roots under `<workers_root>\tmp` older than 2 days, and clones once idle:
- a clone whose worker's latest task `finished` with exit 0 and was cleaned: after
  `finished_clone_hours` (12). It is kept that long only so a follow-up task can reuse it;
- every other clone (failed, timed out, stopped, or older than the host's ledger): after
  `idle_clone_days` (7);
- on disk pressure, every clone, oldest first.

Every folder with `.git` under the workers root is a clone for the sweep, with or without the meta
file. A folder without `.git` (other than `tmp`) is a **stray**: what a failed clone or a delete that
stopped half way leaves. Nothing can show a stray is safe, so it is never deleted, only listed in
`wh status` and counted in the heartbeat, except one the host itself was deleting (its name is kept in
`delete_failed` in state.json): that is deleted again at the next sweep.

A clone is deleted only if, **after a successful `git fetch origin`**: no worker uses it;
it has no uncommitted work; `git stash list` is empty; and `git rev-list --branches --not
--remotes=origin` is empty (every local commit is on the remote). Squash-merged branches whose remote
branch was deleted fail that last test; they pass only if `gh pr list --head <branch> --state merged`
shows a PR whose head commit equals the local branch tip. Anything else is held, with its reason, and
counted in the heartbeat (`held_clones`). If the fetch fails, nothing is deleted.

**Uncommitted work** is every entry of `git status --porcelain --untracked-files=all` except the meta
file and a tracked file whose only change is its line endings (` M` in status, nothing in `git diff
--ignore-cr-at-eol`). A file committed with CRLF while `.gitattributes` says `eol=lf` shows as modified in
every fresh checkout on Windows; without this rule every clone of such a repository would be held for ever, and the
WIP save would push a commit renormalising it. The same rule decides `clone-dirty` and whether the WIP save commits
anything.

**Deletes reach long paths.** Every delete uses the `\\?\` extended-length form of the path, so it works
past 260 characters with `LongPathsEnabled` off (the Windows default). Without it, pytest trees inside run
temp roots (paths up to 274 characters) fail to delete without an error, and temp roots pile up while the log
says they were deleted. A delete that leaves anything is
logged `action=failed`, never `deleted`. Each sweep ends with one `cleanup-done` line: clones on disk,
held, deleted, failed, strays.

## 12. Credentials

`wh enrol` stores the SPN credential with DPAPI (`CryptProtectData`, current user) in an owner-only
file. Each `<agent_prefix>-<worker>` is onboarded on first use with that SPN, exactly as `bus.py onboard`
does, and its credential stored the same way; the worker's bus client decrypts it by agent name.
**Bus fact:** an SPN credential creates only agents named `<SPN name>-*`; any
other name is refused with 422 "agent name is outside the SPN prefix". This is the bus's current
form of scoped issuance, and why `agent_prefix` must equal the SPN's name (SPN
`host-a` creates `host-a-host` and `host-a-<worker>` only).
Nothing secret goes on a command line, in a log or on the bus. The one environment variable that carries a
secret is a worker's own `SB_BUS_TOKEN` (OpenBao hosts only, below).

Honest limit: DPAPI-current-user protects against other accounts, a copied disk or a backup; it
does **not** protect against processes running as the host's account, and every worker runs as that account with
all tools allowed. A worker can therefore read the SPN and other workers' credentials, as it can read
any owner-only file. The same holds for the host's own state, logs and saved briefs: a
worker can rewrite them, which is why a resume re-validates from the bus and the vault rather than
from state. None of this is a boundary against a worker that misbehaves: it already runs as the owner
with all tools, so it does not need the host to run anything. The host's job is narrower: never let
a *message* choose what runs. Real isolation (per-worker Windows accounts) is not built (section 15).
The prefix limits *which names* a leaked SPN can create, not how long it is valid.

**OpenBao (optional, `[openbao]`).** The SPN, the host credential and live worker credentials can live in OpenBao
instead of DPAPI. The host then keeps only a LAN-CA leaf certificate, and workers get their credential in
`SB_BUS_TOKEN`. Phase 2 (`[openbao] ttl_identities`) gives each task attempt its own bus identity, retired when the
task ends, so a leaked worker credential is worth one task. See [openbao-design.md](openbao-design.md).

## 13. Logs and posts

| Where | What |
|---|---|
| `%LOCALAPPDATA%\strugglebus-worker-host\logs\host-YYYYMMDD.log` | Every message considered (seq, sender, type, decision, reason code), claims, launches, exits, clean-up, updates. Never message free text, never secrets. Kept 30 days. A caught or fatal error is logged with its exception type and sanitised message. |
| `%LOCALAPPDATA%\strugglebus-worker-host\logs\host-YYYYMMDD.errors.log` | One timestamped block per error (loop errors, the fatal error before the process exits, supervisor spawn errors): the redacted traceback. Kept 30 days. |
| `<workers_root>\<worker>.log` | The worker's output, plus a header: task seq, brief path, vault commit, blob SHA, model, CLI version, host. |
| `state.json`, `salvage\`, `ghcp-backup\` | State folder, owner-only. |
| `worker-hosts` channel | Claims, refusals, started/finished, heartbeats, pressure, CLI updates. |
| The coordinator's notes channel | Nothing from the host; workers post status there and read their notes there. |
| `security` channel | Changes to `[models]` (section 3). |

## 14. Failure handling

- **Worker that never finishes:** `max_runtime_hours` (6). Warning posted at 80 %; at the limit the
  job is killed and `timed-out` posted. A log silent for 45 minutes posts a `stalled` note but is
  not killed. Before `timed-out` is posted the host commits and pushes the worker's tree as WIP (section 3,
  `pushed: wip`); anything it cannot push stays in the clone (clean-up rules hold it).
- **Host reboots or restarts mid-task:** on start, the sweep looks only at tasks `state.json` records
  as running (`started`) or as accepted but not started (`claiming`, `claimed`); terminal tasks are
  never re-reported. A task accepted or claimed but never started is marked `yielded` and then
  reported with a `yield` reply (reason `restart`), so the coordinator re-posts it; it is never
  silently dropped. A running task's worker is matched by
  its recorded pid and process start time (a reused pid is not the worker). It is normally already
  dead: its job object kills it when the old host's job handle closes. If it is still alive it is
  **killed, not adopted** (the new host holds no job handle or pipe for it, so it cannot supervise
  it); its work stays in the clone. Once the worker is gone the task is marked `interrupted` in
  `state.json` and then posted, exactly once (cause `reboot` or `restart`); if it cannot be killed it
  is logged and not reported. If `resume_after_reboot` is on (default) and the cause was a boot (boot
  time later than launch), the host resumes the worker once through the resume path of section 8
  (task re-read from the bus, brief re-read from the vault, session id checked); a second
  interruption waits for the coordinator. `wh stop` interruptions never
  auto-resume. **What is lost:** the agent turn in progress, and posts and PRs not yet made.
  Uncommitted edits and unpushed commits stay in the clone (clean-up holds it) for the resumed
  session to push. Pushed work is never lost.
- **Vault cannot be pulled:** three retries over a minute, then `refuse` with reason `vault`. A
  stale mirror is never used for a new task (a commit once on `main` may since have been removed).
  Persistent failure shows in the heartbeat.
- **Bus unreachable:** keep supervising running workers, claim nothing, back off to one poll a
  minute; `finished` posts are queued in `state.json` and sent when the bus returns.

## 15. Deliberately not built

Remote stop, drain or update over the bus; a queue on the host; running any agent but the Copilot CLI and Claude
Code; vault working trees for workers (briefs stay self-contained; at most a read-only export, section 8); Linux or
macOS; a web UI; moving or syncing lab data (a task needing data targets a host with that tag; no lab data or
secret ever enters this repository); per-worker Windows accounts; prefix-scoped credentials with a
TTL from the bus itself (today's prefix scoping is section 12; OpenBao phase 2 gives per-task identities).

## 16. Open questions

Settled: vault `main` need not be protected and briefs stay self-contained; the sender check and
the pinned commit are the gate, and the section 12 limit stands. The `worker-hosts` channel must exist (section 3).
Capacity starts at 12 workers on a 128 GB machine and 6 on a 64 GB machine, 8 GB each (section 5). Logon
is per machine, Password or Interactive (section 9). Open, built with config defaults:

1. (Settled: the channel exists before hosts start; section 3.)
4. Could the bus add a compare-and-set claim (first claim on a seq wins, server-side)? It would
   remove the double-run window in section 4.
5. (Settled.) Bus messages cannot be edited after posting; the bus makes them immutable as a
   safety measure. `messages_mutable = false`: no re-read before starting; the digest stays in
   every reply as a cheap cross-check (section 3).
6. The game list for `pause_while_running`, and any per-machine value other than capacity.
7. (Settled: Password on local accounts, Interactive on Entra ID with Windows Hello for Business;
   section 9.)
8. (Settled.) An SPN cannot create any name: the bus allows only `<SPN name>-*` and
   refuses others with 422 "agent name is outside the SPN prefix". Identities derive from
   `agent_prefix` (section 3). Still open: prefix-scoped host credentials with a TTL from the bus (section 12).
