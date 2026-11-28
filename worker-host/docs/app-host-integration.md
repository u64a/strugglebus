# The StruggleBus App as the worker hosts' command center: host-side spec

Status: **reviewed by the bus side and a security review (section 7: sound, with conditions M1 to M6, written
in). Stages A to D are built on the host side; the bootstrap's install steps are not.**
Agreed in outline with the bus side (24 Nov 2026). The owner confirmed the two open decisions:
- remote control is in the first release, subject to the security review;
- the host runs under a dedicated Windows account by default, and the person deploying can opt out.

## Goal

A new user installs StruggleBus, opens the Windows App and registers. From the App they:
- put a worker host on each Windows 11 PC on their LAN;
- see every host's state;
- add and sign coordinators;
- pause, resume, drain or update a host.

They never edit a file, run git or handle a secret. A host may have Copilot CLI, Claude Code or both.

## The stages (all four in the first release)

| Stage | What the user gets | Bus | App | Host (this repository) |
|---|---|---|---|---|
| **A** | Hosts page | nothing new | reads the status | **status JSON** (section 1) |
| **B** | Add a host | host enrolment code | Add-host screen, the .ps1 | **bootstrap, installer, enrol-with-code** (section 2) |
| **C** | Coordinators and signing | site document store | site key; add, sign, publish | **fleet from the bus** (section 3) |
| **D** | Pause, resume, drain, update | operator command post | sign and send a command | **signed commands** (section 4) |

The bus and App side is `docs/WORKER_HOST_COMMAND_CENTER.md` in the strugglebus repository. Where the two documents
disagree, it is a mistake to fix. Test vectors for the App: `tests/data/vectors/` (section 6).

The rules that do not change: a bus message is data, never a command; only signatures by keys pinned on the host by
an administrator carry authority; a host never moves backwards (fleet serial, release serial).

---

## 1. Status message (stage A)

**Where:** the host's channel (`channel` in config.toml, `worker-hosts` by default), kind `status`, from the host's own
identity (`<prefix>-host`). The **body** stays the readable heartbeat line, unchanged for anyone parsing it today. The
**metadata** carries one JSON object under the key `sb_host_status`, under 16 KB.

**When:** with every heartbeat (every 60 minutes idle, every 10 while a worker runs, and on a coordinator's `status`
request), and at once on a state change: started, paused, resumed, draining, sign-in lost or regained, update
announced, applied or rolled back, a command's result.

**Contract** (`v: 1`; additions keep `v` and are optional; a removal or a change of meaning raises `v`):

| Field | Type | Meaning |
|---|---|---|
| `v` | int | 1 |
| `host` | str | host_name: `^[a-z0-9]+(?:-[a-z0-9]+)*$`, at most 31 characters |
| `agent` | str | the host's bus name, `<prefix>-host` |
| `version`, `serial` | str, int | the installed release (`manual`, 0 for a hand install) |
| `started_at` | str | ISO 8601 UTC, when this host process started |
| `interval_s` | int | seconds until the next status message at the latest: how old the details may be |
| `state` | str | `online`, `paused`, `draining`, `needs-sign-in`, `needs-fleet` (not listed in the accepted fleet: takes no work), `updating`, `error` |
| `account` | str | the Windows user the host runs as; with `dedicated` (bool): whether the installer made it for the host |
| `engines` | list | per engine: `name` (`ghcp`/`claude`), `version`, `signed_in` (bool or null if unknown), `default` (bool) |
| `workers` | obj | `busy`, `max`, `claiming` |
| `held_clones`, `outbox` | int | clones kept for unsaved work; replies not yet posted |
| `fleet` | obj | `source` (`bus`/`git`/`config`), `serial`, `coordinators` (agent names), `state` (`accepted`, `legacy`, `unavailable`) |
| `update` | obj or null | `version`, `when` (a time, or `idle`) for an announced release |
| `release` | obj | `source`: where releases are read from, either `fleet` (the fleet repository, as before) or `<repository URL>#<folder>` (set in config, or by a signed redirect); `serial`: the installed release's serial. Added 25 Nov 2026, additive. A site's monitoring should alert on a change of `source` |
| `last_command` | obj or null | stage D: `nonce`, `verb`, `result` (`done`, `refused`), `reason` code |
| `problem` | obj or null | `code` (a fixed list, below) and `text` (one plain sentence) |
| `warnings` | list | standing conditions, present for as long as they hold, unlike `problem` (M6): `not-dedicated` (workers run with the operator's whole account), `isolation-weak` (the isolation check found something the host's account can write) |

`problem.code` is one of: `bus-unreachable`, `channel-missing`, `fleet-unavailable`, `sign-in-needed`, `disk-low`,
`memory-high`, `update-failed`, `rolled-back`, `leaf-expiring`, `openbao-unreachable`, `engine-missing`,
`release-source-unreachable` (added 25 Nov 2026: the release source can't be reached, so the host stays on its
current version), `release-redirect-refused` (added 25 Nov 2026: the installed release names a source outside the
host's allowed remotes, so the host ignores it and uses the fleet repository).

**Never in it:** a token, credential, path, URL with credentials, repository content, brief text, or message text.
The App treats every field as untrusted display data, **rendered as plain text, never as markup** (S3). It shows each
warning on the host's row for as long as it is present (M6).

**Alive or not** comes from the bus, not from this message: the bus records when `<prefix>-host` last made an
authenticated call, and an idle host calls every 10 seconds (`poll_seconds`, its read of the channel). The App shows a
host as alive when it was last seen under 90 seconds ago. Everything else comes from the latest status message. A host
that cannot reach the bus shows as not alive, which is correct from the App's side.

**Host work:**
- `Host.status_json()` built from what `write_status` and `heartbeat_line` already gather;
- `post(..., metadata=)` on the bus client;
- engine sign-in checks: `copilot` and `claude` report a signed-out state without a network call where they can;
  otherwise `null`;
- tests that the JSON never carries a path or a secret.

---

## 1a. The Hosts dashboard: status pushed to the bus (v2)

Agreed on #humans, 27 Nov 2026: Chris's decisions; the design (28827); u64-security's review (28828); bus-dev's
changes (28832). The App gets a top-level **Hosts** page (beside Monitor, Humans and Admin). It's a dashboard of what
each host is doing, as the desktop panel shows it, with 12 hours of history for performance reporting. Admin, Worker
hosts stays for admin work.

**The heartbeat in section 1 does not change.** The heartbeat message, its body and its v1 metadata stay exactly as
they are: coordinators read them to decide whether to send work. This API is an addition, for humans.

### The calls

| Who | Call | Notes |
|---|---|---|
| The host | `POST /api/hosts/status`, body: the v2 snapshot | As **its own bus identity**. At most 16 KB, at most one push per 10 s |
| The App, any enrolled device | `GET /api/mobile/hosts/status` | The latest snapshot of every host, filtered as below, each with the bus's `received_at` |
| The App, any enrolled device | `GET /api/mobile/hosts/{agent_id}/status/history?since=` | Up to 12 hours of **samples** (below), not whole snapshots |

**The bus (bus-dev, the release with schema 25):**
- **Which host a row belongs to comes from the authenticated agent, never from the body.** The `host` and `agent` in
  the body are display data.
- **Only an agent with the bus's own host flag may write.** It's set by a host enrolment code (0.2.72), and for hosts
  enrolled before that, by a one-off admin action in the App (operator device plus Hello, audit-logged, with a
  matching "no longer a host"). The `host-*` name prefix never counts. A push from any other agent is refused (403).
- **The bus stamps `received_at`,** and liveness (online, stale, offline) comes from it, never from the host's clock.
- **Storage:** the latest snapshot whole, and every push kept for 12 hours, older ones deleted.
- **Checks:** the schema, string lengths, 16 KB, and one push per 10 s (429).
- **Audit:** every write gets an audit line with the agent, the outcome and the size.

**Who sees what.** The bus filters when it reads; the host always sends everything:
- **Admin only** (`POST /api/mobile/admin/hosts/status` with the device's grant in the body, the same answer
  whole): `account`, `dedicated`, `warnings`, `bus.channel` and
  `bus.channel_state`; and, added later and **may be absent**: section 4a's `sign_in`, `sign_in_key` and
  `claude_token_since`, and **`signers`** (u64-security, #humans 29197 item 4): the keys this host pins, as
  `[{fingerprint, key_type, namespaces}]` (at most 16; never the key or its name), so the App can warn when its own
  signer set and a host's differ. A backup key registered after a host was installed reaches it only by a re-pin on
  that host. Together the first three map the weakest machine. A host's channel may be private, and a
  device has no per-channel visibility yet.
- **Every enrolled device:** everything else, coordinator names included.
- **Never in it at all:** task ids (they can reveal tasks on channels the reader can't see), file paths, repository
  or clone names, task or message text, tokens.

### The snapshot (v2)

v2 is the whole v1 object (section 1), with `v: 2` and these additions:

| Field | Type | Meaning |
|---|---|---|
| `workers.running` | list | One entry per running worker: `slot` (the worker's name on the host), `engine` (`ghcp`/`claude`), `model`, `minutes` running. `workers.busy`, `max` and `claiming` are as in v1 |
| `machine` | obj | `cpu_pct`, `ram_free_gb`, `disk_free_gb`, `commit_pct`: one decimal, `null` while not yet measured |
| `bus` | obj | `state` (`ok`, `down`, `unknown`), `channel`, `channel_state` (`ok`, `missing`, `unknown`) |
| `model` | str | The default model |
| `ghcp_ok` | bool or null | Whether the last Copilot CLI update worked (`null`: none tried) |
| `tasks` | obj | How this host process's tasks have ended since `started_at`: `finished`, `failed`, `timed-out`, `interrupted`, `refused`, `yielded`, `cancelled`, always all seven. Running totals: a chart takes the differences, and a new `started_at` means they started again |
| `pwsh` | str or null; **may be absent** | PowerShell 7's version (`7.6.10`), asked once an hour; `null` if it can't be found or run. Added after v2 was agreed (u64-security, #humans 28927; bus-dev 28936). The bootstrap installs PowerShell from a pinned zip that Wazuh can't see, so monitoring needs its version here. "May be absent": the bus accepts a snapshot with or without it, so hosts and buses can be updated in either order. For every device; not in the history sample |

**A history sample** is what the history call returns per push, about 200 bytes: `received_at`, `state`,
`workers` (`busy`, `max`), `machine`, `outbox`, `held_clones`, `tasks`.

### The host

- **When:** every 60 s, and at once on a change of anything in section 1's change key, at most every 10 s.
- **When the bus refuses:** a 404 (an older bus), a 403 (not marked as a host yet) or any other refusal is logged
  once (`status-push-refused`) and retried hourly. So a host can be updated before its bus, and starts feeding the
  dashboard the moment the bus accepts it (`status-push-ok`).
- **Otherwise:** a 429 waits a minute; an unreachable bus waits for the next push.
- **The code:** `hoststatus.build_v2()`. `hoststatus.for_device()` and `hoststatus.sample()` are the reference for
  the bus's filter and history.

### Vectors (`contracts/host-status/`)

One busy host with two workers, a warning and an announced update:
- `snapshot-v2.json`: what the host POSTs;
- `snapshot-v2-device.json`: what a device without the operator grant gets for it;
- `sample-v2.json`: its history sample, with `received_at` `2026-11-27T04:00:00Z`.

The host's tests check that its code makes exactly these. The bus builds against the same files.

---

## 1b. Host events in the bus's event log

Agreed on #humans, 27 Nov 2026: Chris ("as long as the local logs on the host remain as well"); the proposal
(28846); u64-security (28848); bus-dev (28850). The App's admin log can then answer "what happened on that host?".
Today it only shows a host's *current* problem: a crash at 3 am that recovered, or yesterday's failed update, left
no trace.

**The local log files don't change.** `logs\host-YYYYMMDD.log` and `.errors.log` stay exactly as they are, as the
full record. An event is a separate, much smaller thing.

**Events are the host's own claims.** They help diagnosis but aren't proof: a compromised host can leave events out
or invent them. The same is true of the status snapshot in §1a.

### The call

`POST /api/hosts/events` (the release with schema 25), with the same identity rule as §1a. That's the host's own
agent credential, the bus's host flag, and `agent` must be the caller (else 400). The body:

```
{"v": 1, "agent": "<the caller's agent name>", "events": [ <1 to 20 events> ]}
```

**Limits:** at most 16 KB per call, and one call per 5 s per host (429).

**The bus refuses the whole batch with 400** for:
- an unknown `type`;
- an unknown field;
- a value of the wrong kind;
- a repeated `id`;
- more than 20 events;
- the wrong `agent`.

**Storage:** each event `id` is stored once, so a retry after a lost answer never makes a duplicate. Source `host`,
with the host's name as the subject. Retention is 30 days, with a cap of 500 rows per host inside the host source's
own cap. So one noisy host can't push out another's events, and hosts together can't push out the bus's update or
security events.

**Order:** the bus sorts by its own `received_at` and shows the host's `at` beside it. Events sent late, after an
outage, sort together at the moment they arrived, each showing its own time.

**Visibility: admins only**, the whole host source (u64-security). It's served only with the operator grant, on
`POST /api/mobile/admin/logs/full` (a read; the grant goes in the body, as everywhere). The existing log route, which any device can read, leaves host events out.

### An event

`{"id": "<a UUID the host makes>", "type": "<from the list>", "at": "<the host's time, YYYY-MM-DDTHH:MM:SSZ>", ...}`
plus only the fields its type lists, each optional.

**Field kinds:** these are the bus's checks, and the bus stores no free text from a host.

| Kind | Fields | Rule |
|---|---|---|
| version | `version`, `previous` | `YYYY.MM.DD` with an optional `.N`, or `manual` |
| code | `reason`, `code`, `step` | lowercase letters and digits in parts joined by `-` (`memory-high`), at most 64 |
| type name | `error` | a Python exception type name (`KeyError`, `json.JSONDecodeError`), at most 64 |
| int | `exit_code`, `attempt` | an integer between -1000000 and 1000000 |

**The types, and the level the bus gives each** (bus-dev's ranking; the host sends no level):

| Type | Fields | Level | The host logs it when |
|---|---|---|---|
| `update-found` | version | info | an update check first finds a newer signed release (once per version) |
| `update-applied` | version, previous | info | the new code starts |
| `update-failed` | version, reason | error | an update can't be applied |
| `update-rolled-back` | version | error | the supervisor restores the previous version |
| `update-missed` | version | warning | the window passed while workers were still busy |
| `release-source-unreachable` | — | warning | the release source can't be fetched (once per outage) |
| `release-redirect-refused` | — | error | a release names a source outside the host's allowed remotes |
| `started` | — | info | the host process starts |
| `stopped` | reason | info | the host stops (`drain`, `stop`, ...) |
| `restarted-after-crash` | exit_code, attempt | warning | the supervisor restarts a host that exited unexpectedly |
| `fatal` | error | error | an error escapes the main loop: its type only, never the message or traceback |
| `bus-lost`, `bus-back` | — | warning, info | the bus stops answering, and answers again (once per outage) |
| `openbao-lost`, `openbao-back` | — | warning, info | OpenBao becomes unreachable, and reachable again |
| `leaf-renew-failed` | — | error | the leaf certificate's renewal fails (once until it next succeeds) |
| `task-refused` | reason | warning | a task is refused: the reason code only, never the task |
| `wip-save-failed` | step | warning | a worker's unsaved work couldn't be saved |
| `copilot-update-failed` | — | warning | a Copilot CLI update fails |
| `pressure` | — | warning | memory or disk pressure begins |
| `problem-raised`, `problem-cleared` | code | warning, info | the status's `problem.code` (§1) changes |

### The host

- **How events are made:** `hostevents.EventLog` writes every log line as before, then turns the lines in its table
  into events. A line that repeats while a condition lasts becomes one event per change.
- **The supervisor** writes `restarted-after-crash` and `update-rolled-back` the same way. It only does so between
  host runs, so it never writes the queue at the same time as the host.
- **The queue:** `state\host-events.json`, at most 200 events. When it's full, the oldest event that isn't an update
  failure, rollback, fatal error, crash restart or refused redirect goes first. It's on disk, so nothing is lost
  while the bus is away or the host restarts.
- **Sending:** up to 20 events per call, at most every 5 s.
  - **201:** stored, and removed from the queue.
  - **400 or 413:** the batch can never be stored, so it's dropped and logged (`host-events-dropped`), never
    retried forever.
  - **403 or 404** (not marked as a host yet, or an older bus): kept, logged once, retried hourly.
  - **429:** a minute's wait. **Unreachable:** the next try.
- **New local log lines** for this (both useful locally too): `task-refused reason=...` (a refusal was only in the
  task state before) and `bus-back` (the end of an outage).

### Vectors (`contracts/host-events/`)

**Accepted:** `batch-good.json`, a batch the bus stores (201).

**Refused (400), with the reason:**
- `batch-unknown-type.json`: `unknown-type`;
- `batch-unknown-field.json`: `unknown-field`;
- `batch-free-text.json`: `bad-value`;
- `batch-wrong-agent.json`: `wrong-agent`;
- `batch-21-events.json`: `too-many-events`.

**Answers:** `expected.json` gives the caller agent and each file's status and reason. `hostevents.validate_batch()`
is the reference for the bus's check, and the host's tests run it on each file.

---

## 2. Add a host (stage B)

### 2.1 What the App hands over: fixed code, separate data

**Code and data are separate** (security review). The App hands the operator two files and edits
neither one's logic:
- **`bootstrap.ps1`:** a fixed file from a release of this repository, shipped in the App's own package. The App
  never edits it.
  - **Once releases are Authenticode-signed** (the project's code-signing certificate), the App ships a signed copy
    and shows the expected certificate **thumbprint**, not only the name (a name can be shared, a thumbprint
    cannot). The operator checks it before running it:
    `$s = Get-AuthenticodeSignature .\bootstrap.ps1; $s.Status; $s.SignerCertificate.Thumbprint; [bool]$s.TimeStamperCertificate`
    The expected result is `Valid`, the thumbprint the App shows, and `True`.
    - **A freshly installed Windows that hasn't been online yet** may not have Certum's root certificate. It then
      reports the signature as untrusted (`UnknownError` or `NotTrusted`), even though the file is fine. Connect it
      to the internet once (Windows fetches trusted roots on demand), then check again. Or use the `Get-FileHash`
      check below against the hash the App shows. Never run it on an untrusted result without one of the two.
  - **How a copy is signed** (`tools/sign-bootstrap.ps1`, run on the owner's PC with the certificate):
    - The repository keeps bootstrap.ps1 unsigned. Its SHA-256 is `bootstrap_sha256` in the signed `release.toml`,
      and the certificates allowed to sign it are that release's `authenticode_thumbprints` (current, and the next
      before a renewal).
    - `-Sign` verifies the release's signature first, and it must be by one of the project release keys **pinned
      in the script itself** (the owner's YubiKeys, by fingerprint). An `allowed_signers` file an agent could edit
      is never enough. It also **refuses** unless the file is exactly the one that release approved. Then it signs
      a copy, with an RFC 3161 timestamp.
    - The check (with or without `-Sign`) passes a signed copy only as: the released bytes, then exactly one
      signature block, `Valid`, a thumbprint the release names, and timestamped. Signing only appends, so nothing
      before the block can change.
  - **Until then,** the App shows the file's full SHA-256 and the exact command
    `Get-FileHash -Algorithm SHA256 .\bootstrap.ps1`, to run **on the target PC, before running the script**.
    `Get-FileHash` is built into Windows, so it can be trusted there.
  - **Where the App runs on the target PC itself,** it launches the bootstrap directly, with no transfer.
- **`sbhost-enrol.json`:** the data for this one host. It is **never executed**, so changing it cannot run code. The
  bootstrap reads it with `-DataFile`:

```json
{"v":1,"written_at":"2026-11-24T04:02Z","device":"office-laptop","bus_url":"https://bus.example.lan","bus_ca_pem":"LS0tLS1CRUdJTi...","host_prefix":"host-office1","enrol_code":"sbhe1_...","engines":["claude"],"dedicated":true,"signers":["owner namespaces=\"strugglebus-fleet,strugglebus-host-command\" ssh-rsa AAAA... app-hello","owner namespaces=\"strugglebus-fleet,strugglebus-host-command\" sk-ssh-ed25519@openssh.com AAAA... yubikey"],"fleet_source":"bus","remotes":["https://github.com/acme/"]}
```

The values:
- **written_at, device:** the App's UTC time to the minute and its device label. The bootstrap shows both.
- **bus_ca_pem:** base64 of the PEM, the bus's LAN root certificate.
- **host_prefix:** the name the enrolment code is bound to.
- **enrol_code:** single use, 15 minutes; blanked in the file once redeemed.
- **engines:** `"ghcp"`, `"claude"` or both; the first is the default.
- **dedicated:** create and use a dedicated Windows account.
- **fleet_source:** `"bus"`, `"git"` or `"either"`.

Rules for the data file:
- **One canonical form, byte for byte.** The vector is `tests/data/vectors/sbhost-enrol.json`. The rules:
  - one line of JSON, ASCII only, no BOM;
  - the keys in the order above, with no spaces;
  - then a single LF.

  This is exactly Python's `json.dumps(obj, separators=(",", ":"), ensure_ascii=True) + "\n"`. The bootstrap
  re-renders the file from the values it read and refuses any difference (a repeated key, spacing, an escape, CRLF or
  a BOM). It also refuses a file over 64 KB.
- **Patterns:** every value matches a fixed pattern, and the bootstrap re-checks each one before use, stopping on any
  mismatch:
  - **bus_url:** `https://<host>[:port]`;
  - **host_prefix:** `^[a-z0-9]+(?:-[a-z0-9]+)*$`, 2 to 31 characters (the bus's service principal rule);
  - **enrol_code:** `sbhe1_` and the bus's code shape;
  - **signers:** OpenSSH allowed_signers lines with a principal, a `namespaces=` limited to the two site namespaces,
    and a known key type;
  - **remotes:** the site-file prefix rule.
- **Signers:** at least two, unless the bootstrap is run with `-SingleSigner` (testing only; the App says so). A site
  key can never get the `strugglebus-release` namespace. The bootstrap refuses one that tries.

### 2.2 What the bootstrap does

The bootstrap runs elevated, as the operator, on the target PC:
`powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -DataFile .\sbhost-enrol.json`.
`-NoProfile` matters: without it, the operator's own `profile.ps1` (writable by any program they run) runs elevated
before any check (u64-security, #humans 28966). Inside, the bootstrap runs git with no user or system config, only
https and no credential helper, and calls `winget.exe` by its full path in App Installer's admin-protected folder,
checked as Microsoft-signed, never through the user-writable PATH alias.

1. **Checks and the data file's fingerprint (M2):**
   - checks Windows 11, elevation, the data file's canonical form and every pattern;
   - prints the plan, **every signer fingerprint**, and **a short digest of the data file** (the first 16 hex of
     SHA-256 over its bytes, in groups of four);
   - the App showed the same digest and fingerprints when it saved the file. The operator compares them, then
     presses Enter. `-Yes` skips the pause but still prints both.

   The data file can be changed in transit (USB, share, mail), and it decides which bus and which signers. This is
   how that gets caught.

   **This holds only because the code printing the digest has been checked first,** by its signature or by
   `Get-FileHash` (2.1). Without that check, the digest is only a check against mistakes: a changed bootstrap can
   print anything.
2. **Prerequisites** with winget, only where missing:
   - Python 3.13, Git and PowerShell 7;
   - GitHub CLI (used to clone from GitHub);
   - the chosen engines: GitHub Copilot CLI and/or Claude Code.

   Versions are recorded. Nothing is downloaded that winget does not sign.
3. **Fetches the host code** at the newest release and **verifies it before running any of it**:
   - `release.toml` and `release.toml.sig` are checked with Windows' own `ssh-keygen -Y verify` against the **project
     release key built into the bootstrap** (namespace `strugglebus-release`);
   - then the files' `tree_sha256` is checked. Any mismatch stops the install.
   - The bootstrap carries the **current and the next** release key, so a key can be rotated without a flag day.
     The release keys are two YubiKeys with touch required, one kept offline. If one is compromised, an admin
     re-pins on every host, as for a site key (Q3).
   - **As built (27 Nov 2026; u64-security, #humans 28898):**
     - **The keys:** the three YubiKeys A, B and C are built into `bootstrap.ps1` (`$ReleaseKeys`). They're the
       keys `sign-bootstrap.ps1` pins, a test checks they match, and they're for namespace `strugglebus-release`
       only.
     - **The signature:** Windows' `ssh-keygen -Y verify` checks it, then **touch and PIN** (flags 0x05) are
       required, as on the hosts.
     - **Not older:** the release must not be older than `$MinReleaseSerial`, which is raised whenever this file
       changes, since a new PC has no installed serial to compare with (prox-manager, 28901).
     - **The elevated scripts:** `release.toml` also carries **`installer_sha256`**, the same construction as
       `tree_sha256` over `install.ps1`, `setup/*.ps1` and `setup/*.txt`: what the bootstrap runs as
       administrator, which `tree_sha256` doesn't cover. Hosts ignore it.
     - **Nothing from the fetched tree runs** until the signature, the PIN flag, the floor, `tree_sha256` and
       `installer_sha256` have all passed.
   As built (PR 64, PR 68; tested end to end on a VM, 28 Nov 2026), the order is 4, 5, 6, 11, 8, 7, then the logon
   denials and 9: the enrolment code lasts 15 minutes and the sign-ins take as long as the operator needs.
4. **The account:**
   - a standard local user (`sbworker`, or `sbworker2`... if taken), not an administrator, with a random 32-character
     password held only in memory: it goes to `install.ps1` on stdin and from there to Task Scheduler, and is never
     shown or stored. It's hidden from the sign-in screen, kept out of Administrators, Remote Desktop Users and
     Remote Management Users, and recorded in `host-account.json` for offboarding.
   - It's granted "log on as a batch job" (registering a task doesn't grant it to a standard user).
   - `ProgramData\strugglebus` is locked down first: owned by Administrators, inheritance cut, Users read only.
5. **Pins the signers:**
   - the site's lines go to `C:\ProgramData\strugglebus\allowed_signers` (administrators write, users read);
   - the project release key goes in with namespace `strugglebus-release` only;
   - every fingerprint is printed. No confirmation prompt: the App is the trusted source, and the operator approved
     the App's request with Windows Hello.
6. **Installs** with the verified `install.ps1 -Account <name> -PasswordStdin`, with a site file generated from the
   data file and the CA written from `bus_ca_pem`. The home is `ProgramData\strugglebus\host\<name>`, for the account,
   SYSTEM and Administrators only. The scheduled task runs as the account.
   - **It records the release it installed** in `app\RELEASE.json`: the release step 3 verified, with
     `moved_to` = the bootstrap's built-in place (u64a/strugglebus, `worker-host`). Without it the new host would never
     update itself: `install.ps1` alone writes "manual", and a bus-fleet site has no fleet repository to fall back on.
     The file sits in the account-writable home, so a compromised host account could edit it; the updater still
     fences any redirect against the site's remotes, and releases still need the admin-only pinned key (u64-security,
     #humans 29111). That is the known limit of anything the host's own account can write.
7. **Sign-in, as the account (after step 8):**
   - each sign-in runs in a window under the host's account (its tokens live in that profile): `gh auth login --web`
     plus `gh auth setup-git` (the host uses gh, and git uses it for GitHub), `copilot login`, and `claude` then
     `/login`;
   - the operator chooses **a device code**, approved on any PC (the default; works for a VM, or a passkey on another
     machine), or **a browser on this PC**;
   - the host's probe then shows, as the account, which sign-ins took. A skipped one leaves that engine unavailable
     until section 4a adds it;
   - **then the logon denials** (in a `finally`, so they apply even if enrolment or a sign-in failed): no sign-in at
     the PC, no Remote Desktop, no network logon, no service logon. Only the scheduled task's batch logon is left. A
     `C:\Windows\.gitconfig` is refused before the install and removed if a sign-in left one.
8. **Enrols with the code (before step 7):**
   - `wh enrol --code-stdin` redeems the code (bus 1: `POST /api/hosts/enrollments/redeem`, with a request id kept in
     the host's state, so a retry after a dropped connection gets the same answer);
   - it stores the returned SPN credential as today (DPAPI under the host's account, or OpenBao), onboards
     `<prefix>-host` and subscribes it to the channel. The code is never printed or logged.
   - **It blanks `enrol_code` in the data file** straight after redeeming, even if the operator keeps the file (Q1).
   - **It prints a confirmation code (M1):** the first 8 hex of SHA-256 over `<agent_id of <prefix>-host>` and
     `<the redeem request id>`, in that order, joined by a newline.
9. **Starts the host** and waits for its first status message. The host is in `needs-fleet` until step 10.
10. **The App adds the host to the fleet, after a match (M1):**
    - once `<prefix>-host` and its agent_id are on the bus, the App computes the same confirmation code. The bus
      records the redeem request id with the service principal, and the App shows the code and the IP the code was
      redeemed from.
    - The operator compares it with the bootstrap's. **Only on a match** does the App add a `[[host]]` entry, raise
      the serial, show the change, and ask for the Windows Hello signature.
    - On a mismatch, someone else redeemed the code first (a copied script). The App retires that service principal,
      and nothing is signed.
    - Once the new fleet is published, the host accepts it, finds itself listed, and starts taking work. The App's
      row goes "waiting for install", then "needs sign-in" and/or "needs fleet", then "online".
11. **The isolation check, for a dedicated account (Q5):**
    - it lists other accounts' scheduled-task actions, Startup items and Run keys, resolves the scripts and programs
      they start, and tests whether the host's account can write any of them;
    - it also tests folders created at the root of C: that give Authenticated Users Modify.
    - Any hit is reported as the standing warning `isolation-weak`, with the paths shown at the console, never on the
      bus. This is the gap a shared machine had in practice.
12. **Offers to delete the data file:** it held a one-time code, spent and blanked by now. The App says so when it
    saves the file.

The App shows the same signer fingerprints the bootstrap prints, so a check by eye stays possible.

**Host work:**
- `tools/bootstrap.ps1` with the project release key;
- `install.ps1 -Account dedicated|current`;
- `wh enrol --code-stdin`, with the confirmation code and the blanking of the code in the file;
- the file digest at step 1;
- the isolation check;
- `wh signin <engine>`;
- engine-aware `wh probe`, so a Claude-only host passes;
- tests of the data-block checks, including hostile values.

---

## 3. Coordinators and signing (stage C)

- **The fleet document:**
  - **content:** fleet.toml as today: serial, owner, coordinators, hosts;
  - **canonical bytes:** exactly the bytes stored, with no reformatting or line-ending change;
  - **signature:** SSHSIG, namespace `strugglebus-fleet`, by a pinned site key. The Windows Hello RSA-2048 key
    (`rsa-sha2-512`) is tested and verifies; so does the YubiKey (`sk-ssh-ed25519`).
- **Source:** site file `fleet_source = "bus" | "git" | "either"`.
  - From the bus, the host reads bus 2's document `fleet` (bytes, signature, serial).
  - With `either`, it takes the higher **verified** serial of the two.
  - The rules are the same for every source: a bad signature is refused; a serial not above the last accepted one is
    refused; a document that is missing or withheld means the last good copy stays in force. A compromised bus can
    withhold, not forge.
- **Size:** 64 KB, the same as the bus cap (the host's limit drops from 256 KB to 64 KB).
- **A host takes no work until the accepted fleet lists it** (state `needs-fleet`). Hosts settle claims only against
  the hosts their fleet lists, so an unlisted host's claims are ignored by the others, and the same task could run
  twice. Today an unlisted host still claims; this closes that.
- **The serial:** the App publishes one more than the highest of the bus's stored serial and every `fleet.serial` a
  host reports. The bus refuses a write that does not go up, and hosts refuse one that is not above their last.
- **Second signer:**
  - the App pins a YubiKey's allowed_signers line, pasted by the operator, and puts it in every script. The bootstrap
    refuses fewer than two signers (2.1).
  - The App signs with its Hello key only. The YubiKey signs with this repository's CLI (`tools/sign-config.ps1`).
  - The App's publish accepts a document and signature made elsewhere and publishes them unchanged, so the YubiKey
    is a real fallback if the Hello key's PC is lost.
- **A lost key:**
  1. The remaining signer signs a fleet document; nothing about keys changes from the bus.
  2. A new key is pinned only by an administrator action on each host: a re-run of the bootstrap's pin step from a
     newly generated script, or `install.ps1 -PinSigners`.
  3. A key is removed the same way.

  The bus never changes what a host trusts.

**Host work:**
- **Built (2026-11-25):**
  - `FleetSync.refresh(current, bus, source)` with `fleet.fetch_from_bus`. It reads `GET /api/site-documents/fleet`
    as the host agent (the bus's site-document store) and takes the serial from the signed bytes only;
  - `either` checks the repository against whatever the bus gave, so the higher verified serial wins;
  - every copy goes through the same `accept` checks and kept copy;
  - `fleet_source` in the site file (`@FLEET_SOURCE@`) and config, default `"git"`, so existing hosts are unchanged;
  - in `bus` mode the release check still fetches the repository mirror;
  - the 64 KB cap for every source;
  - tests/test_fleet_bus.py.
- **Still to do:** test vectors for the App: a fleet document, its SSHSIG by an RSA-2048 key, the allowed_signers line, and expected
  pass and fail cases (wrong namespace, wrong key, one changed byte, a lower serial).

---

## 4. Remote control (stage D)

A command is a small document, signed like the fleet, carried in an ordinary bus message. The bus is only the carrier;
the signature is the authority. An unsigned or badly signed message is ignored, exactly as today.

**The document** (UTF-8 JSON, the exact bytes signed, at most 1 KB):

```json
{"v": 1, "type": "sb-host-command", "host": "host-office1-host", "verb": "pause",
 "nonce": "<128-bit random, hex>", "issued_at": "2026-11-24T14:02:11Z", "expires_at": "2026-11-24T14:07:11Z"}
```

- **Signature:** SSHSIG, namespace **`strugglebus-host-command`**, which no fleet or release signature uses. A fleet
  signature can never be replayed as a command, or a command as a fleet. The signer's allowed_signers line must list
  that namespace (2.1).
- **Carried as:** a message on the host's channel, kind `question`, posted by the bus as `human:operator` through its
  narrow operator command post (`POST /api/mobile/hosts/commands`: an enrolled operator device plus Windows Hello; the
  bus caps the sizes, 1 KB document and 4 KB signature, and verifies nothing). The body is a fixed text ("signed host
  command; see metadata"), and the metadata holds
  `sb_host_command: {doc: <base64 of the bytes>, sig: <the armored SSHSIG>}`.

- **Coordinators** must never read a `human:operator` post on the hosts' channel as an instruction to them. It is a
  host command; the coordinator guide says so (S2).

**Parsing (M4):** the host verifies the signature over the base64-decoded bytes **first**, with an explicit
`-n strugglebus-host-command`, and then parses **those exact bytes**, never a re-encoding. JSON with any **duplicate
key** is refused (`duplicate-key`): Python's `json` lets the last key win, so `{"verb":"pause",...,"verb":"update"}`
could show one verb and run another. The parser uses `object_pairs_hook` to see every key.

**The host accepts a command only if all of these hold**, and otherwise refuses with a reason code in `last_command`:
1. the signature verifies against the pinned keys for `strugglebus-host-command` (`bad-signature`), and the JSON has no
   duplicate key (`duplicate-key`);
2. `host` is exactly this host's bus name (`not-this-host`);
3. `expires_at` is in the future, at most 10 minutes after `issued_at`, and `issued_at` is no more than 2 minutes ahead
   of the host's clock (`expired`, `bad-time`);
4. the nonce was not seen in the last 24 hours. Nonces are kept on disk for 24 hours, so a restart does not reopen a
   replay window (`replayed`);
5. `verb` is one of the fixed list, with no other field present (`bad-verb`, `unknown-field`).

**The verbs:**

| Verb | Does exactly what | Notes |
|---|---|---|
| `pause` | `wh pause` | running workers carry on |
| `resume` | `wh resume` | |
| `drain` | no new claims; when the last worker ends, the host stays **running and paused** | unlike local `wh drain`, which stops and disables the host: a remote drain must leave a host the App can resume |
| `update` | `wh update now`: install the newest release signed by the **project release key**, as soon as no worker runs | the command cannot name a version, URL or file; a rolled-back release stays refused |

**Not remotely possible, on purpose:**
- stop, restart or uninstall the host or the machine;
- change config, models, engines, keys or the fleet;
- touch credentials;
- run anything;
- name a path, URL or version.

Stopping a host stays a local action, or blocking its service principal in the App (which already works, and stops
it taking work).

**Freeze:** a frozen bus cannot carry commands. That is acceptable: blocking the service principal and local commands
still work.

**Clock:** the expiry check assumes the host's clock is right (Windows time sync, which the build already requires).
A host more than 2 minutes off refuses commands with `bad-time`, which the App shows.

**Host work:**
- **Built (2026-11-25):**
  - `workerhost/commands.py`: `carried` (the metadata), `check` (the five rules, in order), and `NonceStore`
    (`<state>\command-nonces.json`, 24 hours, bounded);
  - `Host.handle_command`: a message carrying `sb_host_command` is only ever a command, never a task;
  - the verbs, mapped to the existing control paths, and `drain-to-pause`;
  - `last_command` in the status. A command for another host is logged only, never shown as this host's;
  - one more refusal code beyond the list above, `bad-document`: anything malformed (not JSON, a missing or
    malformed field, a wrong `v` or `type`, over the size caps);
  - every vector in `tests/data/vectors/expected.json` gives its expected result through the real verifier
    (tests/test_commands.py), including a fleet signature replayed as a command and a command for another host.

---

## 4a. Signing in again, after the lock-down (design, for review)

Proposed on #humans 29048; accepted by u64-security with conditions (29049). **Not built yet.** This section is the
design for u64-security and bus-dev to review before any of it is built.

**The problem:** a sign-in lapses (a token expires, a licence changes) or was skipped at install (§2.2 step 7). But:
- the host's account can no longer run interactively: its password exists nowhere, and the logon denials refuse
  every logon but the task's batch logon;
- resetting the password would lose every secret DPAPI holds for that account, the host's own bus credential
  included, so it would mean enrolling again.

**The principle:** the host signs itself in, as its own account, under the batch logon it already runs in. The
operator starts it with a signed host command (§4). No password, no window, no lifting of the denials.

### The commands

Three new verbs. Each is a §4 command with all five of §4's rules:

| Verb | Extra fields | Does |
|---|---|---|
| `sign-in-gh` | none | GitHub CLI's device-code sign-in, then `gh auth setup-git` |
| `sign-in-copilot` | none | `copilot login --device-code` |
| `sign-in-claude` | `epk`, `ct` (below) | stores the Claude token the App encrypted to this host |

Rule 5 changes only for `sign-in-claude`, whose two fields are required and nothing else is allowed. A verb never
names a URL, path or account.

### gh and Copilot: a device code shown only to the person who asked

1. **The host** runs the sign-in with no window and reads its output. It takes the code and the verification URL from
   that output, and **refuses unless the URL is exactly `https://github.com/login/device`** and the code is GitHub's
   form (8 letters and digits, a hyphen in the middle). Anything else ends the attempt (`sign-in-failed`,
   `reason=unexpected-prompt`).
2. **It puts them in its status** as `sign_in` (admin-only, §1a), for this attempt only:
   `{"nonce": "<the command's nonce>", "tool": "gh" | "copilot", "state": "code", "code": "ABCD-1234",
   "expires_at": "..."}`.
   - The nonce ties the code to the command that asked for it.
   - `expires_at` is GitHub's own expiry, capped at 15 minutes.
   - **`state`** (as built, `workerhost/signin.py`): `starting`, then `code`, then `done` or `failed` (with
     `reason`: `unexpected-prompt`, `no-code`, `expired`, `tool-exit`, `setup-git`, `replaced` or `not-started`).
     `code` and `expires_at` are present only in state `code`.
   - The code is cleared when the sign-in completes, fails or expires. It's **never** in a history sample (§1a), an
     event (§1b), a log line, or the v1 status and heartbeat.
   - **The field is absent unless a sign-in was asked for,** like `pwsh` "may be absent". The bus must accept it (and
     the four event types below) before an App can send a sign-in command: a bus that doesn't know an event type
     refuses the whole batch.
   - **One sign-in at a time:** a new command replaces one still running (`replaced`).
3. **The App shows a code only for a command this device sent,** under 15 minutes old, with the same nonce. Any other
   code a host reports is dropped and recorded in the App's log, never shown. Otherwise a compromised host could push
   codes at the operator: device-code phishing.
4. **Beside the code, the App shows:**
   - which tool (GitHub CLI or GitHub Copilot) and which host;
   - this fixed text: "Approve only at https://github.com/login/device, and check GitHub names GitHub CLI or GitHub
     Copilot".
   The URL is the App's own constant, never taken from the host.
5. **The operator approves on their own PC.** The host's sign-in then completes on its own, as the account; for gh,
   it then runs `gh auth setup-git`.

### Claude: a token, encrypted end to end to the host

Claude Code's `/login` wants its code pasted back, so a device flow doesn't fit. Instead the operator makes a
long-lived token with `claude setup-token` on any PC, and the App delivers it **encrypted, so the bus relays only
ciphertext**. "Admin-only and never logged" would be a promise about every code path: request logs, the event log,
the audit feed, the App's own logs, a crash dump. Encryption makes it hold even if one of them slips.

**The host's key:**
- the bootstrap makes the X25519 key pair as the account (§2.2, with the sign-ins), and **prints its fingerprint** in
  the install output beside the others. So the App's first pin is compared with what the operator saw on the machine
  itself, not trusted on first use (u64-security, 29120). A host installed before this makes its key the first time
  it's needed, and its first pin is compared by running `wh status` on the machine;
- the private key is stored with DPAPI, as the host's account, beside its other credentials;
- the public key goes in its status as `sign_in_key` (admin-only): `{"x25519": "<base64>", "fingerprint":
  "SHA256:<base64 of SHA-256 over the key>"}`.

**The App pins that fingerprint per host:**
- it shows the fingerprint with the host's name the first time, and the operator confirms it **matches the one the
  install printed**;
- a changed key is never used until the operator confirms it again (with Windows Hello), and the App says plainly
  that the host's key changed.

**Sending a token:**
1. The operator pastes the token into the App. The App never stores it and never logs it.
2. The App encrypts the token to the pinned key:
   - a fresh X25519 key pair for this message (`epk`, its public half);
   - HKDF-SHA256 over the shared secret, with salt = `epk` followed by the host's public key (the usual ECIES binding:
     the derived key belongs to exactly that pair) and info `strugglebus-claude-token v1`. An all-zero shared secret
     (a low-order point) is refused on both sides (u64-security, 29120);
   - AES-256-GCM, with the host's agent name and the command's nonce as associated data, so the ciphertext can't be
     replayed to another host or in another command.
   - `ct` is the 12-byte IV, the ciphertext and the tag, base64.
3. The App sends it in a signed `sign-in-claude` command. A token of about 100 characters fits within §4's 1 KB
   document cap.
4. The host checks the command (all of §4's rules), decrypts, and stores the token with DPAPI. **A failed decryption**
   (a bad tag, or the wrong key) is the event `sign-in-failed` with `reason=decrypt`, and the status says so. The App
   then shows "the host could not open it; its key may have changed", never a silent failure.
5. On success, the host's own records keep only the date it arrived, never the token. When the host runs Claude Code workers it gives it as
   `CLAUDE_CODE_OAUTH_TOKEN`.

**The token's life:**
- **One token per host.** The status shows `claude_token_since` (a date, admin-only).
- **Rotate at least yearly.** After 335 days the host raises the warning `claude-token-old`.
- **On the offboarding checklist:** revoke it at claude.ai.
- **Exposure, stated plainly:** workers run as the same account and can read the token. That's the same exposure as
  the account's other DPAPI credentials today, and accepted for that reason (u64-security, 29049).

### Audit

Every step is recorded without the code or the token:

**Host events (§1b), five new types:**

| Type | Fields | Level |
|---|---|---|
| `sign-in-requested` | `code`: the tool (`gh`, `copilot`, `claude`) | info |
| `sign-in-code-issued` | `code`: the tool | info |
| `sign-in-done` | `code`: the tool | info |
| `sign-in-failed` | `reason` | warning |
| `claude-token-stored` | — | info |

**The App:** it records showing a code, refusing an unsolicited one, confirming a key and sending a token as bus
security events, through bus-dev's existing App audit path. None carries a code, token or key.

### Who builds what

- **Host (sbworkerhost-project):**
  - the three verbs and their checks;
  - the headless sign-ins and their output parsing, refusing anything unexpected;
  - the X25519 key (made and fingerprinted by the bootstrap) and the decryption;
  - the `sign_in`, `sign_in_key` and `claude_token_since` status fields;
  - the events and the `claude-token-old` warning;
  - the token passed to Claude Code workers;
  - vectors for all of it.
- **Bus (bus-dev):**
  - the three status fields, admin-only and **may be absent** (as `pwsh`), never in a history sample;
  - the five event types;
  - nothing in the command post changes: it already carries any signed document of 1 KB or less.
- **App (bus-dev):**
  - the sign-in buttons on a host;
  - the nonce check and the fixed text;
  - the key pinning and the token entry and encryption;
  - its audit events.

### To prove first, on the test VM (`host-sbtest-host`)

1. **Proven (28 Nov, #humans 29169):** `gh auth login --web` and `copilot login --device-code` run headless under the
   batch logon, with stdin closed and no TTY. gh prints `One-time code (XXXX-XXXX) copied to clipboard` and the URL
   on stderr; copilot prints `visit https://github.com/login/device and enter code XXXX-XXXX` on stdout. Both then
   wait for the approval.
2. `CLAUDE_CODE_OAUTH_TOKEN` alone is enough for Claude Code in a worker, with no `/login` state in the profile.
   **Not yet:** it needs a real `claude setup-token` from the operator.
3. **Proven:** a `sign-in-claude` document is 461 bytes with a 108-character token, and 529 with 160 (the longest
   host name), under §4's 1 KB.

### Built so far

- **The device-code sign-ins** (gh and Copilot): the verbs `sign-in-gh` and `sign-in-copilot`, `workerhost/signin.py`
  (the strict parser and the attempt), the `sign_in` status field, and the four event types `sign-in-requested`,
  `sign-in-code-issued`, `sign-in-done` and `sign-in-failed`.
- **The Claude token (B2):**
  - **`workerhost/claudesignin.py`:** the host's key and the token, both kept in **this account's own DPAPI store**,
    never OpenBao, even on a host that uses OpenBao for its identities.
  - **The verb:** `sign-in-claude`, whose `epk` and `ct` are required and checked as base64; nothing else.
  - **The outcome:** the status's `sign_in` (tool `claude`) reads `done`, or `failed` with `decrypt`.
  - **The status:** `sign_in_key` and `claude_token_since`, admin-only, and the warning `claude-token-old`.
  - **The event:** `claude-token-stored`.
  - **The workers:** Claude Code workers get `CLAUDE_CODE_OAUTH_TOKEN`, and only they; any inherited copy is dropped
    for every worker. Claude Code counts as signed in when a token is stored.
  - **The command:** `wh sign-in-key` makes the key as the account and prints its fingerprint. The bootstrap runs it
    after enrolment and before the logon denials.
  - **Shipping order:** `sign_in_key` is sent routinely, and the bus's status schema refuses an unknown field, so
    **a host release carrying B2 waits for a bus release that accepts `sign_in`, `sign_in_key` and
    `claude_token_since`** (asked of bus-dev, #humans 29187).
- **The crypto (B1):** the host's code is standard-library Python only, and it already calls Windows itself
  for DPAPI through `ctypes`. X25519 and AES-GCM aren't in Python's standard library, so the host will use Windows'
  own CNG (`bcrypt.dll`: `BCRYPT_ECDH` on curve25519, and AES in GCM mode) the same way. That adds no package and
  hand-written crypto is never used. HKDF-SHA256 is `hmac`, which is standard.
  - **Built: `workerhost/cng.py` and `workerhost/sealed.py`,** tested against RFC 7748 6.1, RFC 5869 test case 1 and
    the GCM specification's test case 16, plus an independent X25519 in the tests.
  - **CNG's curve25519, as measured:** a private key is the RFC's little-endian scalar stored clamped; a public key is
    the RFC's bytes unreversed; the raw shared secret comes out reversed and is put back before use
    (u64-security, #humans 29172).
  - **The App:** .NET has no X25519 of its own (`ECDiffieHellman` doesn't offer curve25519 on Windows), so the App
    calls CNG too, or one reviewed library, and `AesGcm`. **Both sides must reproduce
    `contracts/sealed-signin/vector.json`:** every input fixed, and the exact `epk` and `ct`.

If any of these fails, this section changes before anything is built.

---

## 5. The fleet document: schema (what the App writes)

The App writes fleet.toml as text and signs those exact bytes. UTF-8, LF line endings, no byte-order mark, 64 KB at
most. Hosts parse it with `workerhost/fleet.py`. A key a host does not know is listed as ignored, never an error, so
a newer App can add one.

```toml
serial = 5                                  # required; an integer above the last one hosts accepted
owner = "Alex"                              # optional; letters, digits, space . ' - ; 40 at most; named in every
                                            # worker's preamble

[[coordinator]]                             # zero or more
agent_name     = "coord-main"               # [a-z0-9][a-z0-9-]{0,62}
agent_id       = "11111111-1111-4111-8111-111111111111"   # lower-case UUID
project        = "app"                      # [a-z0-9][a-z0-9-]{0,30}
notes_repo     = "https://github.com/acme/team-notes"    # where its briefs live
notes_channel  = "app-notes"                # [A-Za-z0-9][A-Za-z0-9_-]{0,63}
repos          = ["https://github.com/acme/"]           # https://<host>/ or https://<host>/<owner>/ prefixes
default_engine = "ghcp"                     # optional: ghcp (default) or claude
repo_instructions = true                    # optional: load AGENTS.md and the like (default true)
worker_rules   = """
Optional always-rules for this project's workers, at most 4,000 characters; no control characters but newline and tab.
"""

[[host]]                                    # every host, this one included; zero or more
agent_name = "host-office1-host"            # <prefix>-host
agent_id   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
```

No agent_id or agent_name may appear twice across coordinators and hosts.

## 6. Test vectors (`tests/data/vectors/`)

These were made with a throwaway RSA-2048 key, signing as a Windows Hello key would (SSHSIG, `rsa-sha2-512`). The
private half was discarded and is not in the repository. `allowed_signers` holds the public key, with the namespaces
`strugglebus-fleet` and `strugglebus-host-command`. `expected.json` gives each file's expected result at its `now`,
for the host named `this_host`:
- **Fleet:**
  - `fleet.toml` is accepted;
  - `fleet-changed-byte.toml` (one changed byte, same signature) is `bad-signature`;
  - `fleet-wrong-namespace.toml` (signed under the command namespace) is `bad-signature`.
- **Commands:**
  - accepted: `cmd-pause.json` and `cmd-update.json`;
  - refused: `cmd-other-host.json` (`not-this-host`), `cmd-expired.json` (`expired`), `cmd-too-long.json` and
    `cmd-from-future.json` (`bad-time`), `cmd-bad-verb.json` (`bad-verb`), `cmd-unknown-field.json`
    (`unknown-field`), `cmd-replayed.json` (`replayed`: the same document as `cmd-pause.json`, presented after it),
    `cmd-duplicate-key.json` (two `verb` keys: `duplicate-key`, M4), and `cmd-fleet-namespace.json` (signed under
    the fleet namespace: `bad-signature`).

`tests/test_vectors.py` checks every signature result with the host's own verifier. The content results are checked
there once stage D is built. Byte-exact in git (`.gitattributes`: `-text`).

## 7. Security review (24 Nov 2026)

**Verdict:** the design is sound, and remote control (D) is acceptable for the first release once M1 to M6 are in the
docs. **The real authority is C, not D:** whoever can sign a fleet can add a coordinator, and a coordinator runs code
on every host. D adds only pause, drain and update timing. So most conditions protect the site key and the enrolment
path.

**Conditions before anything is built**, with where each one lives:

| | Condition | Owner | Here |
|---|---|---|---|
| M1 | The fleet addition is bound to the real install: a confirmation code from the bootstrap and the App, compared before the Hello signature; on a mismatch the service principal is retired | host + App + bus (records the redeem request id) | 2.2 steps 8 and 10 |
| M2 | The file digest and signer fingerprints are shown by both the App and the bootstrap, and compared before Enter | host + App | 2.2 step 1 |
| M3 | (a) The App shows exactly what a Hello signature signs: the fleet diff, or the verb and host. (b) The site key can be used only by the App (a packaged-app-scoped key), or this is listed as an open risk | App | the bus's `bus/docs/WORKER_HOST_COMMAND_CENTER.md` |
| M4 | Commands: the exact signed bytes are parsed, duplicate keys refused, and verification uses an explicit `-n` | host | section 4; vector `cmd-duplicate-key.json` |
| M5 | Redeem: a code of 128 bits or more, stored hashed and compared in constant time; rate-limited; every mint, redeem and failure audited with the source IP; the App shows the redeeming IP | bus + App | the bus's `bus/docs/WORKER_HOST_COMMAND_CENTER.md`; 2.2 step 10 |
| M6 | A non-dedicated install stays visible as a standing warning | host (`warnings: not-dedicated`) + App | section 1 |

**Answers to the questions:**
- **Q1, the code in the file:** a saved file is better than a one-liner, because PowerShell's history file keeps
  what is typed. (The one-liner option is dropped: the code now lives in the data file, 2.1.) The bootstrap blanks `enrol_code` in the data file after redeeming (2.2 step 8).
- **Q2, pinning without a typed yes:** OK, with M2's digest and fingerprints compared at the Enter step.
- **Q3, the release key:**
  - two YubiKeys with touch required, one kept offline;
  - hosts and the bootstrap carry the current and the next key;
  - a written compromise procedure: an admin re-pins on every host (2.2 step 3).
- **Q4, the commands:** agreed as written, plus M4.
- **Q5, the account:**
  - agreed;
  - a site-specific acceptance test does not ship. Instead, every dedicated bootstrap ends with a generic isolation
    check, reported as `isolation-weak` (2.2 step 11).

**Should:**
- **S1:** until the App can carry an Authenticode signature, publish its SHA-256 signed with the release key. The
  bootstrap inside the App, and the release key inside the bootstrap, are only as good as the App download.
- **S2:** the bus, not the App, sets a command's fixed body, and coordinators never treat `human:operator` posts on
  the hosts' channel as instructions (section 4).
- **S3:** the App renders status as plain text (section 1).
- **S4:** bus audit lines for host enrolment (mint, redeem, fail), site document writes (name, serial, signer
  fingerprint) and command posts (verb, host, nonce, device). A site's monitoring can alert on these once the
  formats are fixed.
