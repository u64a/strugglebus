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

**The bus (bus-dev, bus 0.2.73, schema 25):**
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
- **Admin only** (a request carrying the operator grant): `account`, `dedicated`, `warnings`, `bus.channel` and
  `bus.channel_state`. Together the first three map the weakest machine. A host's channel may be private, and a
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
`powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -DataFile .\sbhost-enrol.json`.

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
4. **The account:**
   - with `Dedicated`, it creates a standard local user (`sbworker`, or `sbworker2`... if taken), not an administrator,
     with a long random password handed straight to Task Scheduler and never shown or stored. It denies that
     account interactive and RDP logon once step 7 is done.
   - Without `Dedicated`, it uses the operator's own account (the status shows `dedicated: false`).
5. **Pins the signers:**
   - the site's lines go to `C:\ProgramData\strugglebus\allowed_signers` (administrators write, users read);
   - the project release key goes in with namespace `strugglebus-release` only;
   - every fingerprint is printed. No confirmation prompt: the App is the trusted source, and the operator approved
     the App's request with Windows Hello.
6. **Installs** with the existing `install.ps1`, with a site file generated from the data file and the CA written from
   `bus_ca_pem`. The scheduled task runs as the chosen account.
7. **Engine sign-in:**
   - device-code sign-in has to happen as the host's account, so the bootstrap starts each sign-in under that account
     (`copilot login --device-code`, `claude` then `/login`) in a window the operator completes;
   - with a dedicated account, this is the only time it is used interactively; step 4's logon denial follows it;
   - skipped sign-ins leave the host in `needs-sign-in`, shown in the App, with `wh signin <engine>` to finish later.
8. **Enrols with the code:**
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
