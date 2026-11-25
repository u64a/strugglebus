# Host secrets in OpenBao

Status: phase 1 (section 2), self-enrolment (section 2.7) and phase 2 (section 3) are built. All are off until a
host sets `[openbao] enabled = true`. P1b (section 4) is a proposal, not built.

This guide covers the worker host's side. The site provides the rest:
- an OpenBao server with TLS certificate auth and a KV v2 mount;
- a step-ca with a provisioner that issues client-auth leaf certificates;
- a host policy that gives each host its own prefix only;
- optionally, a token minter: a bus agent that mints step-ca one-time tokens and drops them on hosts
  (section 2.7).

**Words.** In this codebase *vault* already means a coordinator's notes vault: the git repository of briefs
(`vault_commit`, `Policy.vault`). This guide calls the secrets store **OpenBao**, and so does the code
(`[openbao]`, `workerhost/openbao.py`), so the two never mix.

## 1. Why

Without OpenBao, a host keeps its secrets in Windows DPAPI (design.md section 12):

| Secret | Where | Who can read it |
|---|---|---|
| The SPN (`sbsp1_`), which never expires | `%LOCALAPPDATA%\strugglebus-worker-host\creds\spn.bin`, DPAPI | the host, **and every worker** |
| The host's bus credential | `creds\<host>-host.bin`, DPAPI | the host and every worker |
| Each worker's bus credential, never retired | `creds\<host>-<worker>.bin`, DPAPI | the host and every worker |

- Every worker runs as the host's Windows user, with all tools.
- Its `SB_BUS_STORE` points at the **whole** `creds` folder.
- So any worker can read the SPN from disk and mint any name under the host's prefix.

Other problems:
- Worker identities pile up, because none is ever retired.
- A rebuild loses DPAPI, so the owner has to type the SPN in again.

## 2. Phase 1: secrets in OpenBao

### 2.1 What the host holds

| Item | Where | Notes |
|---|---|---|
| Leaf key and certificate, `<host>.<san_domain>` | `%LOCALAPPDATA%\strugglebus-worker-host\leaf\` (PEM), owner-only ACL | The host's **only** secret on disk. Client auth only, from step-ca. |
| The SPN | OpenBao `agents/<host>/strugglebus-spn` | Read into memory for each spawn, then dropped. Never written to disk. |
| The host's own bus credential | OpenBao `agents/<host>/strugglebus` | Read at start, kept in memory. On rotation the successor goes into OpenBao before it is proved. |
| A worker name's bus credential | OpenBao `agents/<host>/workers/<agent>` | One durable credential per worker name, as with DPAPI. Bus names can never be reused, so destroying it when a task finishes would end that worker name. It is destroyed only when the host gives the name up. Phase 2 replaces it with per-task TTL names. |

- The DPAPI `creds` folder goes.
- The host policy should allow its own prefix only (`agents/<host>/*`). Nothing is shared between hosts.

### 2.2 OpenBao client (`workerhost/openbao.py`)

- **Plain HTTPS** with the standard library, like `busclient.Bus`:
  - `ssl` loads the leaf with `load_cert_chain`;
  - it trusts the LAN root CA (`[openbao] ca`, default `bus_ca`).
- **Calls:**
  - `POST /v1/auth/cert/login`;
  - KV v2 `GET` / `POST` / `DELETE` on `agents/data/...` and `agents/metadata/...`;
  - `POST /v1/auth/token/revoke-self`.
- **One login per use.** A batch of reads or writes, then the token is revoked. No token is kept between uses.
- **Nothing logged.** No OpenBao response, token or secret is ever logged. Errors are logged by HTTP status and
  path only, the same rule as `busclient.server_detail`.
- **Fail closed.** If the leaf is missing, login fails or OpenBao can't be reached, the call raises. There is no
  fallback to a file.

### 2.3 Starting a worker (in place of `Host.ensure_identity`)

1. Log in.
2. Read the SPN.
3. Mint a package for `<host>-<worker>` and redeem it over REST, as `busclient.onboard` does. The host uses the
   REST response in memory, so no CLI output mode is needed.
4. Bootstrap the identity: prove, acknowledge the RoE, subscribe to the notes channel.
5. Write the credential to `agents/<host>/workers/<worker>`.
6. Revoke the token. Drop the SPN and the record from memory.
7. Launch the worker with **`SB_BUS_TOKEN`** set in its process environment only:
   - `SB_BUS_URL` and `SB_BUS_CA` stay;
   - `SB_BUS_STORE` is no longer set.

Notes:
- **Why an environment variable.** Every bus call a worker makes is a fresh process: copilot (Node) runs its shell
  tool, which runs `python busclient.py`. On Windows, Node passes only stdio to child processes, so an inherited
  handle never reaches the bus client, and a read-once file can't serve several calls. The variable is inherited by
  every descendant, never written to disk and never logged.
- **This is not isolation** while workers share a Windows user (section 4).
- **Resume** (after a crash, a planned restart or a reboot):
  - the host reads `agents/<host>/workers/<agent>` again and relaunches with the same credential;
  - if the entry is gone, the bus refuses to mint the same name again, and the task fails with reason `identity`.
- **`busclient.py`** takes its credential from `SB_BUS_TOKEN` and nothing else. It never looks for a store, so a
  worker started without the variable fails closed.
- **Worker names stay as they are in phase 1:** one durable identity per worker name, reused across tasks. Phase 2
  changes the naming.

### 2.4 If OpenBao can't be reached

- The host takes **no new tasks**. Its refusal reason is `openbao`, which the coordinator guide lists.
- What counts as unreachable: the health check fails. It runs every `[openbao] check_minutes` (default 1). A missing
  or unreadable leaf also counts.
- Running workers carry on: their credential is already in their environment.
- The heartbeat gains `openbao=ok|unreachable`.
- On each change of state the host posts one status line on its channel. The wording is fixed, so security
  monitoring may match these fixed lines: **`vault unreachable, no new tasks`**, and **`vault reachable, taking
  tasks`** when it recovers.
- The host retries with the fleet-refresh backoff. It never falls back to a file.

### 2.5 Setup and the cutover

**Site values.** `install.ps1 -SiteFile <your site.toml>` writes the `[openbao]` values into a new host's
`config.toml` (see `site.example.toml`):

```toml
[openbao]
url = "https://vault.example.lan:8200"
ca_url = "https://ca.example.lan"
san_domain = "example.lan"     # the leaf is <agent_prefix>.<san_domain>
leaf_authority = ""            # the token minter's agent name; empty: the host asks by file only
```

**Setup step `setup/30-openbao.ps1`.** Run it as the host's user (not elevated), after `install.ps1`:
1. **The folder.** `<home>\leaf` is made owner-only.
2. **Key and CSR.** An EC P-256 key and a CSR are made on this machine with .NET. The key never leaves it.
   - The name is `<agent_prefix>.<[openbao] san_domain>` from `config.toml`, or `-San <name>.<domain>`.
3. **Issue the leaf.** `wh openbao enrol` asks for a one-time token at a hidden prompt and sends it to step-ca's
   `/1.0/sign` in the request body, over the pinned LAN root.
   - **No step CLI.** The CLI takes the token only as a command-line flag, which this project never allows for a
     secret.
   - **Lifetime.** The leaf asks for `leaf_hours` (default 72, which should match the provisioner's maximum).
     Renewals keep that length.
4. **Renewal is done by the host itself.** Every hour it checks, and when under 48 h are left it renews at `/1.0/renew`
   over mTLS. The heartbeat shows `leaf=<hours>`.
   - So a new token is needed only after a rebuild, or after the host has been off longer than the leaf lasts.
   - `wh openbao renew` renews by hand.
5. **Checks.** Setup prints the folder's ACL (`icacls`), then runs `wh openbao status`: a login, then a write, read
   and destroy under `agents/<host>/selftest`. A security agent can confirm the run in the OpenBao audit trail.

`30-openbao.ps1 -Check` changes nothing and exits 1 if the leaf or the folder still needs work. With a valid leaf
for the right name, a second run changes nothing.

**Seeding:**
- **The SPN, once per SPN.** `wh openbao seed-spn` reads the SPN at a hidden prompt and writes it to
  `agents/<host>/strugglebus-spn`. This replaces `wh enrol`'s prompt.
  - It is typed once, ever: a later rebuild only needs a new leaf.
  - When phase 2 rotates SPNs, the host does it itself.
- **The host credential.** `wh enrol` mints `<host>-host` with the SPN from OpenBao and writes it to
  `agents/<host>/strugglebus`. A host that already has an identity keeps it: see the migration.

**Migrating an existing host:** `wh openbao migrate`
1. Read the SPN and **every** identity under this host's prefix from DPAPI: the host's own and every worker name's.
   Workers are copied too because bus names can never be reused: a worker whose credential is lost can never run
   under that name again.
2. Write them to OpenBao and read each one back to check.
3. Only `wh openbao migrate --delete-dpapi`, run after a verified copy, deletes the `creds` folder.

**Before a rebuild.** A rebuild loses DPAPI. Run `migrate` on the old host **before** it is wiped, once its leaf
exists. Otherwise every worker name it has used is lost for good.

**Where to run `migrate`.** Run it as the host's user, signed in at the machine or over RDP. A session signed in
with an SSH key has no password, so it may have no DPAPI keys: decryption can fail with `CryptUnprotectData`
(0x8009000B). `migrate` says so and changes nothing.

**Rollout:**
- The code ships in a signed release (self-update).
- Each host turns it on with `[openbao] enabled = true`, once its leaf and seed are in place.
- Until then the host keeps working from DPAPI, so the release and the cutover are separate.
- `url` and `ca_url` are required once `enabled = true`; the config check refuses to start without them.

**Other settings** (defaults shown; most sites leave them alone):

```toml
[openbao]
enabled = false                      # true once the leaf and seeds are in place
mount = "agents"                     # KV v2
prefix = ""                          # default agent_prefix (= the leaf name's host part and the SPN name)
leaf_dir = ""                        # default %LOCALAPPDATA%\strugglebus-worker-host\leaf
leaf_hours = 72
```

**Order on a host:**
1. `30-openbao.ps1` (the leaf);
2. `wh openbao seed-spn`, or `wh openbao migrate` on a host that already has a DPAPI store;
3. `[openbao] enabled = true`;
4. `wh enrol` (new host only);
5. `wh stop` / `wh start`.

### 2.6 Tests

- **`openbao.py` against a fake HTTPS server:**
  - login, KV read, write, delete and destroy, revoke;
  - every failure path raises and never falls back;
  - nothing secret reaches the logs (the existing log redaction check).
- **Host:**
  - spawn writes the worker entry;
  - resume reads it again;
  - OpenBao down means no new tasks, running workers untouched, and the fixed status wording;
  - `migrate` is idempotent and stops without deleting if the read-back check fails.
- **`busclient`:** it uses `SB_BUS_TOKEN` and refuses when the variable is missing.
- **End to end on a test host:** a hello task with no `creds` folder. Check the OpenBao audit trail for the login,
  the reads and the writes.

## 2.7 Zero-touch leaf tokens

Goal: no recurring manual step when a host is registered or rebuilt. A running host renews its own leaf. A token is
needed only when the leaf is missing or lapsed, and then the host asks for it itself.

**The leaf name.** The host asks for the name on the leaf it holds (an expired leaf still names it). With no leaf
at all, it uses `<agent_prefix>.<[openbao] san_domain>`. With neither, it cannot ask: it logs `leaf-no-name` once
and waits for `30-openbao.ps1 -San`.

1. **The host asks on the bus** (only if `[openbao] leaf_authority` is set). With no leaf, or under
   `ask_below_hours` (default 6) left while renewal is failing, it posts
   `@<leaf_authority> leaf-needed san=<host>.<san_domain>` in `leaf_channel` (default `security`), at most hourly.
   That needs its bus identity, so it works only while the host is connected.
2. **The token minter delivers.** It should check the name against its own table of hosts, that the sender is that
   host's identity, and a rate limit. It then mints a single-use, short-lived token bound to the name and uploads it
   by SFTP as **`sbdrop`**, with its own drop-only key, to `<san>.token`. It posts `token-delivered san=...` with
   no content.
3. **The host enrols.** Every minute it looks for `<bootstrap_dir>\<san>.token` (default
   `C:\ProgramData\strugglebus\bootstrap`).
   - **The token.** It logs the arrival time, reads the token and deletes the file at once.
   - **Key and leaf.** It makes a new key and CSR (`workerhost/leafkey.py`: .NET through `pwsh -EncodedCommand`, with
     only the name and path in the script) and calls `/1.0/sign`. It then replaces the key and leaf together.
   - **Report.** It posts `leaf-issued san=...`.
   - **Failures.** A refused or unusable token leaves the old key and leaf in place.

The three lines (`leaf-needed`, `token-delivered`, `leaf-issued`) have fixed wording, so security monitoring may
match these fixed lines.

**`sbdrop`** (setup `25-access -HostUser <host user>`):

| Setting | What it is |
|---|---|
| Account | A standard local user with a random password nobody holds. Interactive, RDP, batch and service logon are denied. Network logon is left alone, because sshd's key sign-in uses it. |
| sshd | `Match User sbdrop`, placed last: `ForceCommand internal-sftp`, `ChrootDirectory` the bootstrap folder, its own `sbdrop_authorized_keys` (the token minter's drop key only, from the site's `setup/sbdrop-keys.txt`, site-specific, kept with your deployment), no password, and no forwarding, tunnel, TTY or X11. The new config must pass `sshd -t` before sshd is restarted. |
| Bootstrap folder | SYSTEM and Administrators full. `sbdrop` may list and add files, and gets write on the files it adds (CREATOR OWNER). The host user may read and delete. Nobody else. |

What to check after setup, with a throwaway key that you then remove:
- A put works.
- These are all refused: a shell ("This service allows sftp connections only"), deleting, making a folder, leaving
  the chroot, reading the host's config, and a tunnel to OpenBao.
- The host user reads and deletes the file.
- A second run of `25-access` says nothing to do.

**Asking by file.** A rebuilt host has no bus identity to ask with, because its identity is in OpenBao behind the
leaf. So it asks by file instead:
- **The request.** It writes `<san>.needed`, a timestamp only, in the drop. It does this while it has no valid leaf
  and either has no bus or has no `leaf_authority`. One file per lapse.
- **The pickup.** The token minter lists the folder over SFTP, applies its own checks and rate limit, then
  delivers `<san>.token` as above.
- **After the enrol.** The host deletes the `.needed` file, reconnects on its next bus retry (up to 5 minutes),
  and posts `leaf-issued` if it can.

**No token minter.** With `leaf_authority = ""` the host never asks on the bus; the `.needed` file is the only
request. Whoever runs step-ca at the site watches for it and drops a token, or runs `30-openbao.ps1` on the host
by hand.

## 3. Phase 2: one identity per task (needs bus 0.2.61 or later)

Turn it on with `[openbao] ttl_identities = true`.

**TTL packages:**
- The host asks for `max_runtime_hours + 1 h`, capped at 12 h, in seconds.
  - With the defaults that is 7 h: a 6 h limit, 30 min update grace and 30 min margin.
- The credential expires terminally and the bus retires it automatically.

**The package request:**
- `identity_ttl_seconds` is an optional field on `POST /api/spn/onboarding-packages`. The existing `ttl_seconds` is
  the package's own lifetime, 60-900 s.
- The bus **refuses** anything over its 43200 s cap rather than clamping it, so the host enforces the 12 h cap first.
- Leaving the field out keeps a durable identity, so phase 1 hosts keep working.

**Names:**
- One identity per task attempt: `<host>-<worker>-<yymmdd><n>`, for example `host-box1-core973-2611041`.
- The bus accepts up to 128 characters. The host keeps its own 63-character limit (`creds.AGENT_RE`).
- The coordinator still addresses the worker by `worker`. Bus names are only for provenance.

**Retire on finished:**
- At finished, failed or timed-out, the host calls `POST /api/spn/agents/{agent_name}/retire` for that identity, with
  `{"request_id"}` and the SPN credential.
- Only the SPN that created an identity can retire it. A worker's own credential, or another SPN, gets 403.
- Retiring is idempotent, so a retry after a crash is safe.
- What survives a retirement:
  - the worker's posts, with their sender name, and its claims stay readable;
  - the identity drops out of agent discovery;
  - mentions to it are refused.

  So a coordinator can still read everything a finished worker posted, but cannot @ it.
- It then destroys the OpenBao entry. After phase 2 a live entry exists only during a task.

**Resume after phase 2:**
- The host mints a fresh TTL name and retires the old one. No worker entry needs to be kept in OpenBao.

**SPN rotation:**
- Done in the nightly maintenance window every `[openbao] spn_rotate_days` (default 30; 0 turns it off), and on
  demand with `wh openbao rotate-spn` after any suspected leak.
- `POST /api/spn/credentials/rotate` returns the successor once. The old SPN keeps working for a short overlap
  (60 s), and the host writes the successor to OpenBao and reads it back inside that overlap.
- A lost response means the owner rotates the SPN from the bus console and seeds it again.

**Audit:**
- The bus feed's package-issue and redeem events name the SPN and the minted identity.
- The host's started post carries the bus name it minted, so security monitoring can flag a name that no task asked
  for.

## 4. The risk that remains, and a proposed fix (P1b)

**The risk:**
- The host and every worker run as the same Windows user.
- So any worker can read the leaf key, log in to OpenBao as the host and read the SPN.
- It can also read the host's memory and other workers' environments.
- Phase 2's TTLs bound **worker** credentials, not this.
- Treat it as an accepted risk until P1b. Without OpenBao it is worse: the SPN is readable straight from `spn.bin`.

**Proposed P1b: workers run as a separate local user.** Not built.
- **The account.** Setup creates a standard (non-admin) local user, `sbworker`. Its password is generated, held in
  OpenBao at `agents/<host>/worker-user`, and never typed by anyone.
- **Starting workers.** The host starts each worker with `CreateProcessWithLogonW` as `sbworker`, still suspended,
  inside the host's job object.
- **What it protects.**
  - The leaf key, the host's state and logs stay owner-only to the host's user. `sbworker` can't read them.
  - A process running as another user can't read the host's memory.
  - So a worker can no longer reach the SPN.
- **What it does not protect.** Workers share `sbworker`, so they can still read each other's
  `SB_BUS_TOKEN`. Phase 2's TTLs bound that.
- **Costs:**
  - Copilot and gh need their own sign-ins as `sbworker`: device-code, once per build.
  - `workers_root` and `TEMP` are granted to `sbworker`.
  - The salvage, commit and push steps the host runs inside a clone must work across the two users. git's
    `safe.directory` needs setting.
- **When.** Best done at a host rebuild, rather than later as a migration. It needs nothing from the bus.

**Security conditions for P1b.** All would be part of the build:
1. **No access to host files.** `sbworker` gets no read access to the host state folder, the leaf key, the step
   config or the host's files. This is **tested, not assumed**: setup prints an `icacls` dump, and a setup check
   fails if `sbworker` can open any of them.
2. **The password.** It lives only at `agents/<host>/worker-user`. It is rotated in the same window as the SPN: the
   host runs `Set-LocalUser`, then writes a new version to OpenBao. Nobody ever types it.
3. **A standard user only.** No admin rights. Network and RDP logon are denied by local policy
   (`SeDenyNetworkLogonRight`, `SeDenyRemoteInteractiveLogonRight`), so a leaked password gives a local foothold only.
   The `25-access` SSH and RDP rules never include it.
4. **Monitoring.** Each spawn is a Security-log 4624 logon of type 2 for `sbworker`. The host logs each spawn's time,
   so security monitoring can match the two.
5. **The password in host memory.** `CreateProcessWithLogonW` holds the password in host memory. That is the same
   class of risk as the SPN, and accepted.

A host policy of `agents/<host>/*` already covers `agents/<host>/worker-user`.

## 5. What the site provides

| Who | What |
|---|---|
| Whoever runs step-ca | A provisioner for client-auth leaves named `<host>.<san_domain>`, with renewal by the leaf itself; network access from each host to OpenBao and step-ca; a way to deliver one-time tokens (by hand, or a token minter, section 2.7) |
| Whoever runs OpenBao | The cert auth role and the `agents/<host>/*` policy for each host, including destroy rights on `workers/` and `metadata/`; audit logging |
| The bus | For phase 2: `identity_ttl_seconds` on the package request, SPN retire by provenance, SPN self-rotation |
| The owner | The SPN, typed once per SPN (`wh openbao seed-spn`); the first token for a host if there is no token minter |
| A security agent (optional) | Watching the fixed status lines and the audit trails |

## 6. Build order

| # | Step | Needs |
|---|---|---|
| W1 | `openbao.py` and its tests | - |
| W2 | Host: spawn and resume from OpenBao, `SB_BUS_TOKEN`, fail closed, the heartbeat field | W1 |
| W3 | `30-openbao.ps1`, `wh openbao seed-spn` and `migrate` | W1, a step-ca provisioner |
| W4 | (P1b, if wanted) workers as `sbworker` | W2 |
| W5 | Signed release with W1-W3 (and W4) | W2, W3 |
| W6 | Cutover on each host (section 2.5) | W5, the OpenBao policy |
| W7 | Phase 2: TTL packages, dated names, retire on finished, SPN rotation | bus 0.2.61 |

The code for W1-W3 and W7 is in this repository. W4 is not built. W5 and W6 are each site's own steps.
