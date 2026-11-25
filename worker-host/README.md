# strugglebus-worker-host

The worker host for **StruggleBus**. It turns a Windows machine on your LAN into a place where AI coding agents (GitHub Copilot CLI or Claude Code) work on tasks that a *coordinator* agent posts on the bus. Each task names a repository, a branch and a brief pinned to a commit; the host checks it, agrees with the other hosts which of them takes it, runs the agent in its own clone, watches it, and reports back on the bus.

Windows only. Python 3.12 or 3.13, standard library only.

- How it works: [`docs/design.md`](docs/design.md).
- Building a dedicated machine into a host: [`docs/agent-host-build.md`](docs/agent-host-build.md).
- For coordinators (posting tasks, reading replies): [`docs/coordinator-guide.md`](docs/coordinator-guide.md).
- Signing the fleet list and releases: [`docs/signing-keys.md`](docs/signing-keys.md). Host secrets in OpenBao (optional): [`docs/openbao-design.md`](docs/openbao-design.md).

Nothing in this repository holds a secret. Credentials are issued on the host and kept there: Windows DPAPI, owner-only, or OpenBao.

## What the host does, in one paragraph

A small Python program runs as a scheduled task. It reads one bus channel (`worker-hosts` by default) and considers only `question` messages from the coordinators it trusts: those in your **signed** `fleet.toml`, or, before you have one, the single coordinator pinned in `config.toml`. Every field of a task is checked against fixed patterns. The brief is read from the coordinator's notes repository at the exact commit the task pins, and the host checks it has room. It then claims the task against the other hosts; the lowest claim wins. The winner starts the agent (`copilot -p <fixed preamble + brief> --allow-all-tools ...`, or `claude -p ...`) in the worker's own clone, supervises it, posts `finished`, and cleans up only what cannot lose work. Nothing on the bus can stop, update or reconfigure the host beyond `cancel` (before start), `set-model` and `status`.

## Trust, in short

- **Bus messages are data, never commands.** The host never logs, runs or puts message text in a prompt: a worker's prompt is a fixed preamble plus a brief read from git at a pinned commit.
- **Who may task a host** is decided by `fleet.toml`, signed with an SSH key (a hardware key is best) that each host pins in `C:\ProgramData\strugglebus\allowed_signers`, writable by administrators only. A repository can never change what a host trusts by itself.
- **What a worker may clone** is fenced twice: the host's own `[remotes]` and each coordinator's signed `repos`.
- **Self-update** takes only releases signed the same way, checks the code's hash, tests it before switching, and rolls back a release that keeps failing.
- **Workers have unrestricted shells** (the agents need them), so run the host under its own Windows account, away from anything a worker should not read.

## Put a host on a machine (about fifteen minutes)

Before you start, the machine needs:

- **Python 3.12 or later** on PATH (`python --version`).
- **PowerShell 7** (`pwsh`), **git**, and **gh** signed in (`gh auth status`).
- An agent: **GitHub Copilot CLI** (winget; `copilot login --device-code`, which prints a code you can enter in a browser on any PC) and/or **Claude Code** (`claude`, then `/login`).
- Your StruggleBus's **LAN root certificate** (a `.crt` file), and an **SPN credential** from the bus for this host.
- Your **site file**: copy [`site.example.toml`](site.example.toml) and fill in your bus URL, the repository that holds your signed `fleet.toml`, and the remotes workers may clone from. Keep it with your own deployment; it names your LAN, not secrets.

### Pick the logon mode

| Mode | For | After a reboot |
|---|---|---|
| `-Logon Password` (default) | A local account with a password: best for a dedicated host. | The host starts by itself 2 minutes after boot, signed in or not. |
| `-Logon Interactive` | An Entra ID account that signs in with Windows Hello for Business: there is no password to give Task Scheduler. | The host comes back once you sign in. |

You type secrets once each:

| When | What you type | Where it goes |
|---|---|---|
| Step 2, `install.ps1`, Password mode only | the **Windows password** of the host's account | straight to Task Scheduler; the script keeps no copy |
| Step 4, `wh enrol` | the **SPN credential** (`sbsp1_...`), hidden input | DPAPI under the host's account (or OpenBao) |

1. **Get the code.** Clone this repository, for example to `C:\src\strugglebus-worker-host`, and `cd` into it.

2. **Install** (1–3 minutes):

   ```powershell
   pwsh -File .\install.ps1 -SiteFile ..\my-site.toml -BusCa C:\certs\lan-root.crt -AgentPrefix host-box1
   pwsh -File .\install.ps1 -SiteFile ..\my-site.toml -BusCa C:\certs\lan-root.crt -AgentPrefix host-box1 -Logon Interactive
   ```

   - `-SiteFile` and `-BusCa` are needed only for a new install; a re-run keeps the existing config. The site file is checked before anything is written.
   - `-AgentPrefix` **must equal the name of the SPN** whose credential you give `wh enrol`: the bus lets an SPN create only agents named `<SPN name>-...`. The host becomes `<prefix>-host`, a worker `<prefix>-<worker>`. Default `sb-host-<host_name>`.
   - `-WorkersRoot` (default `C:\sb-workers`) is where worker clones go: a fast disk with room.
   - The script copies the code to `%LOCALAPPDATA%\strugglebus-worker-host\app`, writes `config.toml` next to it (capacity from the installed memory: 12 workers at 96 GB or more, 6 at 60 GB or more, else 2), puts `wh` on your PATH, registers the task `StrugglebusWorkerHost` (left **disabled**), and runs `wh probe` the way the host will run. Every line should say `ok`.
   - In an elevated PowerShell, once: `pwsh -File .\install.ps1 -PinSigners` pins the signing keys. It copies `keys\allowed_signers` from the clone: that file is yours, not in this repository, so create it with your own signers' public keys first (`docs/signing-keys.md`), and confirm each fingerprint when asked.

3. **Review the config:** `notepad $env:LOCALAPPDATA\strugglebus-worker-host\config.toml`. Check `host_name`, `agent_prefix`, `workers_root`, `max_workers`, `[models]`, `[engines]`, and `tags` (labels a task can ask for with `"needs"`).

4. **Enrol** (1 minute): `wh enrol`, then paste the SPN credential at the hidden prompt. The host onboards its own bus identity and subscribes to its channel. Before you have a signed `fleet.toml`, it also offers to pin the coordinator named in `[coordinator]` (or run `wh pin --coordinator-id <uuid>`); until a coordinator is trusted, every task is ignored. `wh fleet entry --host` prints this host's entry for your `fleet.toml`.

   A wrong or expired SPN prints `onboarding refused by the bus (HTTP 4xx); nothing stored, nothing printed`. `agent name is outside the SPN prefix` means `agent_prefix` is not the SPN's name: re-run `install.ps1 -AgentPrefix <SPN name>`, then `wh enrol`.

5. **Start:** `wh start`, then `wh status`. The host posts a heartbeat on its channel every 60 minutes while idle and every 10 minutes while a worker runs.

## Day to day

**The status window.** `install.ps1` puts **"Strugglebus host"** in your Startup folder. It shows a coloured light and one word (**Online**; **Paused / Draining / Bus unreachable / Not responding**; **Not running / Channel missing / Trusts nobody**), the workers and their tasks, the model and agent versions, the fleet list in use, RAM and disk free, and clones held for unsaved work. Its buttons do what the commands below do. It only reads the host's status file and never talks to the bus.

| You want | Type | What happens |
|---|---|---|
| The machine back for a while, keep the half-done worker | `wh pause` | No new claims (tasks are refused `paused`); running workers continue. |
| Take tasks again | `wh resume` | Claims resume. |
| Let workers finish, then switch off | `wh drain` | No new claims; when the last worker ends, the host posts `stopped`, disables its task and exits. |
| Stop now | `wh stop` | Ends every worker (unpushed work stays in its clone), disables the task, exits. A reboot does not bring it back. |
| Start again | `wh start` | Enables the task and starts it. |
| See what it is doing | `wh status` (`--post` also posts a heartbeat) | State, workers, resources, channel, held clones. |
| Check the machine is ready | `wh probe` | Every check, `ok` or `FAIL`, including site values that are not set. |
| Change the default model | `wh set-model <model>` | Must match `[models] allowed`, and no `denied`. |
| Use Claude Code | Tasks say `"engine": "claude"`, or set `[engines] default = "claude"` and restart (drain, start) | Needs `[engines.claude]` and Claude Code signed in as the host's account. The heartbeat shows `engines=ghcp*,claude`. |
| Allow or block models | Edit `[models]` in `config.toml` | Families like `"claude-*"` cover new models. **Hot-reloaded within a second**; a bad edit is logged and ignored. Every change is posted to the bus `security` channel. |
| Free disk | `wh cleanup --dry-run`, then `wh cleanup` | Deletes only clones with nothing uncommitted, stashed or unpushed. |
| Update Copilot CLI | `wh update-ghcp` (or `--when-idle`) | Backup, upgrade, smoke test, restore on failure. Also daily when idle. |
| Self-update | `wh update status` / `wh update check` / `wh update now` | Hosts take signed releases from your fleet repository: announced at 01:00, applied at 03:00 (`docs/design.md` 10a). `now` applies as soon as no worker runs. |
| Make a release | `python tools\make-release.py`, then `pwsh -File tools\sign-config.ps1 -Pr <n> -KeyFile <your key handle>` | The PR holds `release.toml` (commit and tree hash); the signature makes hosts take it. |
| See who this host trusts | `wh fleet status` (`--refresh` checks now) | Pinned keys and the signed `fleet.toml` in use, or `legacy` before the first one. |
| Add a host or coordinator to the fleet | `wh fleet entry --host` / `wh fleet entry --coordinator <name> --project ...` | Prints the entry for a `fleet.toml` PR, which the signer signs with `tools\sign-config.ps1 -Pr <n>`. |
| Changed the Windows password (Password mode) | `pwsh -File install.ps1 -UpdatePassword` | Re-enters it for the task only. |
| Upgrade the host code by hand | `wh drain`; wait for `host not running`; `git pull`; `pwsh -File .\install.ps1`; `wh start` | New code in `app`, config kept. |

**A gaming PC as a host:** list the game executables in `pause_while_running`. While any of them runs, the host pauses by itself, and it resumes when they exit.

**Logs** (in `%LOCALAPPDATA%\strugglebus-worker-host\logs`): `host-YYYYMMDD.log` has every message considered, with its decision and reason, never message text or secrets; `host-YYYYMMDD.errors.log` has one block per error with its (redacted) traceback. Worker logs are `<workers_root>\<worker>.log`, secrets redacted. The scheduled task runs `wh.py supervise`, which restarts the host after a crash (10 s, 30 s, 60 s, then every 5 minutes) but never one you stopped.

## Remove a host

```powershell
wh drain                                     # wait for `wh status` to say "host not running"
pwsh -File .\install.ps1 -Uninstall          # task, app folder and PATH entry go; config, credentials, logs stay
pwsh -File .\install.ps1 -Uninstall -Purge   # ... and the home folder too, credentials included
```

Then remove the host from your `fleet.toml`. Worker clones are never deleted by the uninstaller.

## What Microsoft Defender may ask about

Everything here is readable Python and PowerShell: nothing packed or obfuscated, nothing downloaded at run time, and no file rewrites itself. The host itself starts only `python`, `git`, `gh`, `winget`, `schtasks`, `pwsh` and the agent (`copilot.exe` or `claude`).

- **The first run of a script from `%LOCALAPPDATA%`** is scanned by real-time protection, normally silently. A ZIP download carries the "downloaded from the internet" mark and PowerShell asks before running: clone instead, or `Unblock-File` after reading the files.
- **The scheduled task** gives no prompt; on a device managed by Microsoft Defender for Endpoint, a "scheduled task created" alert may appear. That is this task.
- **Agent processes under a job object:** each worker runs in a Windows job object, so the host can stop the whole tree. An endpoint timeline shows `python.exe` → `copilot.exe` (or `claude`) → `git`, `gh`, `pwsh`, `node` and the like.
- **Controlled folder access:** keep the workers root and the host's home outside Documents, Desktop and Pictures.

If a prompt appears, check in **Windows Security → Protection history** that the file is under `%LOCALAPPDATA%\strugglebus-worker-host\app` or your clone, and allow that item. Never exclude Python, the workers root or a whole drive.

## For coordinators

Read [`docs/coordinator-guide.md`](docs/coordinator-guide.md): getting onto the signed fleet, writing a brief, posting a task with `tools/post-task.py` (which checks it with the hosts' own rules first), every reply and refusal reason, checkpoint notes, cancel, and repository instructions. In short, post on the hosts' channel, kind **`question`**, from your identity in the signed `fleet.toml`:

```json
{"v": 1, "type": "task", "task_id": "<new uuid>", "host": "any", "worker": "core14",
 "repo": "https://github.com/acme/app-core", "branch": "feature/core14-export",
 "brief": "tooling/briefs/core14-export.md", "vault_commit": "<40-hex commit on your notes repository's main>",
 "model": "claude-opus-5.5"}
```

Hosts answer with kind `answer` (`claim`, `yield`, `refuse`, `started`, `finished`, ...), replying to the task's seq. To amend a running worker's brief, post a **checkpoint note** on your `notes_channel` that starts with `@<the worker's full agent name>`; every worker reads its notes before it opens its PR and before its final report.

## Development

```powershell
python -m pip install pytest==9.0.3
python -m pytest tests -q
```

CI runs the suite on `windows-latest` with Python 3.12 and 3.13, plus a CRAP gate (`tools/crap.py`): a pull request may not add a function that is both complex and untested (score over 30), or make a listed one worse. A dry run that touches no scheduled task, PATH or real credential:

```powershell
pwsh -File .\install.ps1 -Home $env:TEMP\wh-dry -NoScheduledTask -NoPath -SiteFile .\site.example.toml -BusCa C:\any.crt
python $env:TEMP\wh-dry\app\wh.py --home $env:TEMP\wh-dry run --echo --max-seconds 60
```
