# Agent host build: `setup.ps1` for a fresh Windows machine

Status: partly built. The install USB (section 5), debloat (6.1), power and Windows Update policy (6.2), remote
access (6.3), OpenBao (6.4), the multi-project host (7), the engines (7.6), the restart rule (9.2) and self-update
(9.4) are built. `setup.ps1`, `bootstrap.ps1`, `baseline.toml` and the remaining steps are design. This document is
the brief for building a dedicated Windows machine into a worker host. It extends `design.md` (the worker host
itself) with the machine the host runs on.

## 1. Goal

Install Windows 11 Enterprise from a USB stick, answer a handful of prompts, do the sign-ins, and the machine is
taking tasks for any project within the hour. Hosts are rebuilt regularly, so everything about a machine is either
asked at setup or comes from this repository and your site file; nothing lives only on the box. The same script
re-run on an existing box converges it to the same state (idempotent): that is how existing boxes are cleaned up in
place, and how the script is tested before any rebuild.

Security patching is a first-class job of the build: Windows, the apps and the tools are kept current every night
(section 9).

A dedicated host is a pure agent host. Other services (a SIEM, a database) belong on other machines.

## 2. Machines, profiles and switches

| kind | examples | profile |
|---|---|---|
| **Dedicated agent host** | a machine built or rebuilt for agent work only | `dedicated` |
| **Work-managed machine** | a cloud dev box, any machine whose Defender, updates and policy belong to an IT department | `managed` |
| **Daily-use machine** | a desktop or laptop someone works on | none: this build does not run on them. A daily-use Windows machine can still run the host with `install.ps1` |

A dedicated host is Windows 11 **Enterprise**, signed in with a **local account with a password** (no Windows
Hello, no Microsoft account, not Entra- or domain-joined), and does nothing but agent work.

Every part of the baseline is a switch, and the profile only sets the defaults. The `managed` profile is designed
alongside `dedicated`, so a work-managed machine is a configuration choice rather than a rewrite.

| switch (`host.toml`) | what it controls | `dedicated` | `managed` |
|---|---|---|---|
| `debloat` | section 6 | on | off |
| `policy` | power, time, diagnostic data, consumer features, long paths | on | off |
| `security` | the section 8 table (firewall, RDP, audit, legacy protocols) | on | off |
| `defender` | `exclusion`, `devdrive` or `none` (section 8) | `exclusion` | `none` |
| `wazuh` | the Wazuh agent | on | off |
| `sysmon` | Sysmon with the SwiftOnSecurity config | off | off |
| `windows_update` | the update policy in `baseline.toml` (section 9) | on | off (IT owns it) |
| `app_updates` | the nightly tool and app updates (section 9) | on | on |
| `wsl` | WSL 2 with Ubuntu (section 11) | on | on, if policy allows it |
| `logon` | the scheduled task's logon mode (section 10) | `Password` | `Interactive` |

Tools, the worker drive layout and the host itself are installed in every profile.

## 3. The flow the owner runs

1. Boot the Windows 11 Enterprise USB (latest release). It carries your site's `autounattend.xml` (site-specific, kept with your deployment)
   (section 5), which answers every setup screen except the local account name and password, and the disk.
2. At the first sign-in, bootstrap starts by itself. On an existing box: elevated PowerShell,
   `irm <raw url of bootstrap.ps1 at a release tag> | iex`, or run it from the USB. Bootstrap installs git, clones
   this repository to `C:\strugglebus-worker-host` at that tag, and runs `setup.ps1` elevated.
3. `setup.ps1` asks, once each (only the ones its switches need):
   - the **profile** (default `dedicated`);
   - the **Windows password** of this account, for the scheduled task (section 10; `Password` logon only);
   - the **bus SPN API token**;
   - the **Wazuh enrolment key** (`wazuh` on only);
   - which **drive holds the workers** (it lists fixed drives with size and free space; default: the largest
     non-OS drive, or C: if there is only one). If that drive is not C:, it then asks how Defender should treat it:
     **exclusion** (default), **Dev Drive** (reformats the drive; asked again to confirm) or **leave Defender
     alone** (section 8);
   - the **host short name** for the bus (default: the machine name, lower-case; the machine is renamed to match
     if it differs).

   Secret handling is in section 12. The site's values (bus URL, fleet repository, clone fence, OpenBao) come from
   your site file (a copy of `site.example.toml`), passed to `install.ps1 -SiteFile <site.toml>` together with the
   bus's root certificate (`-BusCa`). Everything else comes from `host.toml` (per machine, gitignored),
   `baseline.toml` (fleet-wide, this repository) or defaults.
4. The script runs its steps (section 4), reboots if a step needs it, resumes, and ends by printing the sign-ins.
5. The owner signs in, interactively:
   - `gh auth login` once for each GitHub account whose organisations the workers use. Git Credential Manager
     keeps one credential per organisation (section 7.5).
   - `copilot` (GHCP CLI), if the host runs Copilot workers.
   - `claude` (Claude Code), if the host runs Claude Code workers.
   - Any other git server (for example a LAN Forgejo at `https://git.example.lan/`): a token in Git Credential
     Manager.
   - Azure CLI (`az login`) and Microsoft Graph are signed in by hand only when a project needs them; they are not
     part of setup.
6. `setup.ps1 -Only 90-selfcheck`: every step's check again, plus the sign-ins. If this host is not yet in
   `fleet.toml` (or its agent_id changed in a rebuild) it opens a PR adding or updating its entry. It posts
   `host=<name> state=ready` on `worker-hosts`.
7. The owner signs and merges that PR with one command (section 7.2). Within 15 minutes every host counts the new
   host's claims. There is no step on the coordinator side: any coordinator in `fleet.toml` can task it.

## 4. Repository layout for this work

```
bootstrap.ps1            git + clone at a tag + run setup.ps1 (about 50 lines; no logic)
setup.ps1                orchestrates the steps; -WhatIf prints the plan; -Only <step> runs one
autounattend.xml         the install USB's answer file (section 5); site-specific, kept with your deployment
site.example.toml        the template for your site file (install.ps1 -SiteFile)
fleet.toml  (+ .sig)     the coordinators and hosts every host trusts (section 7.2); signed by the owner
baseline.toml (+ .sig)   fleet-wide update settings and the tool list (section 9); signed by the owner
tools/sign-config.ps1    run by the owner on a signing PC: review, sign, push and merge a fleet, baseline or release PR
tools/prepare-usb.ps1    finishes the install USB (section 5.1); not in this release yet
tools/grant-ssh.ps1      adds an SSH key to a new host (section 6.3)
keys/allowed_signers     the public halves of your signing keys (site-specific, kept with your deployment); confirmed by fingerprint
.gitattributes           fleet.toml, baseline.toml and *.sig as -text (signed bytes never change)
setup/
  00-inventory.ps1       hardware, drives, RAM, Windows edition -> setup/state.json (gitignored)
  05-signers.ps1         pins keys/allowed_signers in C:\ProgramData\strugglebus after checking it against a
                         plugged-in security key and the owner's own copy of the fingerprints (signing-keys.md)
  10-debloat.ps1         built: apps, optional features, default-user settings (section 6; list in setup/debloat.txt)
  20-policy.ps1          built: power (never sleep on mains, 6.2), long paths (worker trees go past 260
                         characters), Windows Update restart times (9.2); later: time, diagnostic data
  25-access.ps1          SSH, RDP and C:\sshdrop, LAN only (section 6.3); not in this release yet
  30-openbao.ps1         built: the host's leaf certificate for OpenBao (section 6.4)
  30-security.ps1        firewall, RDP, audit policy, SMB, PowerShell logging (section 8)
  35-defender.ps1        exclusion, Dev Drive or nothing (section 8)
  40-tools.ps1           the tool list in baseline.toml (section 9)
  42-wsl.ps1             WSL 2, Ubuntu, .wslconfig with a memory cap (section 11)
  45-trust.ps1           the site's LAN root certificate for git and the bus (per URL; machine store untouched)
  50-layout.ps1          worker drive, \workers \wt \tools \drop, pagefile, config.toml
  60-wazuh.ps1           agent MSI, enrol, group windows, service running
  70-host.ps1            install.ps1 -SiteFile -BusCa -Logon <mode>, wh enrol --spn-stdin, first wh start
  80-maintenance.ps1     the nightly maintenance task (section 9)
  90-selfcheck.ps1       every step's check again; fleet.toml PR if needed; posts ready on the bus
host.toml.example        per-machine values: profile and switches, LAN subnet, Wazuh manager, drive, host name
docs/agent-host-build.md this file; docs/security-standard.md once agreed
docs/signing-keys.md     runbook: security-key enrolment, signing PCs, signing, lost keys
```

Every step is a function with a `Test-` (is it already done?) and a `Set-` (do it), and is skipped when its switch
is off. `setup.ps1` runs `Test-`, skips if true, else `Set-` then `Test-` again and fails loudly if still false.
That is the whole idempotence mechanism; no DSC. The built steps follow the same shape: `-WhatIf` prints the plan,
`-Check` exits 0 when there is nothing to do.

## 5. Install media: `autounattend.xml`

**Not in this release yet:** the answer file, `tools/prepare-usb.ps1` and `setup/25-access.ps1` are still tied to the
authors' own hardware and LAN. Sections 5, 5.1 and 6.3 describe what they do, so you can do the same by hand or write
your own; generic versions are planned.

- The latest Windows 11 Enterprise ISO from your volume licensing, written to a USB stick with `autounattend.xml`
  at its root (and `bootstrap.ps1` beside it).
- The file answers the language and locale, the keyboard and the time zone, accepts the licence, and skips the
  privacy, network and Microsoft-account pages. The authors' file sets locale **en-AU**, keyboard **US** and time
  zone **AUS Eastern Standard Time**; edit those three for your region.
- Windows still asks for the **local account name and password**, so no password is ever in the file, and for the
  disk, so a wrong guess cannot wipe one.
- **If setup insists on a work or Microsoft account and shows no local option:** recent Windows 11 builds can
  ignore `HideOnlineAccountScreens`, even on a machine not in Autopilot. Autopilot registration causes the same
  screen. Either:
  - unplug the network and restart setup; or
  - press Shift+F10 and run `start ms-cxh:localonly`, which opens the local-account page.

  If the device is registered in Autopilot (Intune: Devices > Enrollment > Windows Autopilot devices), remove it so the
  next rebuild is not caught again. A dedicated host is never Entra-joined (section 2).
- At the first sign-in it starts bootstrap elevated. Not in the file yet: it is added when `bootstrap.ps1` exists.
- The edition is picked with Microsoft's published generic (KMS client) key for Windows 11 Enterprise, which
  selects the edition and does not activate it. Activation is separate, against your licensing.
- Windows UI is the ISO's language; formats and keyboard are as above.
- Automatic device encryption is prevented (`PreventDeviceEncryption`), so a clean install does not turn BitLocker
  on by itself (section 8: BitLocker off).
- A spare machine built from the same USB, or the VM in section 13, is the test bench.

### 5.1 Making the USB, drivers included (`tools/prepare-usb.ps1`)

1. **Rufus** (`winget install Rufus.Rufus`): the Enterprise ISO (the "business editions" ISO carries Enterprise),
   partition scheme **GPT**, target **UEFI (non CSM)**, file system as Rufus picks (NTFS: the install image is
   over FAT32's 4 GB limit). If Rufus offers "Windows User Experience" options, untick all of them: the answer
   file does that job.
2. **The rest**, from a clone of this repository:
   ```powershell
   pwsh -File tools\prepare-usb.ps1 -Drive I: [driver-pack switches]
   ```
   The script has one switch per hardware model whose driver pack it knows how to unpack (see
   `Get-Help tools\prepare-usb.ps1`). Every driver switch can be left out. Re-running it replaces only what it wrote.
   - `autounattend.xml` at the root.
   - `$WinPEDriver$\<model>\`: drivers Windows Setup installs by itself. Setup looks for this folder on every
     drive, installs what matches the hardware into the new Windows and ignores the rest, so one USB serves every
     model and the network works at the first sign-in. No change to `autounattend.xml` is needed for it.
   - `drivers-after-setup\<model>\install.cmd`: vendor installer programs Setup cannot preload. Run it once after
     the first sign-in (right-click, Run as administrator); it runs each installer in turn.
   - `strugglebus-setup\`: this repository's `setup\` steps. At the new machine, run `25-access.ps1` first,
     elevated (section 6.3). It sets up SSH, RDP and `C:\sshdrop`. After that, `tools\grant-ssh.ps1` runs from your
     own computer, and everything else happens over SSH.
   - Every `.exe`/`.msi` copied must carry a valid signature, or the script stops.
3. **Driver packs:**
   - Use the vendor's own pack for the model. A pack shipped as an MSI is unpacked with an administrative install
     (nothing is installed on the PC running the script).
   - **Never preload firmware** (`Class=Firmware` INFs): firmware is left to Windows Update, so Setup never flashes
     a machine.
   - **Preload only the network.** Setup stops with `0xE0000219 - 0x40031` (SPAPI_E_NO_ASSOCIATED_SERVICE) when a
     matching preload package has no service: `Class=Extension`, `SoftwareComponent` or `AudioProcessingObject`
     INFs, which audio and graphics packs carry. Everything that is not needed to reach the network goes to
     `drivers-after-setup` and `pnputil`.
   - A pack that carries such INFs but matches only its own model's hardware is usually harmless on other models.
     To be safe on a different model, park that model's folder outside `$WinPEDriver$`; re-running the script with
     its switch puts it back.
   - A new model: add its pack to the script the same way (plain `.inf` drivers to `$WinPEDriver$`, installers to
     `drivers-after-setup`), and keep firmware out of the preload.
4. Two models' packs fit on a 64 GB USB with plenty to spare (about 5 GB together).

## 6. Debloat (`setup/10-debloat.ps1`, `dedicated` only)

Enterprise is the base because it honours the policies that keep consumer content off the machine
("Turn off Microsoft consumer experiences", Start and lock-screen suggestions off). Pro ignores several of them.

Each item is removed three ways:
1. the installed package, for all users;
2. the provisioned package, so new profiles do not get it;
3. a policy, where one exists, so Windows does not reinstall it.

Per-user settings (taskbar, Start, Explorer) are written to the current user and to the Default user profile. The
nightly maintenance (section 9) re-runs this step, because feature updates put some apps back; normally it changes
nothing, and when it does the log says what.

`setup/debloat.txt` holds one entry per line, with a comment. It is short and reviewed, and every line can be
undone: the file's header says how, kind by kind. The entry kinds:
- `app <name>`: removed for every user and as a provisioned package;
- `keep <name>`: never removed. A trailing `*` is allowed, for a family such as the handwriting packs;
- `feature <name>`: an optional feature, disabled;
- `policy <HKLM\path> <value> <dword>`: a machine policy;
- `user <Software\path> <value> <dword>`: written for the running user and the Default profile;
- `onedrive`.

Names are exact; only a `keep` may end in `*`. The package names were checked against a fresh 26H2 Enterprise
image. Lines for packages that only older images have are marked "(not on 26H2)" and do nothing when the package is
absent.

**Safety rails in the script:**
- Store, App Installer, Edge, WebView2, Windows Security, Terminal, PowerShell and the frameworks are protected in
  the script itself. An `app` line naming one of them, or anything a `keep` line covers, stops the run before any
  change.
- Packages the list neither removes nor keeps are printed at the end as "not in the list". Only removable packages
  are printed, not Windows' own system packages, so anything a feature update adds shows up for review. On the 26H2
  image that line is empty.
- After applying, it reads the machine again. It fails loudly if anything is still to do.

### 6.1 Running it (built; `setup.ps1` will call it as `-Only 10-debloat`)

Elevated, on the host (from PowerShell 7 it re-runs itself in Windows PowerShell 5.1, where the Appx cmdlets work):

```powershell
powershell -ExecutionPolicy Bypass -File setup\10-debloat.ps1 -WhatIf   # the plan: one line per change, nothing changed
powershell -ExecutionPolicy Bypass -File setup\10-debloat.ps1           # apply; log in C:\ProgramData\strugglebus\logs\debloat.log
powershell -ExecutionPolicy Bypass -File setup\10-debloat.ps1 -Check    # exit 0 if nothing to do (setup.ps1's Test- step)
```

Sign out and in afterwards for the taskbar and Start changes to show. On a fresh 26H2 Enterprise install the first
run makes about 90 changes (two dozen apps removed, OneDrive uninstalled); a second run says "nothing to do", and
winget, the Store and worker tasks still work.

**Remove:**
- Copilot app, Widgets (Windows Web Experience Pack), Recall (optional feature)
- Xbox app, Game Bar and the Xbox overlays and identity provider; Game DVR off by policy
- News, Weather, Bing Search; web results in Start search off by policy
- Teams (consumer), new Outlook, Clipchamp, To Do, Office Hub, Power Automate
- Phone Link, Feedback Hub, Tips, Get Help, Maps, Alarms, Sound Recorder, Dev Home, Solitaire, Cortana
- **Quick Assist** (a common tool for taking over machines by social engineering; not wanted on a host)
- OneDrive: uninstalled, and file sync blocked by policy
- Taskbar search box, Task View, Widgets and Copilot buttons; Start recommendations; lock-screen Spotlight and
  tips; "suggested" notifications; the advertising ID

**Keep** (removing these breaks things):
- Microsoft Store and App Installer (winget needs both)
- Edge and WebView2
- the VCLibs, UI.Xaml and .NET Native frameworks
- Windows Terminal, Notepad, Calculator, Snipping Tool, Paint, Photos
- Windows Security, Windows Update, the media codecs and extensions

**Deliberately not done:**
- disabling services wholesale (it breaks updates);
- blocking telemetry in the hosts file;
- removing Store, Edge or Defender;
- running third-party debloat scripts from the internet. Their lists were a reference only.

On an existing box, `setup.ps1 -WhatIf` lists every package, feature and setting it would change, and
`-Only 10-debloat` applies them; until `setup.ps1` exists, run the step itself as in 6.1. It never touches user
files, worker clones or the host. Other profiles already on the machine keep their own per-user settings: only the
running user and the Default profile are written.

### 6.2 Power: the screen turns off, the machine never sleeps (`setup/20-policy.ps1`, built)

A sleeping host drops off the bus and stops its workers. Windows' Balanced plan on a laptop typically sleeps after
10 minutes on mains, and closing the lid sleeps it too. `20-policy` is built for its power part, long paths and the
Windows Update restart times (9.2); time and diagnostic data settings join it later. On mains (AC) it sets:

| Setting | Value |
|---|---|
| Sleep after | never |
| Hibernate after | never |
| Unattended sleep timeout (after a wake-up nobody is at, e.g. for updates) | never (Windows' default is 2 minutes) |
| Turn off the screen after | 10 minutes |
| Closing the lid | do nothing |
| Power mode | Best performance |
| Hibernation and Fast Startup | off (`powercfg /hibernate off`): every restart is a real one, and the hibernation file's disk space comes back |
| `LongPathsEnabled` | 1 (worker trees go past 260 characters) |

**On battery Windows' own settings stay.** A host that loses mains power then sleeps rather than running flat.

**How it applies them:**
- Settings are read and written through Windows' power API (`powrprof.dll`) by GUID. That reaches settings
  `powercfg /q` does not show on some machines, such as a laptop's lid action and the unattended sleep timeout.
- On modern-standby machines (most laptops) Balanced is the only plan, so the active plan is changed in place.
- The power mode can only be set through the API, for the power source in use. On battery that one item waits for
  a later run; nightly maintenance re-runs the step.

Run it the same way as 10-debloat (elevated; `-WhatIf` prints the plan, `-Check` exits 0 when there is nothing to
do):

```powershell
powershell -ExecutionPolicy Bypass -File setup\20-policy.ps1 -WhatIf
powershell -ExecutionPolicy Bypass -File setup\20-policy.ps1
```

A second run says "nothing to do", and `powercfg /a` then lists only modern standby (or nothing) as a sleep state.

### 6.3 Remote access: SSH, RDP and C:\sshdrop (`setup/25-access.ps1`, built)

Every host can be reached from the LAN, the same way, and has the same drop folder.

| | What `25-access` sets |
|---|---|
| **SSH** | Windows' OpenSSH Server, running, starts at boot. Key sign-in on. **Password sign-in only while the host has no administrator key**: that is how the first key gets on. Inbound TCP 22 allowed from the LAN only (rule `strugglebus-ssh-lan`). Every other inbound allow rule for port 22 is disabled |
| **RDP** | on, Network Level Authentication required, the Remote Desktop firewall rules limited to the LAN |
| **`C:\sshdrop`** | the shared drop folder agents on the LAN use over SSH, at one path on every host. Administrators and SYSTEM full control, signed-in users modify. Has a README |

Give your LAN in CIDR form with `-Lan` (for example `-Lan 192.0.2.0/24`); `host.toml` will carry it once
`setup.ps1` exists.

**Getting the first key on a new machine** (a one-time password):
1. At the new machine, elevated, from the install USB: `powershell -ExecutionPolicy Bypass -File <usb>\strugglebus-setup\25-access.ps1 -Lan <your LAN>`.
   There is no key yet, so password sign-in is on, from the LAN only.
2. From your own computer: `pwsh -File tools\grant-ssh.ps1 -Target <user>@<ip>`.
   - `ssh` asks for that account's Windows password **in your terminal**. The script never sees it.
   - It adds your `~\.ssh\id_ed25519.pub` as an administrator key and turns password sign-in off.
   - It then checks that your key signs in.
3. Each further key is the same command from any computer that already has access, with no password. Examples:
   your other PCs, or an agent's key with `-PublicKey <agent>.pub`.

**Agent keys are administrators.** A drop-folder-only account (SFTP into `C:\sshdrop`, no shell) is a planned later
enhancement.

A second run of `25-access` says "nothing to do". `grant-ssh` reports "already there" for a key it already added.

### 6.4 Host secrets in OpenBao (`setup/30-openbao.ps1`, built; design in [openbao-design.md](openbao-design.md))

Optional: a site without OpenBao keeps the host's secrets in Windows DPAPI. With it, the host's only secret on disk
is its leaf certificate, `<agent_prefix>.<san_domain>` (`san_domain` from the site file's `[openbao]` table). The
SPN, the host's bus credential and each worker name's credential live in OpenBao under `agents/<agent_prefix>/`.

1. **Get a token.** The site's token minter (the site file's `leaf_authority`, an operations agent) mints a one-time
   token, valid for 1 h and bound to that one name. How it reaches the host is in openbao-design.md.
2. **Issue the leaf.** As the host's user, not elevated, run `pwsh -File setup\30-openbao.ps1` and paste the token at
   the hidden prompt.
   - The setup prints the leaf folder's ACL and a login check.
   - The host renews the leaf hourly by itself. A new token is needed only after a rebuild, or after 3 days off.
3. **Store the secrets.** On a new host run `wh openbao seed-spn` and paste the SPN once, ever. On a host with a DPAPI
   store, run `wh openbao migrate` instead.
4. **Switch over.** Set `[openbao] enabled = true` in `config.toml`. On a new host, run `wh enrol`. Then
   `wh stop` / `wh start`.
5. **Check.** The heartbeat shows `openbao=ok leaf=<hours>`. Run a hello task, then
   `wh openbao migrate --delete-dpapi` on a migrated host.

**If OpenBao can't be reached:**
- the host takes no new tasks, and running workers carry on;
- it posts `vault unreachable, no new tasks`, then `vault reachable, taking tasks` when it recovers.

## 7. Multi-project host

A host can work for several coordinators, each with its own project, notes repository, notes channel and set of
repositories. Projects can live on several GitHub organisations and on other git servers, such as a LAN Forgejo.
Before the first signed `fleet.toml` a host trusts one coordinator, pinned by `wh enrol` from the site file's
`coordinator`, and reads its briefs from the site file's `vault_repo`.

### 7.1 The task envelope

- `repo`: a **full clone URL**, `https://github.com/<org>/<repo>` or `https://git.example.lan/<owner>/<repo>`.
  Short names stay accepted for one release (mapped through `[repos]`), then go.
- `engine` (optional): `ghcp` or `claude` (section 7.6). Absent: the host's default engine.
- `model`: validated against that engine's allowed list.
- The project is **not** in the envelope: it comes from the sending coordinator's entry in `fleet.toml`.
- Unchanged: `host` is `any` or one host's name, which is how a task is aimed at one machine (`design.md` §4).
  `needs` tags still restrict a task to hosts that offer them.

### 7.2 `fleet.toml`: one signed list, in the fleet repository

```toml
serial = 1                                      # one more on every signed change

[[coordinator]]
agent_name     = "acme-coordinator"
agent_id       = "<uuid>"                       # from the bus; not a secret
project        = "acme"
notes_repo     = "https://github.com/acme/acme-notes"   # briefs come from here
notes_channel  = "acme"
repos          = ["https://github.com/acme/"]           # org prefixes or exact repo URLs
default_engine = "ghcp"

[[host]]
agent_name = "host-box1"
agent_id   = "<uuid>"
```

- The fleet repository is the site file's `fleet_repo`. Every host refreshes it every 15 minutes: `git fetch` into
  `<home>\fleet.git`, then it reads `fleet.toml` and `fleet.toml.sig` at `origin/main`. Nothing else in the
  repository is read or run; host code changes only through `install.ps1` or a signed release (9.4).
- **The file must carry the owner's signature.** The full runbook is `docs/signing-keys.md`. In short:
  - `fleet.toml.sig` is an SSH signature of the file's exact bytes as git stores them
    (`ssh-keygen -Y sign -n strugglebus-fleet`). The host checks it with `ssh-keygen -Y verify`.
  - The signing keys are FIDO2 keys on hardware security keys (for example YubiKeys: one daily, one spare, one
    off-site), resident, with PIN and touch on every signature. Any one of them can sign. Rebuilding a signing PC
    changes nothing on the hosts, because the key is on the security key.
  - Hosts accept only the public keys pinned at setup in `C:\ProgramData\strugglebus\allowed_signers`. Only an
    elevated prompt can write there, and the host and its workers run without elevation, so a worker cannot add a
    key. Setup reads your site's `keys/allowed_signers` (site-specific, kept with your deployment) once, shows the fingerprints for the owner to
    confirm, and never re-reads it; a change later is `install.ps1 -PinSigners` (later `setup.ps1 -Only signers`)
    on each host, by hand.
  - `fleet.toml` starts with `serial = <n>`. A host refuses a serial lower than the last it accepted
    (`fleet-old`), so an older signed file cannot be put back.
  - `.gitattributes` marks `fleet.toml`, `baseline.toml` and `*.sig` as `-text`, so line endings never change the
    signed bytes.
  - Why: the hosts obey whoever controls this file. Branch protection on `main` (PR required, tests must pass, no
    force push, no deletion) stops accidents, but GitHub cannot tell the owner from an agent using the owner's
    token, and the workers hold that token. A signature made with a key that never sits on a host can be told
    apart.
  - Agents can still propose changes (a new project, a new host). Only the owner can make them take effect.
- A valid, verified file replaces the old list and is logged. A failed fetch, an invalid file or a bad signature
  keeps the last good list (persisted in the home folder), is logged and is posted on `worker-hosts`.
- A running task keeps the coordinator it started under. A task from a coordinator that has been removed is
  refused at validation.
- **Starting a project:** the new coordinator, or the owner, opens a PR adding its entry (`wh fleet entry` prints
  one, with the agent_id looked up on the bus). **Adding or rebuilding a host:** the self-check opens the PR
  (section 3, step 6). Either way the owner runs `tools/sign-config.ps1 -Pr <n> -KeyFile <key handle>` on a signing
  PC. It shows the change, signs it, pushes the `.sig` to the PR branch and merges once the tests pass. Every host
  trusts the change within 15 minutes.

**How it works in the code:**
- `workerhost/signing.py` (the check), `workerhost/fleet.py` (the file, the URL rules of 7.3, fetch and keep),
  `tools/sign-config.ps1`, `install.ps1 -PinSigners`.
- **Before the first signed file.** A host that has never accepted a signed file uses `config.toml`'s
  `[coordinator]` pin and `[[hosts]]` (`fleet=legacy` in the heartbeat). The first accepted file replaces both, for
  good: if the kept copy later fails its check, the host trusts **nobody** (`fleet=unavailable`) until a refresh
  succeeds, rather than falling back to the old pins.
- The accepted copy, its signature and `accepted.json` (serial, sha256, commit, signer) are in
  `<home>\state\fleet\`. The kept copy is checked again at every start.
- Refresh outcomes, logged (and the ones marked * posted on `worker-hosts` once per commit): `fleet-accepted`*,
  `unchanged`, `fleet-missing` (no file on main yet), `fleet-unsigned`* (no or malformed `.sig`),
  `fleet-bad-signature`*, `fleet-cannot-verify`* (this host has no pinned list or no ssh-keygen), `fleet-invalid`*,
  `fleet-old`* (serial not higher than the last accepted, including the same serial with different bytes),
  `fetch-failed`.
- The heartbeat shows `fleet=<serial>:<short commit>`, or `fleet=legacy` / `fleet=unavailable`.
- Keys the host does not know in `fleet.toml` are ignored and logged, not refused, so adding a field for a newer
  host does not stop older ones.
- Every task records the coordinator that sent it. Only that coordinator can cancel it; resume after a reboot
  needs the same coordinator, still in the fleet; the worker's notes come from that coordinator.
- `wh fleet status [--refresh]` and `wh fleet entry --host | --coordinator ...` (section 3, step 6).

### 7.3 The guard on clone URLs

`fleet.toml` says which repositories each coordinator may use. The host's own `config.toml` keeps an outer fence,
written from the site file's `remotes` when `install.ps1 -SiteFile` makes a new config, so even a signed mistake in
`fleet.toml` cannot point hosts anywhere else:

```toml
[remotes]
allowed = [
  "https://github.com/acme/",
  "https://github.com/acme-labs/",
  "https://git.example.lan/",
]
```

A config without the table allows `https://github.com/` only.

A task's `repo` must match a prefix in **both** the coordinator's `repos` and `remotes.allowed`. The URL must also
pass these rules (`workerhost/urls.py`), or it is refused with `reason: shape, field: repo`:
- the scheme is `https`;
- the host is lower-case, with no user name, password, port, query or fragment;
- the path is exactly `/<owner>/<repo>` with an optional `.git`;
- names match `[A-Za-z0-9_.-]+` and are not `.` or `..`.

ssh, `file:`, `ext::` and every other transport are refused. Prefix matching compares whole path segments, so
`https://github.com/acme/` does not match `https://github.com/acme-evil/`. A new organisation means editing
`[remotes]` in each host's `config.toml` (later: `host.toml` and `setup.ps1 -Only 50-layout`); that is rare, and
deliberate.

### 7.4 Per project

- **Repository.** `repo` may be a full clone URL under the coordinator's `repos` and the host's fence (7.3). A short
  name still works for one release: it maps through `[repos]` to `https://github.com/<owner/repo>`, and that URL
  must then pass the same two prefix checks.
- **Briefs** are read from the sending coordinator's `notes_repo`, one mirror each:
  `<home>\vaults\<host>--<owner>--<repo>.git`. The legacy single-coordinator `vault_repo` keeps `<home>\vault.git`.
  The heartbeat's `vault=failing` covers every mirror.
- **Worker preamble.** A fleet coordinator's workers get a project preamble. It names the project, the coordinator
  (questions go to `@<coordinator>`) and the notes channel (status posts and notes). It ends with the project's
  rules from the signed file. The preamble keeps the hard rules ("never push to develop, main or master") and the
  "your brief is your whole task" line.
- **Two optional coordinator keys:**
  - `worker_rules`: up to 4,000 characters, no control characters but newline and tab. The rules are substituted
    last, so a `{...}` in them stays literal. A brief is measured for the command line with its own project's rules.
  - `repo_instructions`: true or false, the project's default when a task does not say.

  Older hosts ignore both keys and log them.
- **Environment and notes.**
  - Every worker variable is set as `SB_<name>`: `BUS_CA`, `BUS_URL`, `BUS_STORE`, `TASK_SEQ`, `COORDINATOR_ID`,
    `COORDINATOR_NAME`, `NOTES_CHANNEL` and `PROJECT`. (Releases before 2026.11.26 also set older names; the host
    now only removes them.)
  - `notes` reads the task's own notes channel.
  - Before each launch, the worker identity is subscribed once to that channel. New identities are subscribed to
    `Humans` as well.
- **What the host reports.**
  - `started`, `finished`, `failed` and `timed-out` carry `project`, so usage can be split per project.
  - The task state records `project` and `repo_url`.
  - `.ds-worker.json` gains `project`, and its `repo` is the URL.
  - `wh fleet status` shows each coordinator's `repo_instructions` default and how many rule lines it has.
- **Clones.** A new clone uses `gh repo clone <url>` for github.com and `git clone -q -- <url>` elsewhere, with
  `GIT_TERMINAL_PROMPT=0`. An existing clone of another repository is refused (`clone-mismatch`), never
  re-pointed. So two projects that use the same worker name fail safely rather than share a clone.
- Worker names stay unique per host across projects: the per-worker lock is host-wide. Two projects that use the
  same worker name take turns.
- **Site values.** The code's defaults name no site. A new host's site values (bus, fleet repository, coordinator,
  remotes, short names, OpenBao) come from a site file: `install.ps1 -SiteFile <site.toml> -BusCa <LAN root>
  -AgentPrefix <prefix>`. Start from `site.example.toml`.
- **Not yet:** per-project clone folders (`<drive>:\workers\<project>\<worker>` and `<drive>:\wt\<project>\...`)
  wait for the drive layout (section 11), where they belong. Also not yet: 7.5 (`GH_TOKEN` per organisation).

### 7.5 Several GitHub accounts on one host (design)

- Every account the workers need is signed in on the host. Git Credential Manager uses
  `credential.https://github.com.useHttpPath = true`, so each organisation gets its own stored credential.
- Workers run as the host's account and can use any of them. Keep that in mind when one account is personal and
  another belongs to an employer.
- `gh` keeps one *active* account per host name, and switching it would race between concurrent workers. So the
  host will never switch it. Instead it will set `GH_TOKEN` for each worker to the account that owns the task's
  organisation (`gh auth token --user <login>`). The organisation-to-login map goes in `host.toml`.
  - A brief that works in another organisation gets that account's token the same way.
- Copilot CLI works under any account that holds a Copilot licence.

### 7.6 Engines: GHCP CLI and Claude Code

Built (`workerhost/engines.py`). Copilot (`ghcp`) and Claude Code (`claude`) each run under their own licence or
subscription. Two reasons to have both:
- better models for some tasks;
- carrying on when one engine's licence lapses.

- **Config:** `config.toml` `[engines]` has `default`, the engine for a task that names none. `[engines.claude]`
  has the executable, the default model and the allowed and denied models. Claude Code's ids differ from Copilot's:
  aliases (`opus`, `sonnet`, `fable`, `haiku`) or dashes (`claude-opus-5-5`), not dots. Copilot keeps
  `copilot_exe` and `[models]` as before.
- **Per host:** `install.ps1` asks for the default on a new host (`-DefaultEngine`). A task's `engine` field
  overrides it.
- **No separate cap:** Claude Code workers count against `max_workers` like any other.
- **The heartbeat** lists what is usable now: `engines=ghcp*,claude` (`*` marks the default), plus `claude_models=`.
  - Claude counts as usable when it is configured, its executable is found, and `~/.claude/.credentials.json`
    exists. That file's presence is checked; it is never read.
  - A task for an engine this host lacks is refused with `reason: engine`, and another host may take it.
  - A Copilot licence that has lapsed can't be detected without spending a request: such tasks fail at launch
    with `aic` 0.
- **The Claude Code launch** follows the GHCP rules:
  - headless (`claude -p`), an argument list, no shell;
  - the same fixed preamble plus the brief, sent on **stdin**, so the command-line length limit doesn't apply;
  - **permissions match GHCP's `--allow-all-tools` with its path fence:**
    - `--permission-mode acceptEdits`: file edits only inside the clone and the `--add-dir` folders;
    - `--allowedTools Bash,WebFetch,WebSearch`;
    - never `--dangerously-skip-permissions` or `bypassPermissions`, and a test pins that;
  - `--setting-sources ""` (none) and `--strict-mcp-config`: **no settings file is loaded at all.** Not the host
    account's, which may also be someone's interactive account, and not the repository's `.claude/settings.json`
    or `settings.local.json`. A repository's settings act without the model choosing anything:
    - `env`, for example `ANTHROPIC_BASE_URL`, would send the subscription token elsewhere;
    - `apiKeyHelper` runs a command;
    - hooks, `permissions.allow` and `additionalDirectories` change what the worker can do;
    - and `-p` skips the trust prompt.

    This was tested: with `project,local`, a planted `settings.local.json` value reached the worker's shell, and
    with `""` it didn't. The CLI's own `init` line confirms `permissionMode: acceptEdits`, no MCP servers and no MCP
    tools;
  - `--output-format stream-json --verbose`, so the log keeps moving (the stall check reads it) and the last
    `result` line carries the cost;
  - the host's session id (`--session-id`, or `--resume` for a resume). A resume only resumes a session of the same
    engine, whose record says it ran in this worker's clone (`~/.claude/projects/*/<id>.jsonl`, `cwd`).
- **Where Claude Code may run: not on a host whose Windows account is shared with other agents or with a person's
  own sign-in.** A worker's unrestricted shell can read anything that account can, including other agents' keys,
  the Claude subscription token (`~/.claude/.credentials.json`) and every interactive Claude transcript
  (`~/.claude/projects`). Give the worker host its own local Windows account (`install.ps1 -Logon Password` with a
  dedicated account) before configuring `[engines.claude]`. That account separation is the real fix for the GHCP
  case too.
- **Repository instructions:** Claude Code doesn't read `AGENTS.md` or `.github/copilot-instructions.md` by
  itself, and that's where GHCP-era repositories keep their rules. With `repo_instructions` on, the preamble tells
  the worker to read them, plus `CLAUDE.md`, first. With it off, the worker isn't told to, but Claude Code still
  loads a repository's `CLAUDE.md` itself: a known difference.
- **Usage:** GHCP keeps `aic`. Claude Code reports `usd`, `by_model_usd` and `calls` from the `result` line of its
  own attempt in the worker log, never added to AIC.
- **Updates:** `DISABLE_AUTOUPDATER=1` in each worker's environment, so a version never changes under a running
  worker. Updating Claude Code in the host's window (with winget, like GHCP) is not built yet: update it by hand
  when idle.

## 8. Security standard

Rows other than Defender apply when the `security` switch is on (`dedicated`).

| area | setting | note |
|---|---|---|
| Remote Desktop | enabled; Network Level Authentication required; firewall rule scoped to the LAN subnet from `host.toml` only | NLA stops the pre-auth attack surface; a laptop on the LAN works, nothing else does |
| Firewall | all three profiles on; inbound default block; allowed inbound: RDP (LAN), ICMP echo (LAN); file sharing off unless `host.toml` says on; outbound open | the network is set to Private at setup so the right profile applies. Outbound is open, so Wazuh's 1514/1515 need no rule |
| Wazuh agent | official MSI, enrolled to the manager in `host.toml`, group `windows`, service automatic | the key never appears on a command line (section 12). The manager side is the site's own |
| Windows Update | section 9 | |
| Defender | Defender Antivirus on with cloud protection. **MDE onboarding is done by hand**; the script does not. The worker drive, by the `defender` switch: **`exclusion`** (default) excludes `<drive>:\workers` and `<drive>:\wt` from scanning; **`devdrive`** (offered only when the worker drive is not C:) formats it as a Dev Drive, so Defender scans in its lighter performance mode; **`none`** changes nothing (work-managed machines, where Defender is IT's) | git and test suites touch tens of thousands of small files, and real-time scanning of each one is the host's biggest slowdown. An exclusion is fastest but that folder is not scanned at all; a Dev Drive keeps scanning at most of the speed |
| BitLocker | off; not configured | the owner's call per site |
| Accounts | the install-time local account is the only interactive account; Guest and built-in Administrator disabled; the scheduled task runs as that account with Password logon | |
| Legacy protocols | SMBv1 removed; LLMNR and NetBIOS name resolution off; WDigest off; Remote Registry off; PowerShell v2 removed | free hardening, no effect on the agents |
| Logging | PowerShell script block and module logging on; audit policy: logon, process creation **with command line**, account management, policy change. Sysmon is **off** by default (a small Wazuh manager copes better) and turned on per host with the `sysmon` switch | this is what makes the Wazuh agent worth having; it is also why no secret may ever be on a command line |
| Diagnostic data | Required | |
| Power | High performance; sleep and hibernate off; display off allowed; fast startup off | |
| Time | NTP against the LAN source in `host.toml`, else `time.windows.com` | |
| Consumer surface | section 6 | |

Deliberately **not** in scope: domain join, Intune or Entra join, scripted MDE onboarding, BitLocker, LAPS. Each
is a later step with its own decision.

`docs/security-standard.md` becomes the one page that holds this table once each row is kept or struck.
`setup/30-security.ps1` is written against it line by line, so the audit is "does the script do what the page
says".

## 9. Patching and updates

The aim: security fixes for Windows **and** for every app and tool on the box land within a day, without killing
running work, and without anyone touching each machine.

### 9.1 `baseline.toml`: the settings, in one place (design)

The update settings and the tool list are fleet-wide, so they live in one file in the fleet repository, signed
exactly as `fleet.toml` is (section 7.2). Change it once and every host follows by the next night. A host may
override a value in its own `host.toml`, for example to hold one test machine back.

```toml
serial = 1                      # one more on every signed change

[updates]
feature_deferral_days = 60      # a new Windows version waits 60 days (tested on the VM first)
quality_deferral_days = 0       # monthly and out-of-band security fixes: no delay
restart_time          = "03:00" # Windows restarts here when an update needs it
window                = "02:00-06:00"  # nightly maintenance window, local time
max_skipped_nights    = 2       # then the host drains to let maintenance run (9.3)

[tools.winget]                  # installed by setup, upgraded every night
ids = ["Git.Git", "GitHub.cli", "Python.Python.3.13", "OpenJS.NodeJS.LTS", "Microsoft.PowerShell",
       "Microsoft.AzureCLI", "7zip.7zip"]

[tools.psmodules]               # PowerShell 7, all users, upgraded every night
names = ["Az", "Microsoft.Graph"]
```

GHCP CLI and Claude Code are not in this list. They update in the host's own window (`design.md` §10), which
already waits for no worker to be running.

**PowerShell 7 must be the MSI.** Install it with `winget install --id Microsoft.PowerShell --exact --installer-type wix
--scope machine`. winget's default for 7.6 is the Store (MSIX) package, and that puts `pwsh` on the path only as an app
alias under `WindowsApps`. The alias fails with "Access is denied" outside an interactive sign-in, for example over
SSH, and the host's scheduled task is in the same position: it makes the leaf key with `pwsh`
(`workerhost/leafkey.py`). The MSI puts `C:\Program Files\PowerShell\7` on the machine PATH, ahead of the alias.

**Python is 3.13, and stays on a version that still gets Windows builds.** Python 3.12 went source-only, so its
security fixes no longer reach Windows installers. When a Python minor version stops getting Windows installers,
plan the move to the next one. The worker host uses only the standard library, so a move is `install.ps1` with the
new python.exe first on PATH, plus `python_exe` in config.toml. CI runs the suite on 3.12 and 3.13
(`.github/workflows/tests.yml`).

### 9.2 Windows Update (`windows_update` switch)

- Monthly security updates install as soon as Windows offers them: no deferral. Defender definitions update on
  their own schedule, several times a day.
- Feature updates (a new Windows version) wait `feature_deferral_days`, so they are tried on the test VM first and
  the debloat list is checked against them.
- "Updates for other Microsoft products" is on.
- A restart, when one is needed, happens at `restart_time`. **Built in `20-policy`**: active hours 08:00-02:00
  (Windows' 18-hour maximum) and a daily install at 03:00, as Windows Update policy values. With Windows' defaults
  (active hours 8:00-17:00) a host restarts in the early evening. "No auto-restart with users signed in" is not
  set: someone may stay signed in, and updates would never finish. Active hours cannot cover a whole day, so the
  host does not fight restarts. It avoids them. The first and third points below are built
  (`workerhost/winupdate.py`); the second is not yet, and until it is, `resume_after_reboot` resumes such a worker
  once:
  - While a restart is pending, the host does not claim a task that could still be running at `restart_time`
    (`now + max_runtime_hours`; with 6 hours, from about 21:00). It posts `restart-pending` in its heartbeat.
    "Pending" is checked hourly: the restart flag, or updates waiting in Windows Update's local cache that may need a
    restart (an offline search, about 3 s, through Windows PowerShell; it works in the task's non-elevated logon).
    Inside the restart window (03:00-08:00) a pending restart can come at any moment, so nothing is claimed then.
    A failed query blocks nothing. The time is `[update] windows_restart` (default 03:00, matching 20-policy).
  - A worker still running at `restart_time` is interrupted. It pushes its work in progress and resumes once after
    the reboot (`resume_after_reboot`).
  - The host is back two minutes after boot, with nobody signed in (section 10).

### 9.3 Nightly maintenance (`app_updates` switch, design)

An elevated scheduled task, separate from the host, runs in `window` every night:

1. It asks the host to hold new claims, through a file in the host's home that the host reads each loop, as it
   reads `enabled`. If no worker is running, it goes ahead. If workers are running, it waits for them until the
   window ends, then releases the hold and tries again the next night.
2. `winget upgrade` for every id in `[tools.winget]`, plus any other app on the box that has an update (Store apps
   update themselves).
3. `Update-PSResource` for `[tools.psmodules]`.
4. `wsl --update`, then `apt-get update && apt-get -y upgrade` in Ubuntu (Ubuntu's own unattended security
   upgrades stay on as well).
5. It re-runs `10-debloat` and `20-policy` (`dedicated` only), and installs any tool newly added to
   `baseline.toml`.
6. It releases the hold and posts `maintenance=ok updated=<n>` (or what failed) on `worker-hosts`. A failure is
   never silent.

If maintenance has been skipped for `max_skipped_nights` nights in a row because workers were always running,
the next night the hold starts at the beginning of the window and stays until the running workers finish. Security
updates are therefore never more than about three days behind on a busy host.

### 9.4 The host's own code: self-update from signed releases (built)

The host updates its own code from releases the owner signs, in the same nightly window. The full description is
`design.md` §10a; code in `workerhost/update.py`.

- A release is `release.toml` (+ `release.toml.sig`, namespace `strugglebus-release`) on the fleet repository's
  `main`, signed with the same pinned keys as `fleet.toml`. It names a commit and a sha256 over the installed files
  at that commit. `tools/make-release.py` writes it; `tools/sign-config.ps1` signs and merges it.
- The host reads it from the mirror it keeps for `fleet.toml`, checks the signature and the file hash, and runs
  nothing before that check.
- Times come from `config.toml` `[update]`:
  - `check_at` (01:00): a newer release is announced, mentioning every coordinator in the fleet, and the host
    takes no new tasks;
  - `window` (03:00): no worker running, so it applies;
  - `window` + `grace_minutes` (03:30): running workers push their work to their branches and stop; the host
    applies, and each such task is resumed once after the restart;
  - an hour after the grace without having applied (the host was off or asleep): it takes tasks again and
    announces the release again at the next check.
- If the new code fails three times in a row soon after starting, the supervisor puts the previous files back and
  that release is never retried.
- A release with `needs_install = true` is announced but not applied: run `install.ps1` by hand.

## 10. Running with nobody signed in

`dedicated`: the scheduled task uses `install.ps1 -Logon Password` (`design.md` §9). It starts at boot, two minutes
after startup, whether or not anyone is signed in. That is why a dedicated host uses a local account with a
password. After changing that password, run `install.ps1 -UpdatePassword`.

`managed`: `-Logon Interactive`, for machines with no password to give (Entra and Windows Hello): the host runs
while the user is signed in, and keeps running if they disconnect without signing out.

## 11. Drive layout, pagefile and WSL

- OS on C:. The chosen worker drive holds `\workers\<project>`, `\wt\<project>`, `\tools` and `\drop`. It is a Dev
  Drive only if the owner chose that at setup (section 8); Dev Drive needs at least 50 GB, and the script never
  reformats a drive that has data on it.
- The pagefile is fixed at a quarter of RAM, maximum half (on 128 GB: 32 GB initial, 64 GB maximum), on C:. The
  host's 80% commit gate (`design.md` §5) stays; the fixed pagefile is what keeps it from refusing work when a
  large test run spikes commit.
- **WSL 2 with Ubuntu** is installed (`wsl` switch). Its virtual machine counts against the same memory as the
  workers (an uncapped WSL VM can reserve tens of GB of commit), so `.wslconfig` always caps it:
  - `memory` = an eighth of RAM by default (16 GB on a 128 GB host), overridable in `host.toml`;
  - `autoMemoryReclaim = dropCache`, so memory Linux has finished with goes back to Windows.

  Setup creates the Ubuntu user without a prompt and makes it the default. WSL needs the Virtual Machine Platform
  feature and one reboot. The test VM needs nested virtualisation turned on.
- No Docker Desktop.

## 12. Secrets and prompts

- **The rule for every step:** process creation is audited with the command line, and script blocks are logged.
  So no secret is ever put on a command line, in an environment variable of a child the script starts, or in a
  string passed to `Invoke-Expression`. Secrets go through stdin, a file with a tight ACL, or an API call.
- All prompts use `Read-Host -AsSecureString`, are converted only in memory, are dropped after use, and are never
  echoed or logged. `setup.ps1` runs with no transcript; the step log (`setup/log/*.txt`) records step names and
  outcomes only.
- **Windows password:** passed to `install.ps1`, which hands it to Task Scheduler. It is not kept anywhere else.
- **SPN token:** written to `wh enrol --spn-stdin` on stdin. `wh enrol` stores it with DPAPI, owner-only
  (`design.md` §12), or in OpenBao (section 6.4).
- **Wazuh key:**
  1. it is written to the agent's `authd.pass`, with an ACL of SYSTEM and Administrators only;
  2. the MSI is installed with the manager address only;
  3. the service enrols;
  4. the file is deleted once the agent holds its key (`client.keys` exists and the agent reports connected).
- **The site's LAN root certificate** is given to git per URL (`http.https://git.example.lan/.sslCAInfo`) and to
  the bus client (`install.ps1 -BusCa`, written as `bus_ca`). The Windows machine trust store is not changed, which
  matters on work-managed machines.
- **The signing keys** are on hardware security keys and never on any computer. Hosts hold only the public halves,
  in an admin-only file (section 7.2, `signing-keys.md`).
- The site file and `host.toml` hold no secrets. The site file holds the site's addresses and fences; `host.toml`
  holds the profile and switches, addresses, the subnet, the drive letter, the organisation-to-login map and
  overrides. `host.toml` is gitignored; a template with placeholders is committed.

## 13. Testing and acceptance

- **Hyper-V VM:** a Windows 11 Enterprise VM is the test bench, built from the same USB image, with nested
  virtualisation for WSL. A daily-use machine can host the VM, but setup is never run on the daily-use machine
  itself.
- **Existing dedicated boxes:** `setup.ps1 -WhatIf` first, then a step at a time, starting with
  `-Only 30-security`. Check that RDP still works from another machine before the rest runs.
- **Acceptance on a fresh VM from the USB image:**
  - the VM posts `state=ready` and opens its `fleet.toml` PR. The owner signs and merges it with `sign-config.ps1`;
  - an unsigned or wrongly signed `fleet.toml` on a test branch is rejected (`fleet-unsigned`);
  - after the merge, the VM claims smoke tasks that open a PR in a scratch repository in each organisation and git
    server the site uses, with each engine (GHCP and Claude Code) and each GitHub account;
  - a night of maintenance runs and posts `maintenance=ok`;
  - the Wazuh dashboard shows the agent active;
  - the installed apps are only the keep list.
- **`managed` profile:** `setup.ps1 -WhatIf -Profile managed` on the VM shows that only tools, layout, WSL,
  maintenance (apps only) and the host would run.
- **Unit tests** in `tests/`, as the other host tests are:
  - the URL rules, including hostile URLs (userinfo, look-alike organisations, `ext::`, `..`, percent-encoding);
  - parsing `fleet.toml`, verifying its signature, its refresh, and falling back to the last good list;
  - engine and model selection;
  - per-project paths;
  - the restart-time claim rule and the maintenance hold.

## 14. Order of work

1. **Multi-project** (sections 7.1 to 7.4): signed `fleet.toml` and its refresh, `sign-config.ps1`, coordinator
   entries, the URL rules, notes, prompt and environment. Done; per-project roots and `GH_TOKEN` per worker (7.5)
   remain.
2. **Claude Code engine** (section 7.6). Done.
3. `docs/security-standard.md` agreed (section 8, each row kept or struck).
4. `setup.ps1` with profiles and switches, inventory, debloat, policy, security, Defender, tools, WSL, trust and
   layout; `-WhatIf` on an existing dedicated box, then a full run on the VM. Debloat, policy and access are done.
5. Wazuh, host, maintenance and self-check steps; `baseline.toml`; `autounattend.xml` (done); a fresh VM end to end
   from the USB image.
6. `bootstrap.ps1`, a README update, and a runbook page "rebuild a host".

Later: work-managed machines on the `managed` profile.

## 15. Decisions and open questions

Decided:
- Defender: exclusion by default; Dev Drive or nothing offered when the worker drive is not C:; nothing on
  work-managed machines.
- Sysmon: off by default, a per-host switch.
- VS Code: not installed. Tools: Python, PowerShell 7, the Az and Microsoft.Graph modules, Azure CLI, WSL with
  Ubuntu (plus Git, gh, Node, 7zip, GHCP CLI and Claude Code).
- Locale, keyboard and time zone: set in `autounattend.xml`, per site.
- Feature updates deferred 60 days, security updates not deferred, apps patched nightly; the settings live in
  `baseline.toml`.
- Branch protection on `main`: PR required, tests must pass, no force push, no deletion.
- WSL memory cap: an eighth of RAM (16 GB on a 128 GB host) by default.
- Signing: FIDO2 keys on hardware security keys, PIN and touch per signature, pinned on hosts in an admin-only
  file, with a serial against replay (`signing-keys.md`).

Open: none in this design. Items marked **(verify)** in `signing-keys.md` are confirmed the first time they are
done.
