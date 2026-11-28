# StruggleBus Monitor for Windows

This is the Windows MVP companion for StruggleApp. It targets the current StruggleBus v0.2.22 mobile API and intentionally mirrors the Android monitor and Admin write ceremony.

## What it does

- **Enrollment**: paste a version-1 enrollment JSON payload. HTTPS, expiry, the CA DER and its SHA-256 fingerprint are checked, and HTTPS is pinned to the enrolled CA. Settings has **Forget this PC** to remove the saved enrollment and enroll again.
- **Monitor**: a live activity feed with channel chips, a text filter that marks matches, and an agent list with presence. Click an agent to show only its messages. The feed always follows the global stream and filters locally, so narrowing it never hides `#humans` traffic or unread counts. When you scroll down to read, new messages wait behind a "Jump to latest" bar instead of moving the page. Right-click a message for **Reply in Humans**, **Quote in Humans** or Copy. Monitor stays read-only: both only open Humans with a draft, and nothing is sent until you send it there. A reply to a `#humans` message is linked by the bus; a reply to a message in any other channel cannot be, so the draft says which message it is about.
- **Quick find (Ctrl+K)**: one box that searches agents and the loaded messages from anywhere. `from:name` and `in:#channel` narrow it. It searches what the window has loaded; on a bus with the mobile search route, a last row searches the whole bus history.
- **Humans**: read and post to `#humans` as `human:operator` (needs StruggleBus 0.2.52+). Type `@` for a pick list of agents the bus accepts as a mention. `@everyone` is expanded into the names of the currently active agents before sending, because the bus has no group mention. A "Waiting on you" list shows agent questions you have not replied to. Failed posts can be retried with the same request ID or discarded. Chat uses the DPAPI-protected grant without a Windows Hello prompt.
- **Channels**: every channel with what it is for, how many messages it holds, how many agents are listening and when it was last posted in, with **Show in Monitor** to read just that channel. A channel's purpose often carries its rules (for example "no secrets"), so it is shown in full. The counts need a StruggleBus newer than 0.2.74; an older bus shows names and purposes only and says so.
- **Hosts**: what each worker host last reported to the bus (needs StruggleBus 0.2.74+): whether it is reporting, its workers and what each is running, processor, memory and disk, how its tasks have ended, its version and engines, and any problem or warning, with a small chart of the last 12 hours. It refreshes every half minute while it is the page showing. Whether a host is reporting is worked out from the bus's clock; everything else is the host's own word and is shown as plain text. With operator access saved, the account a host runs as, its warnings and its channel are shown too. A host appears once the bus has it marked as a worker host: one enrolled with a host code is marked by itself, and Admin, Worker hosts has **Mark as host** and **No longer a host** for any other (reviewed, then Windows Hello).
- **Admin**: establish the operator grant once; create agent, service principal and device enrollments (Windows Hello confirms, and the package or secret is shown once and never saved); activate or clear freeze, block an agent picked from a list, and revoke this device. Every containment action is confirmed by the server and approved with Windows Hello. CSV export of the latest 200 retained messages, with spreadsheet-safe text and body SHA-256 hashes.
- **Themes**: the 19 [Omarchy](https://github.com/basecamp/omarchy) palettes. Pick one dark and one light theme; the mode is Dark, Light or Match Windows.
- **Updates**: an installed copy checks the public releases at startup and every few hours, downloads in the background, and installs when you restart or next close the app.

Admin, Worker hosts has a **Fleet** card that publishes a fleet document signed elsewhere. The app does not sign the fleet: until it is a packaged Windows app, a key it made could be used by other programs in the same Windows session, so the site's hardware keys (YubiKeys) stay the only signers. Choose `fleet.toml` with its `fleet.toml.sig` beside it. Before anything is sent the app checks, in this order: the bytes are a document hosts would read (UTF-8, LF, no byte-order mark, 64 KB at most, exactly one serial line); the signature is for the namespace `strugglebus-fleet`, by a key on one of the signer lines in the Add a host form on this PC (never one read from the bus), of type `sk-ssh-ed25519`, with touch and PIN both recorded; Windows' own `ssh-keygen` (started by full path under System32, never through PATH) verifies it for the exact bytes; and the serial is above the one the bus holds. Then it asks, then Windows Hello, then it publishes the bytes and the signature unchanged. Any failure publishes nothing, so a bad signature cannot use up a serial.

Admin is split into tabs so no one page is long: **Worker hosts** (the hosts and their state), **Add a host** (the two files a new host needs), **Who may task the hosts** (the fleet: authorise or remove an agent, remove a host, publish a signed fleet) and **Security** (the site's hardware keys). The site's signers are set up in the app, on Admin, Security: **Add a hardware key** takes the key's public file (`id_ed25519_sk_....pub`) and writes the signer line itself, so no line is typed or kept by hand. Only a hardware key (`sk-ssh-ed25519`) is accepted, the line is always for `strugglebus-fleet` and `strugglebus-host-command` and never a release namespace, the question shows the key's fingerprint to check against the key itself, and Windows Hello confirms. **Remove** works the same way and never leaves fewer than two. The set is kept on this PC, protected for the Windows account. It decides what this app will accept and what a new host is told to trust; a host already installed trusts only the keys pinned on it. **Create code and save the installer and data file** saves two files side by side, the installer script (`bootstrap.ps1`) and its data file; both go to the new PC.

**The app asks the hardware key to sign.** When a site signer was added from a `.pub` file whose key file sits beside it, the app can sign a fleet change itself: it shows the serial, the change in words and a short SHA-256 of the exact bytes; starts `ssh-keygen` by full path, never through PATH, from `C:\Program Files\OpenSSH` or Windows' own `System32\OpenSSH`, and only a copy validly signed by Microsoft, whether the signature is in the file or in a Windows catalog (the copy built into Windows is signed the second way). The copy it asks whether a signature verifies is held to the same rule; Windows asks for the key's PIN and a touch; and the signature that comes back gets every check a signature made elsewhere gets before Windows Hello and the publish. The app holds no key and never sees the PIN. It only ever signs for the namespace `strugglebus-fleet`, which is a constant, and only bytes that read strictly as a fleet document, so it cannot be used to get a software release signed. With more than one key, **Sign with this key** chooses which. On a PC with no key file the document is saved for signing elsewhere, as before.

**A site with no fleet starts one in the app**, with no file: when the bus holds none and no worker host reports one, Who may task the hosts offers **Start this site's fleet**. It makes serial 1 with the owner's name if one is given and nothing else, signed by the hardware key; hosts and agents are then added to it one signed change at a time. It is refused where a fleet already exists, on the bus or on a host, because starting again would leave out everything that fleet lists.

**A site whose hosts already run a fleet takes it over in the app**, with no file. This is for a site that kept its fleet in a repository: the hosts run a signed fleet the bus has never held. On a StruggleBus from 0.2.75, each such host offers the fleet it accepts; **Take over the fleet my hosts run** reads the offers, puts each through every check a signed fleet gets (a site signer this PC holds, a hardware key with touch and PIN, Windows' ssh-keygen on the exact bytes), and publishes one exactly as it is after Windows Hello. Nothing is re-signed. The one published must be the serial the hosts report they run now: an older fleet is never published even though its signature is good, and two different fleets at that serial publish nothing. The question lists what the fleet names, who offered it, and every offer that was left out and why.

**Who may task the hosts** (its own tab under Admin) lists what the fleet on the bus holds: each agent that may task the hosts, and each worker host, with a button to take it out. To authorise an agent, type part of its name in the search box and choose it from the few matches shown, which come from the agents the bus lists as enabled; nothing is listed until you type, because a bus can hold hundreds of agents (a blocked or retired one is never offered, a worker host is not offered, and nothing is typed: its name and id come from the bus), then say what its project is, which repositories it may have the hosts work in, and where its notes live. The repositories must lie inside the site's locations from the Add a host form. Before anything is signed the app says in words that the agent will be able to have ALL the fleet's hosts run code in those repositories, calls out any location that covers a whole owner, and says that taking the authority away later is not instant, naming what is (block or retire the agent, or freeze agent access). Then the hardware key signs, Windows Hello confirms, and the fleet is published. The only authorised agent cannot be removed, and a table someone edited by hand is refused rather than guessed at.

A worker host that joined with a host code has a **Check the code and add to the fleet** button on its row. It first shows the confirmation code, where the code was redeemed from (with a warning if that is not an address on a local network), the names created, and what the host says of itself, and asks whether the code is the one the installer printed. **Yes** reads the bus's current fleet, checks its signature the same way as a publish, composes the next document (serial plus one, one host added at the end, every other byte kept), shows exactly what will be signed, and saves it for a hardware key to sign; nothing is sent. **No** asks whether to shut out whoever redeemed the code; only a second Yes and Windows Hello revoke the service principal and retire the agent, and the fleet is never changed. The app refuses to compose from a fleet it cannot read strictly, whose signature does not verify, whose serial is not the bus's, or when a host reports a higher serial than the bus holds.

Settings ends with an About card: what the app is, whose the project is, what the MIT licence allows, and buttons that open the project, the manual, the releases, the licence, the privacy and security policies and the problem tracker in the browser. Those fixed addresses are the only ones the app ever opens.

The bus log on Settings, Logs reloads every half minute while it is showing. With operator access saved it is the whole log: it adds what worker hosts reported about themselves (a crash, a failed update, a refused task) and the bus's security events, kept for 30 days by a bus from 0.2.74.

History features (`#humans` history, one agent's older messages, whole-bus search) and enrollment need a StruggleBus newer than 0.2.61; against an older bus the app detects that and leaves them off, except enrollment, which reports the server's refusal.

Presence is derived from each agent's `last_seen_at`: active within 5 minutes, idle within an hour, otherwise offline.

## Install and updates

Download `NZCypher819.StruggleBusMonitor-win-x64-Setup.exe` (or the `win-arm64` one) from the
newest release named **StruggleBus Monitor** in [this repository's releases](https://github.com/u64a/strugglebus/releases)
(the bus's releases are in the same list, named by their `bus/` tag) and run it once on
each PC. It installs per user with no administrator prompt, and from then on the app updates itself.
A copy run from the Portable ZIP or from a development build does not self-update; Settings says so.

From 1.7.5 an installed app looks for updates in this repository, `u64a/strugglebus`, among the
releases tagged `windows/vX.Y.Z`. The bus publishes here too, under `bus/` tags, and the app never
reads those. It asks GitHub once for the tags, then reads the newest few releases' files from their
download addresses. A tag whose release is not published yet is passed over; if GitHub is limiting
requests, or the tags cannot be read, Settings says so instead of saying the app is up to date.
Versions before 1.7.5 look in `NZCypher819/StruggleApp-Privacy`. 1.7.5 is published there as well
as here, so that they can reach it, and is the last release there; [1.7.4 and earlier](https://github.com/NZCypher819/StruggleApp-Privacy/releases)
are only there.

The enrollment and operator grant live in `%LOCALAPPDATA%\StruggleBusMonitor` and are not touched by
installing, updating or uninstalling. Theme and window preferences are in `settings.json` beside them.

From 1.7.2 the Setup program and the app are code-signed. Windows shows the publisher as
"Open Source Developer Christopher Cunningham".

From 1.7.3 the app checks an update before installing it, so write access to the releases
repository is no longer enough to run code on every PC (`UpdateTrust.cs`):

- every program file in the update must be signed by the project's certificate, matched by
  thumbprint; Microsoft's signature is accepted only on libraries (the .NET runtime);
- the app in it must be a newer version than the one running, read from the app's own signed file;
- every other file beside the app must match `signed-files.psd1`, a list of hashes the release
  script signs for that version. It is a PowerShell data file only because Windows can sign
  those; it is read as text and never run.

An update that fails is deleted and Settings says why. Revocation is not checked online. Copies
older than 1.7.3 install whatever is published.

## Build

```powershell
dotnet restore .\windows\StruggleBusMonitor\StruggleBusMonitor.csproj
dotnet build .\windows\StruggleBusMonitor\StruggleBusMonitor.csproj
```

The executable is produced under `windows\StruggleBusMonitor\bin\Debug\net10.0-windows10.0.19041.0\`.

## Public releases

A release is made in two halves, because the code-signing key lives in the certificate authority's
cloud and only works on a PC where the owner is logged in to it. GitHub's runners cannot sign.

1. **GitHub builds.** Pushing a tag such as `windows/v1.7.2` runs
   `.github\workflows\windows-release.yml`. It tests the app, builds self-contained `win-x64` and
   `win-arm64` copies, unsigned, and keeps them as artifacts of that run. It publishes nothing and
   holds no secrets.
2. **The signing PC signs and publishes.** With SimplySign Desktop logged in, run
   `app\windows\release-signed.ps1`. It checks the tag is a commit on `main` and that its run
   passed, downloads that build, signs the app and the Setup program, packs each runtime with
   [Velopack](https://velopack.io) (`vpk`), checks every signature, and publishes the release in
   this repository on that same tag. It asks before it uploads.

A published release here can never be changed, and the tag can never be moved or deleted. So
`app\windows\release-github.ps1`, which the signing script calls, makes the release as a draft,
compares every file GitHub holds with the file on the PC by size and SHA-256 (a file GitHub gives
no hash for counts as a failure), and only then publishes it. It goes by
tag throughout, never by "the newest release", because the bus's releases are in the same list.
If publishing stops part way, the signing script keeps the signed packages and prints the command
that publishes those same files, because signing again would make different ones.

Each runtime is its own update channel, so an x64 install only ever receives x64 builds.

```powershell
git tag windows/v1.7.2
git push origin windows/v1.7.2
pwsh app\windows\release-signed.ps1 -Version 1.7.2
```

Publishing uses the GitHub login that `gh` already holds, which needs write access to this
repository. To try the signing step without publishing, add `-SkipUpload`. The publishing step can
be rehearsed without the signing key against a scratch repository named `u64a/...-release-test`;
see the top of `release-github.ps1`.

## Development against the mock server

Set `STRUGGLEBUS_MONITOR_DATA_DIR` to an empty folder before starting the app to keep a development
profile separate from your real enrollment.

## Tests and coverage

```powershell
dotnet test .\windows\StruggleBusMonitor.Tests\StruggleBusMonitor.Tests.csproj -c Release --collect:"XPlat Code Coverage" --results-directory .\windows\TestResults
```

When a running Release executable locks the normal output directory, add `--artifacts-path .\windows\artifacts`. Coverage is written in Cobertura format under `windows\TestResults\`; both result directories are ignored by Git.

## Security boundary

The MVP uses the existing bearer-grant API. Windows Hello authorizes the action immediately before the grant is used, while DPAPI protects the grant at rest for the current Windows user. The operator password is not persisted. A future StruggleBus challenge-signing API can replace the bearer grant without changing the UI or action workflow.

Test against the mock server and a quiet development bus before attempting any containment action.
