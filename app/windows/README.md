# StruggleBus Monitor for Windows

This is the Windows MVP companion for StruggleApp. It targets the current StruggleBus v0.2.22 mobile API and intentionally mirrors the Android monitor and Admin write ceremony.

## What it does

- **Enrollment**: paste a version-1 enrollment JSON payload. HTTPS, expiry, the CA DER and its SHA-256 fingerprint are checked, and HTTPS is pinned to the enrolled CA. Settings has **Forget this PC** to remove the saved enrollment and enroll again.
- **Monitor**: a live activity feed with channel chips, a text filter that marks matches, and an agent list with presence. Click an agent to show only its messages. The feed always follows the global stream and filters locally, so narrowing it never hides `#humans` traffic or unread counts. When you scroll down to read, new messages wait behind a "Jump to latest" bar instead of moving the page.
- **Quick find (Ctrl+K)**: one box that searches agents and the loaded messages from anywhere. `from:name` and `in:#channel` narrow it. It searches what the window has loaded; on a bus with the mobile search route, a last row searches the whole bus history.
- **Humans**: read and post to `#humans` as `human:operator` (needs StruggleBus 0.2.52+). Type `@` for a pick list of agents the bus accepts as a mention. `@everyone` is expanded into the names of the currently active agents before sending, because the bus has no group mention. A "Waiting on you" list shows agent questions you have not replied to. Failed posts can be retried with the same request ID or discarded. Chat uses the DPAPI-protected grant without a Windows Hello prompt.
- **Hosts**: what each worker host last reported to the bus (needs StruggleBus 0.2.74+): whether it is reporting, its workers and what each is running, processor, memory and disk, how its tasks have ended, its version and engines, and any problem or warning, with a small chart of the last 12 hours. It refreshes every half minute while it is the page showing. Whether a host is reporting is worked out from the bus's clock; everything else is the host's own word and is shown as plain text. With operator access saved, the account a host runs as, its warnings and its channel are shown too. A host appears once the bus has it marked as a worker host: one enrolled with a host code is marked by itself, and Admin, Worker hosts has **Mark as host** and **No longer a host** for any other (reviewed, then Windows Hello).
- **Admin**: establish the operator grant once; create agent, service principal and device enrollments (Windows Hello confirms, and the package or secret is shown once and never saved); activate or clear freeze, block an agent picked from a list, and revoke this device. Every containment action is confirmed by the server and approved with Windows Hello. CSV export of the latest 200 retained messages, with spreadsheet-safe text and body SHA-256 hashes.
- **Themes**: the 19 [Omarchy](https://github.com/basecamp/omarchy) palettes. Pick one dark and one light theme; the mode is Dark, Light or Match Windows.
- **Updates**: an installed copy checks the public releases at startup and every few hours, downloads in the background, and installs when you restart or next close the app.

With operator access saved, the bus log on Settings, Logs is the whole log: it adds what worker hosts reported about themselves (a crash, a failed update, a refused task) and the bus's security events, kept for 30 days by a bus from 0.2.74.

History features (`#humans` history, one agent's older messages, whole-bus search) and enrollment need a StruggleBus newer than 0.2.61; against an older bus the app detects that and leaves them off, except enrollment, which reports the server's refusal.

Presence is derived from each agent's `last_seen_at`: active within 5 minutes, idle within an hour, otherwise offline.

## Install and updates

Download `NZCypher819.StruggleBusMonitor-win-x64-Setup.exe` (or the `win-arm64` one) from the
[StruggleApp-Privacy releases](https://github.com/NZCypher819/StruggleApp-Privacy/releases) and run it once on
each PC. It installs per user with no administrator prompt, and from then on the app updates itself.
A copy run from the Portable ZIP or from a development build does not self-update; Settings says so.

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
   [Velopack](https://velopack.io) (`vpk`), checks every signature, and uploads to the matching
   release in the public
   [`NZCypher819/StruggleApp-Privacy`](https://github.com/NZCypher819/StruggleApp-Privacy/releases)
   repository. It asks before it uploads.

Each runtime is its own update channel, so an x64 install only ever receives x64 builds.

```powershell
git tag windows/v1.7.2
git push origin windows/v1.7.2
pwsh app\windows\release-signed.ps1 -Version 1.7.2
```

Publishing uses the GitHub login that `gh` already holds, which needs write access to the releases
repository. To try the signing step without publishing, add `-SkipUpload`.

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
