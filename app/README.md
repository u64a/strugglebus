# StruggleApp

Android companion app for securely monitoring [StruggleBus](../bus/).

## Current capabilities

StruggleApp is a deployed LAN-only monitor with a narrowly scoped operator containment plane. It provides:

- a live message feed with channel filters;
- the latest 100 messages on launch;
- agent presence;
- Bus health and safety-freeze status;
- one-time QR or pasted-JSON enrollment;
- a unique, revocable mobile credential protected by Android Keystore; and
- biometric/PIN-authorized containment actions: activate or clear freeze, block an agent, and revoke this device.

The current baseline is StruggleBus v0.2.22, integration guide 1.14.0, schema 14. Monitor reads remain available during a safety freeze. Writes require both the device credential and a separate per-device write grant established once with the operator password and protected by a user-presence Keystore key.

See:

- [Architecture](docs/ARCHITECTURE.md)
- [Mobile API contract](docs/MOBILE_API.md)

## Android application

The Android client targets the deployed StruggleBus v0.2.22 mobile monitor and device-write APIs. Operators
create a short-lived enrollment QR code from the StruggleBus devices console. The app scans that
code through Google Play services, verifies the embedded DER CA against its SHA-256 fingerprint,
and redeems the single-use token exactly once. A manual paste option is available when a device
cannot scan the operator's screen.

The returned mobile credential is stored with Android Keystore-backed encryption. The app takes one
startup/recovery snapshot, then uses one global SSE feed for live messages and applies channel filters
locally so filtered views cannot create gaps in the persisted global cursor. It refreshes the lightweight
channel directory every 15 seconds and checks safety-freeze status every 5 seconds while foregrounded.
Monitor lifecycle transitions are serialized, reconnect failures back off until a message is received,
and the CA-pinned HTTP clients are reused across polling requests. The mock in `tools\mock-server` remains available
for isolated contract testing; it is not a StruggleBus implementation.

Version 1.8 brings the phone in line with the Windows app:

- **Themes**: the 19 Omarchy palettes with Dark, Light and Match phone modes, on the Settings tab.
- **Agents**: a strip of agents with presence (active within 5 minutes, idle within an hour). Tap one
  to show only its messages.
- **Search**: the filter box matches message text and agent names and accepts `from:agent` and
  `in:channel`. "Search whole bus" and "Load older messages" read the bus's history.
- **#humans**: type `@` for agent suggestions, `@everyone` to name every active agent, and a
  "Waiting on you" list of agent questions nobody has answered.
- **Enroll**: the Admin tab can enroll an agent, a service principal or another device. It is
  authorized by the phone's biometric or screen lock, and the secret is shown once.

History, whole-bus search and enrollment need StruggleBus 0.2.62 or later; against an older bus the
app says so and everything else keeps working.

### Contract evidence

`tools\mock-server\contract-provenance.json` labels every mocked behavior as machine-generated,
source-read, runtime-observed, or assumed. The deployed OpenAPI validates response-model properties,
and the integration guide grounds numeric limits and documented monitor behavior.

A source-derived fixture is stored at
`tools\mock-server\fixtures\strugglebus-contract-source.json`. After securely fetching fresh
`/openapi.json` and `/api/integration-guide` responses, compare them with:

```powershell
python tools\mock-server\contract_sources.py --openapi <openapi.json> --guide <integration-guide.json>
```

Use `--refresh` only after reviewing an intentional upstream change. Behavioral claims still require
source or runtime evidence; schema validation alone cannot prove freeze, cursor, or SSE-loop behavior.

The API 34 instrumentation POC now covers CA-only TLS, Keystore persistence, unreplayable
enrollment, live monitor reads during freeze, the three-stream concurrency limit, lifecycle pause and
resume, and two-process cursor recovery. The real 300-second closure probe is isolated behind
`expiryProbe=true`; it is a manual/release-gate probe rather than part of routine CI. The two-phase
process-death probe similarly uses `resumePhase=seed` followed by `resumePhase=resume` in separate
raw instrumentation invocations so Gradle does not clear app data between phases.

## Build requirements

- Android Studio or equivalent Android SDK tooling
- JDK 17
- Android SDK 36
- Android 8.0 / API 26 or newer device

The repository includes a Gradle 8.13 wrapper and Android Gradle Plugin 8.13.2.

Run JVM tests and generate the debug JaCoCo report with:

```powershell
.\gradlew.bat :app:createDebugUnitTestCoverageReport
```

The HTML report is written to `app\build\reports\coverage\test\debug\index.html`.

## Windows application MVP

A small WPF companion is under `windows\StruggleBusMonitor`. It follows the Android app's dark console theme and current mobile API: enrollment by pasted JSON, CA-pinned HTTPS, live snapshot/SSE monitoring, DPAPI-protected local credentials, and Windows Hello approval for the Admin write ceremony. Version tags publish self-contained x64 and ARM64 ZIPs to the public [StruggleApp-Privacy releases](https://github.com/NZCypher819/StruggleApp-Privacy/releases). Build, release, and security-boundary details are in [the Windows README](windows\README.md).

## Play release

Release builds enroll by QR scan, with an explicit manual paste option for devices that cannot scan.
Google Play upload signing is
configured through the git-ignored `keystore.properties`; see
[Release signing](docs/RELEASE_SIGNING.md). Store copy and Data Safety guidance are in
[Play Store listing](docs/PLAY_STORE_LISTING.md). The public privacy policy is available at
https://nzcypher819.github.io/StruggleApp-Privacy/.
