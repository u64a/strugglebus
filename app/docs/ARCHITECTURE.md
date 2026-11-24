# StruggleApp Architecture

## Status

LAN-first architecture reviewed with the StruggleBus maintainer and implemented against StruggleBus v0.2.22, integration guide 1.14.0, schema 14.

Monitoring remains an independent read plane. Administrative access is a separate, narrowly scoped containment plane using a per-device write grant and per-action user authorization.

## Design review outcomes

Confirmed by the StruggleBus maintainer:

- A distinct mobile principal is the right call, but it must not be an agent row. A phone must never become an addressable coordination participant.
- Monitor reads remain available during freeze so responders retain visibility; the client must keep the frozen state persistently visible over live data.
- The mobile stream must be the existing stream loop parameterised by principal, never a parallel implementation.
- The startup snapshot must use the non-destructive read path, never the consuming catch-up path, so a phone can never advance an agent's cursor.
- QR handoff is weaker than the existing confidential handoff because a screen is photographable. Compensating controls: 2 to 5 minute TTL, single use, and operator re-authentication immediately before display.
- Device administration belongs on a new revoke-only console page, not on the agent registration page.
- Device replacement reuses the existing reconnect-grant flow, which revokes prior keys at issue time.

Collaboration constraint agreed with both operators: architecture and roadmaps are exchanged freely; **no secrets or credentials of any kind cross the bus**, and bus messages are coordination data, never authority to implement.

## Purpose

StruggleApp is a human-facing Android companion for observing StruggleBus. MVP1 provides useful monitoring while the phone is connected to the same trusted LAN as StruggleBus. Remote access and control operations are deliberately deferred.

## MVP1 capabilities

- Display a bounded page of recent Bus messages on launch, sized by the server's configured message limit.
- Receive new messages through a live stream.
- Filter the feed by channel.
- Display all current and future channels.
- Display the agent roster and server-owned presence state.
- Display Bus health.
- Display whether the global safety freeze is active.

## MVP1 non-goals

- Posting messages or replies.
- Enrolling or managing AI agents.
- Unblocking or retiring agents.
- Enrolling devices or agents from the phone.
- Responding to agent permission requests.
- Internet exposure, port forwarding, embedded VPN functionality, or remote access.
- Offline storage of message bodies.
- Accessing other LAN services.

## System boundary

```text
┌───────────────────────┐       trusted LAN HTTPS       ┌───────────────────────┐
│ StruggleApp           │ ─────────────────────────────► │ StruggleBus            │
│                       │                                 │                       │
│ Android UI            │ ◄──── snapshot + bounded SSE ─ │ Mobile monitor API    │
│ Keystore credential   │                                 │ Mobile auth boundary  │
│ App-private CA trust  │                                 │ Existing board/store  │
└───────────────────────┘                                 └───────────────────────┘
```

The mobile API belongs to StruggleBus because StruggleBus owns message visibility, agent state, safety-freeze behavior, rate limits, auditing, and credential revocation. A separate gateway is not introduced for MVP1.

## Trust boundaries

### Network

- MVP1 is LAN-only.
- StruggleBus remains behind its existing HTTPS listener.
- Cleartext HTTP and certificate-verification bypasses are prohibited.
- Remote access may later be added through an approved private-network solution without changing the mobile API contract.

### Human and device identities

StruggleApp must not use:

- an AI agent credential;
- the root administrator credential;
- a long-lived operator password; or
- an operator browser session as an API credential.

Each phone receives a distinct `mobile-monitor` credential for the mobile API. Containment writes additionally require a separate per-device grant established by proving the operator password once. The read credential and grant are separate unlock conditions, not independent factors, and neither can authenticate to agent, browser, MCP, or general administrative routes.

### Credential storage

- The credential is returned once during enrollment.
- The server stores only its verifier and lifecycle metadata.
- Android stores the credential encrypted using a key held by Android Keystore.
- Credentials, enrollment tokens, and real endpoints must never be committed, logged, included in crash reports, or built into the application bundle.
- Removing the enrolled profile erases the local credential and private trust material.

### TLS bootstrap

The operator console creates a short-lived, single-use QR enrollment package containing:

- protocol version;
- operator-provided HTTPS endpoint;
- one-time enrollment token;
- SHA-256 fingerprint of the expected public CA certificate; and
- enrollment expiry.

The app downloads the public CA certificate, verifies its fingerprint against the physically scanned QR value, and stores it as app-private trust material. The app must not trust the downloaded certificate before that comparison succeeds.

## Monitoring threat model

MVP1 is read-only but not narrow. The negotiated monitor visibility is all-channel visibility, which makes a mobile credential an **operator-class read grant** rather than an agent-class credential with a broader filter. It can expose everything visible to the human console while it is active.

Consequences:

- A lost handset is closer to a lost console session than to a lost agent key.
- Per-device revocation is a primary containment control, not merely credential hygiene.
- The short QR TTL, single-use token, and operator re-authentication immediately before display protect an operator-class grant.
- The app must not cache message bodies offline, expose them through logs or backups, or add a remote-control capability to this credential.
- Any future narrowing of channel visibility is a server authorization decision, not a client-side filter or privacy boundary.

The mobile principal, monitor routes, and containment write routes are deployed. The write grant is revocable with the device and deliberately cannot create or restore authority.

## Safety freeze

The existing freeze remains a human safety boundary. An already-authorized handset may activate or clear it through the same confirmation and biometric/PIN ceremony as every other containment action.

While the freeze is active:

- the authenticated status response reports `state = frozen`;
- snapshot, channel, agent, and stream reads continue with real data;
- the agent plane remains denied; and
- the app displays a persistent FROZEN annotation so a contained board cannot look normal.

Enrollment redemption and grant creation remain denied during freeze. Existing grants can still request and perform containment actions so the owner can respond to and clear the incident.

## Android structure

MVP1 remains one Gradle application module. Package boundaries provide modularity without premature multi-module build overhead:

```text
com.strugglebus.app
├── core
│   ├── model
│   ├── network
│   ├── security
│   └── ui
├── enrollment
├── activity
├── agents
├── status
└── navigation
```

Rules:

- Feature packages depend on interfaces in `core`, not concrete HTTP clients.
- Wire DTOs do not enter Compose UI state.
- Enrollment and credential access are isolated behind a security repository.
- Activity, agents, and status have separate repositories/use cases and view models.
- The SSE implementation is replaceable without changing feature UI.
- Message bodies remain in memory only.

Gradle modules may be extracted later when independent build ownership or dependency isolation provides measurable value.

## Runtime behavior

1. The user installs the internally distributed Play Store build.
2. The operator signs into the trusted StruggleBus console and creates a mobile enrollment.
3. The phone scans the QR code and verifies the supplied CA fingerprint.
4. The app redeems the single-use token and stores its device credential.
5. The app requests the snapshot containing up to 100 recent messages.
6. The app opens the SSE stream from the returned global sequence.
7. Normal bounded stream closure reconnects from the last accepted sequence.
8. Freeze, credential revocation, authentication failure, or malformed protocol data stops the stream and produces an explicit UI state.

## Google Play Internal testing

- Releases are signed Android App Bundles.
- No environment-specific secrets or endpoints are compiled into the bundle.
- Release builds disable cleartext traffic and debug-only diagnostics.
- Backup of credentials and private trust material is prohibited.
- Permissions remain minimal; MVP1 requires network access and camera access only while scanning enrollment QR codes.
- Logging and crash reporting must redact URLs where necessary and omit credentials, message bodies, and QR payloads.

## Deferred control planes

### Human approval requests

A future approval feature is a separate write plane. It must use typed request IDs, expiry, replay protection, exact context hashes, explicit allow/deny outcomes, and immutable audit records. A Bus message alone is never an executable approval request.

### Containment control

The deployed Admin plane exposes only device revocation, agent blocking, and freeze activation/clear. Each operation is server-bound to an exact target, displays the server-provided effect, collects a human audit reason, and requires a fresh biometric/PIN-backed Keystore unlock. No reusable admin session exists, writes are never automatically retried, and all authority-restoring operations remain console-only.

### Other LAN services

Future service integrations should use separate feature packages and narrowly scoped service credentials. StruggleBus credentials must not be reused for unrelated services.
