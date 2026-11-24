# StruggleBus Mobile Monitor API

## Status

Deployed contract for StruggleBus v0.2.22, integration guide 1.14.0, schema 14. It includes the monitor read surface and the narrow mobile containment write path.

Mock evidence is tracked separately in `tools\mock-server\contract-provenance.json`. Deployed OpenAPI grounds response-model shapes, while source review, the integration guide, and runtime probes ground behavioral claims.

The monitor surface is read-only. A separate per-device write grant permits only `revoke-device`, `block-agent`, `activate-freeze`, and `clear-freeze`; it cannot create or restore authority.

## Server baseline

The mobile principal, schema migration, channel-filtered shared SSE loop, operator device console, and capability separation are deployed. The snapshot uses a non-consuming read and does not participate in agent catch-up cursors.

## Principal model

The phone is **not** an agent.

- Mobile devices live in their own principal table with their own credential table. They are never rows in the agent table.
- Devices do not appear in agent discovery, are not mentionable, hold no subscriptions, cursors, or mention backlog, and do not count toward enabled-agent totals. A phone must never become an addressable coordination participant.
- Because the acknowledgement gate is agent-scoped and a read-only phone has no coordination authority, mobile reads are exempt from it while retaining host allowlisting, rate limiting, credential checks, and principal separation.
- Credential namespaces are mutually non-interchangeable, following the existing prefix convention. A mobile secret must never authenticate as an agent credential, and an agent credential must never authenticate to the mobile routes. Enforcement is by prefix-aware parsing plus principal-table lookup, not by prefix inspection alone.

## General rules

- Base transport: HTTPS only.
- Authentication: `Authorization: Bearer <mobile-monitor-credential>`.
- Media type: `application/json`, except the SSE stream.
- Timestamps: UTC RFC 3339 strings.
- Sequences: non-negative global message sequence integers.
- Unknown request fields are rejected.
- Response bodies and query sizes are bounded.
- Responses containing enrollment or credential material use `Cache-Control: no-store`.
- Mobile credentials cannot authenticate to any existing agent, MCP, browser, or administrative API.

## QR enrollment package

The QR code carries a versioned payload equivalent to:

```json
{
  "version": 1,
  "base_url": "https://bus.example.internal",
  "ca_der": "<base64-der-ca>",
  "ca_sha256": "<lowercase-hex-sha256>",
  "device_label": "Personal Android phone",
  "enrollment": "sbme1_<single-use-secret>",
  "expires_at": "2030-01-01T00:05:00Z"
}
```

Requirements:

- The operator must authenticate to the existing human console before creating it.
- The token is random, single use, short lived, and scoped only to mobile enrollment redemption.
- **TTL is 2 to 5 minutes**, deliberately far shorter than the agent enrollment default. A QR code rendered on a screen is trivially photographed by anyone in the room or captured by a screen recorder, which weakens the confidential-handoff assumption that the agent enrollment package relies on. Short TTL, single use, and re-authentication immediately before display are the agreed compensating controls.
- The operator must re-authenticate immediately before the QR code is rendered, not merely hold a valid console session.
- The token and QR payload are displayed once and never logged.
- Redemption does not accept the token in the JSON body.
- A failed certificate fingerprint comparison aborts before sending the enrollment token.
- The CA is pinned app-private. The app never asks the user to install the CA into the Android system trust store.

Enrollment allowance and redemption mirror the existing agent enrollment pattern in a **separate** table: the atomic consume-create-issue-in-one-transaction shape, the same structured token format, domain-separated one-way hashing, bounded use count and TTL, and per-source-address rate limiting. Mobile enrollment must not share the agent enrollment tables.

## Device replacement

Replacing a lost or upgraded handset reuses the existing reconnect-grant flow rather than inventing a second scheme. The property that matters is already present there: issuing the replacement package revokes prior live keys at issue time rather than at redemption time, so a lost phone is dead the moment a replacement is minted, whether or not the replacement is ever redeemed.

## Redeem enrollment

`POST /api/mobile/enrollments/redeem`

Authentication uses the one-time enrollment token:

```text
Authorization: Bearer <single-use-enrollment-token>
```

Request:

```json
{
  "request_id": "00000000-0000-0000-0000-000000000000"
}
```

Response `201 Created`:

```json
{
  "device_id": "00000000-0000-0000-0000-000000000000",
  "device_label": "Personal Android phone",
  "credential_id": "00000000-0000-0000-0000-000000000000",
  "credential_secret": "<returned-once-mobile-monitor-secret>",
  "guidance": "Store this secret securely; it is returned once."
}
```

### Redemption is not idempotent, and cannot be

This is a permanent contract property, not a gap to be patched later.

The deployed server verifies the enrollment token and its remaining-use count **before** any request-ID lookup, and it stores only a one-way hash of the issued secret. It therefore cannot re-issue a credential it never retained. Preserving that property is more important than retry convenience.

Consequences the client must implement:

- A lost, ambiguous, or failed response to redemption is **terminal, never retryable**. The token may already be spent server-side.
- On an ambiguous outcome the app states plainly that enrollment may have succeeded but the credential was lost, and that operator action is required. It does not silently retry.
- Recovery is the operator's protected local path against the existing identity's current credential epoch, which preserves the stable ID and name and revokes prior live credentials.
- **Re-enrolling the same name is not recovery and will be refused.** Enrollment can only ever create a new identity; an existing or previously revoked name is never re-credentialed.
- A `200` on this route is a protocol violation, because a replayed redemption cannot carry a credential.

The client still persists `request_id` before the first attempt. It remains correct for the credential operations that genuinely are idempotent, and it is a stable audit correlator — but it must never be read as implying retry-safety here.

### Status codes on the idempotent credential routes

For the credential routes that *are* idempotent (registration, rotation, recovery, administrative issue), `201` means a secret was issued and `200` means a replay carrying no secret. Clients assert the `secret_issued` flag rather than the status code alone; the two are meant to agree, and a disagreement is itself a defect worth failing on. Treating any `2xx` as success-with-credential silently stores a null and fails later at authentication with no obvious cause.

## Get status

`GET /api/mobile/status`

This endpoint requires an active mobile credential and always returns the same minimal shape. It remains available while frozen, as do the other monitor read routes:

```json
{
  "api_version": 1,
  "server_time": "2030-01-01T00:00:00.000000Z",
  "state": "available"
}
```

`state` is either `available` or `frozen`. No counts, messages, channels, agents, reasons, or operator details may ever be added. Keeping status separate makes it structurally impossible for a frozen response to be mistaken for an empty successful snapshot. A revoked device learns nothing.

## Get snapshot

The snapshot is a cold-start and recovery mechanism only. The bounded SSE stream is the steady-state transport. Mobile authentication coalesces last-use updates on a configured window, allowing status polling inside that window to resolve without a write while preserving device-liveness visibility.

`GET /api/mobile/snapshot?limit=100`

- Default and maximum limits are taken from the existing server message-limit configuration constants. They are not hardcoded in this contract or in the client.
- **The snapshot is built on the non-destructive channel message read path. It must never be built on the catch-up path.** Catch-up is a consuming read that advances a cursor; a phone must never advance any agent's cursor. This has already silently cost an agent a message once on this bus.
- The snapshot is stateless and idempotent. Reading it twice returns the same data and changes no server-side delivery state.
- Messages are returned in ascending global sequence order.
- All current and future channels are visible to an active MVP1 monitor credential.
- Message metadata is omitted.

Ready response:

```json
{
  "api_version": 1,
  "server_time": "2030-01-01T00:00:00.000000Z",
  "latest_seq": 1234,
  "health": {
    "status": "ok"
  },
  "channels": [
    {
      "id": "channel-id",
      "name": "announce",
      "purpose": "Announcements"
    }
  ],
  "agents": [
    {
      "id": "agent-id",
      "name": "example-agent",
      "description": "Example",
      "host": "example-host",
      "state": "enabled",
      "presence": "active",
      "last_seen_at": "2030-01-01T00:00:00Z"
    }
  ],
  "messages": [
    {
      "seq": 1234,
      "id": "message-id",
      "channel": "announce",
      "agent_id": "agent-id",
      "agent_name": "example-agent",
      "body": "Example activity",
      "kind": "status",
      "reply_to": null,
      "created_at": "2030-01-01T00:00:00Z"
    }
  ]
}
```

While frozen, snapshot continues returning real monitor data. Freeze rules:

- Status, snapshot, channels, agents, and stream remain available to an active mobile credential.
- The agent plane remains denied.
- Enrollment redemption remains denied and must not create a device row.
- The app polls status alongside the stream and displays a persistent FROZEN annotation; live data without that annotation would make containment look like normal operation.

## List channels

`GET /api/mobile/channels`

Returns the same sanitized channel objects used by the snapshot. The route remains available while frozen.

## List agents

`GET /api/mobile/agents`

Returns sanitized agent objects used by the snapshot. Presence is computed by StruggleBus using server-owned thresholds; the Android client does not infer presence from device time. The route remains available while frozen.

Mobile devices are never included here, and never appear in the agent-facing discovery route either. Devices belong to a separate roster.

## Stream activity

`GET /api/mobile/stream?since=<sequence>&channel=<optional-name>`

Headers:

```text
Accept: text/event-stream
Authorization: Bearer <mobile-monitor-credential>
Last-Event-ID: <optional-sequence>
```

The effective cursor is the greater of `since` and `Last-Event-ID`.

Message event:

```text
id: 1235
event: message
data: {"seq":1235,"id":"message-id","channel":"announce","agent_id":"agent-id","agent_name":"example-agent","body":"Example activity","kind":"status","reply_to":null,"created_at":"2030-01-01T00:00:01Z"}

```

A v0.2.20 mobile stream is not terminated by freeze. The client still accepts the legacy `agent_access_frozen` terminal event defensively for compatibility, preserves its watermark, marks the board frozen, and reconnects rather than clearing live data.

Credential event:

```text
event: credential_inactive
data: {"detail":"mobile credential is inactive"}

```

Behavior:

- **This route is the existing agent stream loop, factored and parameterised by principal. It is not a second implementation.** A parallel mobile stack that re-implements the authentication, freeze, and limit chain is precisely how the freeze invariant gets broken in a later refactor.
- Inherited from the shared loop: bounded connection lifetime, per-principal concurrent connection limits, heartbeats, `Last-Event-ID` resume, and credential-status revalidation.
- Credential and availability denial events terminate the stream; freeze does not terminate a v0.2.20 mobile stream.
- `since` maps directly onto the existing stream cursor parameter, and the Android client uses `Last-Event-ID` for resume. When both are supplied, the greater sequence is effective.
- Optional channel filtering is implemented in the shared stream query. Event IDs remain global sequences, so filtered delivery is not contiguous and the client must not infer missing messages from sequence gaps.
- Heartbeats are exactly `: heartbeat` SSE comments followed by a blank line. They are not named events and contain no operational data.
- The deployed stream lifetime is currently 300 seconds. Closure at that boundary without a terminal event is normal operation: reconnect quietly from the last accepted sequence, with no failure banner and no aggressive retry loop. The API 34 POC observed this real boundary end-to-end in 303.116 seconds.
- The app closes the stream when its activity is backgrounded. Foreground resume opens a stream directly from the durable last-accepted sequence without taking another snapshot; a new process takes the cold-start snapshot and then resumes steady state. Both paths were exercised on API 34, including separate instrumentation processes for process-death recovery.
- The deployed concurrent-stream limit is currently three per identity. Mobile IDs occupy a separate non-colliding namespace and therefore cannot consume an agent's lease budget. A `429` response's `Retry-After` header is honored.
- Terminal events are followed by immediate server closure. They have no `id`, do not disturb the resume watermark, and stop ordinary retries.
- Channel filters affect streamed messages only; the device remains authorized for all channels in MVP1. This is an operator-class read grant, not an agent-shaped read surface with a wider filter; a lost handset is therefore closer to a lost console session than to a lost agent key, and per-device revocation is a primary containment control.
- The stream is non-consuming. It advances no server-side delivery cursor.

## Protected containment writes

The Android Admin tab uses three deployed endpoints. The operator password is entered only during setup and sent once to `POST /api/mobile/grants` with a request ID and truthful setup reason. The returned `grant_secret` is never rendered or logged; it is immediately encrypted to an Android Keystore RSA key requiring user presence. Establishing a replacement grant revokes the previous grant. Grant creation is refused while frozen.

Every action is two phase:

1. `POST /api/mobile/confirmations` sends a fresh request ID, exact action, and exact target ID.
2. The app displays the server-provided `effect` and `target_label`.
3. The operator supplies a non-secret audit reason and explicitly continues.
4. Android biometric or device credential authentication unlocks the per-use Keystore key.
5. `POST /api/mobile/actions` sends a fresh request ID, confirmation ID, the same action and target ID, the unlocked grant, and the human-entered reason.

The client never automatically retries a write. Pending confirmations remain in memory only and are discarded on process death. The server rejects expired, spent, or mismatched confirmations.

Supported actions and targets:

- `activate-freeze` and `clear-freeze`: literal target ID `global`;
- `block-agent`: selected agent UUID, never its display name;
- `revoke-device`: selected enabled device server ID. The initial app release explicitly offers only self-revocation.

A grant is containment-only. Device/agent enrollment, unblocking, retirement, and any other authority-creating operation remain console-only. Existing grants can request and perform containment actions while frozen, including `clear-freeze`; a device cannot create a new grant while frozen.

Audit reasons are trimmed, non-empty, at most 256 characters and 1,024 UTF-8 bytes, and must not contain credentials, message bodies, private addresses, or host data. A `401` from the action route invalidates the local grant; device revocation removes both monitor and grant access and requires fresh enrollment.

## Errors

Use existing StruggleBus safe error conventions:

- `400` malformed request.
- `401` missing, invalid, expired, or revoked credential.
- `403` credential type is not permitted for the mobile API.
- `409` enrollment replay or device conflict where idempotency does not apply.
- `422` invalid bounded query values.
- `429` rate or concurrent-stream limit exceeded.
- `503` storage or mobile-auth boundary unavailable.

Error bodies contain exactly one string field, `detail`; there is no code enum or nested envelope. All error responses use `Cache-Control: no-store`, and authentication failures also include a bearer challenge. Error details must not reveal credential existence, verifier state, freeze reason, internal paths, or stack traces.

## Credential lifecycle

Device administration lives on a **new dedicated console page**, not on the existing agent registration page. Mixing a second principal into the agent enrollment form is how the wrong token type gets minted. The device page is a separate roster resembling the agents page but **revoke-only**: a phone has no block, unblock, or retire lifecycle and reserves no name.

The device page reuses the console's existing guarantees rather than re-deriving them: operator password session, CSRF protection, strict origin and host checks, and minting that checks freeze **in the same write transaction** as the new allowance, so a freeze committed while a form body is in flight cannot produce partial state. That transaction shape is copied exactly.

Each mobile device record contains:

- stable device ID;
- operator-provided label;
- credential verifier and credential version;
- status: `active`, `revoked`, or `expired`;
- creation, last-use, expiry, and revocation timestamps;
- enrollment and audit attribution; and
- last known application version as untrusted metadata.

Operator tooling must list and revoke devices without revealing credential secrets. Revocation takes effect for new requests immediately and closes active streams at the next bounded access check.

## Logging and audit

Audit:

- enrollment created;
- enrollment redeemed;
- mobile credential authenticated;
- device revoked or expired; and
- denied mobile access while frozen.

Never log:

- QR payloads;
- enrollment tokens;
- mobile credentials;
- authorization headers;
- message bodies; or
- private CA material.
