-- Device write grants and action confirmations: a second, revocable proof.
--
-- Reads are authorised by the device credential alone, because a monitor must
-- keep polling while the handset is locked. A write additionally requires this
-- grant, which the app holds under biometric release. The two secrets live on
-- the same device, so they are not independent factors; what differs is the
-- unlock condition, and the property that buys is that possession of the
-- running app is not by itself a write capability.
--
-- The operator password is deliberately NOT what the handset stores. It is one
-- system-wide verifier that also opens the console from any browser, so a
-- handset copy could not be contained by revoking the device: the holder would
-- no longer need the device. A grant is per-device, so the existing revocation
-- and replacement paths contain it, and those paths are the primary control the
-- device roster was built around.
--
-- A grant secret is server-generated with 256 bits of entropy and never shown
-- to a human, so it is stored as a plain SHA-256 hash and compared in constant
-- time. It deliberately does not use the password verifier's PBKDF2 work
-- factor: that cost exists to defend a low-entropy human secret, and applying
-- it here would put an expensive verification on the write path that shares a
-- bounded worker pool with operator login - a write burst would lock the owner
-- out of their own console.
--
-- Confirmations bind one action to one target for one device, expire quickly
-- and are single use, so a confirmation obtained for a small action cannot be
-- replayed against a larger one.
--
-- Rollback: this migration only adds tables and indexes. To return to schema
-- 13, drop both tables and their triggers and set `PRAGMA user_version = 13`.
-- No agent, credential, device, message or cursor row is read or written here,
-- so a rollback loses only write grants and unspent confirmations; every device
-- keeps reading. Restore from a verified backup instead if grant state must be
-- preserved.

CREATE TABLE mobile_write_grants (
    id                   TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    device_id            TEXT NOT NULL
        REFERENCES mobile_devices(id) ON DELETE RESTRICT,
    kind                 TEXT NOT NULL
        CHECK (kind IN ('sbmw1')),
    secret_hash          TEXT NOT NULL UNIQUE
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    status               TEXT NOT NULL
        CHECK (status IN ('active', 'revoked')),
    issuance_request_id  TEXT NOT NULL UNIQUE
        CHECK (length(issuance_request_id) BETWEEN 1 AND 128),
    creation_reason      TEXT NOT NULL
        CHECK (length(creation_reason) BETWEEN 1 AND 256),
    created_at           TEXT NOT NULL,
    last_used_at         TEXT,
    revoked_at           TEXT,
    revocation_reason    TEXT
        CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256),
    version              INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (
        (status = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

-- One active grant per device. Establishing a replacement must revoke the
-- predecessor in the same transaction, so a device can never hold two write
-- secrets and a revocation can never leave one behind.
CREATE UNIQUE INDEX idx_mobile_write_grants_one_active
    ON mobile_write_grants (device_id)
    WHERE status = 'active';

CREATE INDEX idx_mobile_write_grants_device
    ON mobile_write_grants (device_id, status);

-- A grant is never re-secreted in place, exactly as a device credential is not.
CREATE TRIGGER mobile_write_grants_are_append_only
BEFORE UPDATE ON mobile_write_grants
WHEN new.id <> old.id
  OR new.device_id <> old.device_id
  OR new.kind <> old.kind
  OR new.secret_hash <> old.secret_hash
  OR new.issuance_request_id <> old.issuance_request_id
  OR new.created_at <> old.created_at
BEGIN
    SELECT RAISE(ABORT, 'mobile write grant provenance is immutable');
END;

CREATE TABLE mobile_action_confirmations (
    id             TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    device_id      TEXT NOT NULL
        REFERENCES mobile_devices(id) ON DELETE RESTRICT,
    -- Containment only, enforced here rather than only in application code.
    -- Everything in this set stops or narrows access. Actions that mint or
    -- restore authority - enrolling a device or agent, unblocking, retiring -
    -- are deliberately absent: a device-held secret must not be able to create
    -- authority, and the console remains the only place those happen. A code
    -- path that tried would be refused by the database.
    action         TEXT NOT NULL
        CHECK (action IN (
            'revoke-device',
            'block-agent',
            'activate-freeze',
            'clear-freeze'
        )),
    target_kind    TEXT NOT NULL
        CHECK (target_kind IN ('device', 'agent', 'system')),
    target_id      TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 256),
    target_label   TEXT NOT NULL CHECK (length(target_label) BETWEEN 1 AND 256),
    -- Captured when the confirmation is issued so the executing request cannot
    -- act on a target that changed underneath the displayed description.
    target_version INTEGER NOT NULL CHECK (target_version >= 0),
    status         TEXT NOT NULL
        CHECK (status IN ('pending', 'consumed')),
    request_id     TEXT NOT NULL UNIQUE
        CHECK (length(request_id) BETWEEN 1 AND 128),
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    consumed_at    TEXT,
    CHECK (created_at < expires_at),
    CHECK (
        (status = 'pending' AND consumed_at IS NULL)
        OR (status = 'consumed' AND consumed_at IS NOT NULL)
    ),
    -- A freeze transition has no per-object target, and an object action must
    -- never be recorded against the system.
    CHECK (
        (action IN ('activate-freeze', 'clear-freeze') AND target_kind = 'system')
        OR (action = 'revoke-device' AND target_kind = 'device')
        OR (action = 'block-agent' AND target_kind = 'agent')
    )
);

CREATE INDEX idx_mobile_action_confirmations_device
    ON mobile_action_confirmations (device_id, status, expires_at);

-- Single use in the strongest sense: the binding cannot be edited, and a
-- consumed confirmation cannot return to pending. Only the consumption fields
-- may ever change.
CREATE TRIGGER mobile_action_confirmations_bindings_are_immutable
BEFORE UPDATE ON mobile_action_confirmations
WHEN new.id <> old.id
  OR new.device_id <> old.device_id
  OR new.action <> old.action
  OR new.target_kind <> old.target_kind
  OR new.target_id <> old.target_id
  OR new.target_label <> old.target_label
  OR new.target_version <> old.target_version
  OR new.request_id <> old.request_id
  OR new.created_at <> old.created_at
  OR new.expires_at <> old.expires_at
  OR (old.status = 'consumed' AND new.status <> 'consumed')
BEGIN
    SELECT RAISE(ABORT, 'mobile action confirmation binding is immutable');
END;
