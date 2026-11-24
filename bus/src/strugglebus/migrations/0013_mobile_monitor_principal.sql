-- Mobile monitor principals: a read-only, non-agent identity class.
--
-- A monitoring device must not be an agent. An `agents` row means more than
-- "may call the API": it carries discovery, mentionability, subscriptions,
-- delivery cursors and mention backlog, so a handset modelled as an agent
-- would appear in agent discovery and other agents could correctly address
-- coordination work to it. A read-only capability flag would not remove any of
-- that, because the problem is what the row means elsewhere.
--
-- These tables therefore stand apart from the agent tables entirely. Nothing
-- here alters `agents` or `agent_credentials`, so the agent credential
-- lifecycle and its CHECK constraints are untouched, and a mobile identifier
-- can never collide with an agent identifier.
--
-- Rollback: this migration only adds tables. To return to schema 12, drop the
-- five tables and their triggers and set `PRAGMA user_version = 12`. No agent
-- row, credential, message, cursor or receipt is read or written here, so a
-- rollback loses only mobile devices and their enrollment history. Restore
-- from a verified backup instead if mobile state must be preserved.

CREATE TABLE mobile_devices (
    id            TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    label         TEXT NOT NULL UNIQUE
        CHECK (
            length(label) BETWEEN 1 AND 64
            AND label NOT GLOB '*[^0-9a-z-]*'
        ),
    description   TEXT NOT NULL DEFAULT ''
        CHECK (length(description) <= 1024),
    status        TEXT NOT NULL
        CHECK (status IN ('enabled', 'revoked')),
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT,
    revoked_at    TEXT,
    revocation_reason TEXT
        CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256),
    version       INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (
        (status = 'enabled' AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

-- A device label is permanently reserved once used, exactly as an agent name
-- is. Revocation is terminal: a replaced handset is a new device, and reusing a
-- label would let history be silently reattributed.
CREATE TRIGGER mobile_devices_label_is_immutable
BEFORE UPDATE ON mobile_devices
WHEN new.label <> old.label OR new.id <> old.id OR new.created_at <> old.created_at
BEGIN
    SELECT RAISE(ABORT, 'mobile device identity is immutable');
END;

CREATE TABLE mobile_device_credentials (
    id                   TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    device_id            TEXT NOT NULL
        REFERENCES mobile_devices(id) ON DELETE RESTRICT,
    kind                 TEXT NOT NULL
        CHECK (kind IN ('sbm1')),
    secret_hash          TEXT NOT NULL UNIQUE
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    status               TEXT NOT NULL
        CHECK (status IN ('active', 'revoked')),
    creation_method      TEXT NOT NULL
        CHECK (length(creation_method) BETWEEN 1 AND 64),
    creation_reason      TEXT NOT NULL
        CHECK (length(creation_reason) BETWEEN 1 AND 256),
    issuance_request_id  TEXT NOT NULL UNIQUE
        CHECK (length(issuance_request_id) BETWEEN 1 AND 128),
    created_at           TEXT NOT NULL,
    last_used_at         TEXT,
    revoked_at           TEXT,
    version              INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX idx_mobile_device_credentials_device
    ON mobile_device_credentials (device_id, status);

-- A mobile credential is never re-credentialed in place; issuing a replacement
-- creates a new row and revokes the old one, so the hash and its owner cannot
-- drift apart.
CREATE TRIGGER mobile_device_credentials_are_append_only
BEFORE UPDATE ON mobile_device_credentials
WHEN new.id <> old.id
  OR new.device_id <> old.device_id
  OR new.kind <> old.kind
  OR new.secret_hash <> old.secret_hash
  OR new.issuance_request_id <> old.issuance_request_id
  OR new.created_at <> old.created_at
BEGIN
    SELECT RAISE(ABORT, 'mobile credential provenance is immutable');
END;

CREATE TABLE mobile_enrollments (
    id                TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    secret_hash       TEXT NOT NULL UNIQUE
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    device_label      TEXT NOT NULL
        CHECK (
            length(device_label) BETWEEN 1 AND 64
            AND device_label NOT GLOB '*[^0-9a-z-]*'
        ),
    status            TEXT NOT NULL
        CHECK (status IN ('pending', 'exhausted', 'revoked')),
    uses_allowed      INTEGER NOT NULL CHECK (uses_allowed BETWEEN 1 AND 8),
    uses_remaining    INTEGER NOT NULL CHECK (uses_remaining >= 0),
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    last_redeemed_at  TEXT,
    exhausted_at      TEXT,
    revoked_at        TEXT,
    revocation_reason TEXT
        CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256),
    actor_type        TEXT NOT NULL
        CHECK (actor_type IN ('system', 'local-admin', 'remote-admin')),
    actor_id          TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    creation_reason   TEXT NOT NULL CHECK (length(creation_reason) BETWEEN 1 AND 256),
    version           INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (uses_remaining <= uses_allowed),
    CHECK (created_at < expires_at),
    CHECK (
        (
            status = 'pending'
            AND uses_remaining > 0
            AND exhausted_at IS NULL
            AND revoked_at IS NULL
            AND revocation_reason IS NULL
        )
        OR (
            status = 'exhausted'
            AND uses_remaining = 0
            AND exhausted_at IS NOT NULL
            AND revoked_at IS NULL
        )
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE TABLE mobile_enrollment_redemptions (
    request_id     TEXT PRIMARY KEY
        CHECK (length(request_id) BETWEEN 1 AND 128),
    enrollment_id  TEXT NOT NULL
        REFERENCES mobile_enrollments(id) ON DELETE RESTRICT,
    device_id      TEXT NOT NULL
        REFERENCES mobile_devices(id) ON DELETE RESTRICT,
    credential_id  TEXT NOT NULL
        REFERENCES mobile_device_credentials(id) ON DELETE RESTRICT,
    redeemed_at    TEXT NOT NULL
);

-- Redemptions are evidence, never a cache to be rewritten. A replayed
-- redemption cannot return a secret the server never retained, so the record
-- exists for audit rather than for idempotent replay.
CREATE TRIGGER mobile_enrollment_redemptions_no_update
BEFORE UPDATE ON mobile_enrollment_redemptions
BEGIN
    SELECT RAISE(ABORT, 'mobile redemptions are immutable');
END;

CREATE TRIGGER mobile_enrollment_redemptions_no_delete
BEFORE DELETE ON mobile_enrollment_redemptions
BEGIN
    SELECT RAISE(ABORT, 'mobile redemptions are immutable');
END;

CREATE TABLE mobile_device_audit (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    id             TEXT NOT NULL UNIQUE
        CHECK (length(id) BETWEEN 1 AND 128),
    event_type     TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    device_id      TEXT
        REFERENCES mobile_devices(id) ON DELETE RESTRICT,
    credential_id  TEXT
        REFERENCES mobile_device_credentials(id) ON DELETE RESTRICT,
    actor_type     TEXT NOT NULL
        CHECK (actor_type IN ('system', 'local-admin', 'remote-admin')),
    actor_id       TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    reason         TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    request_id     TEXT CHECK (request_id IS NULL OR length(request_id) BETWEEN 1 AND 128),
    occurred_at    TEXT NOT NULL,
    details_json   TEXT NOT NULL DEFAULT '{}'
        CHECK (length(details_json) <= 4096)
);

CREATE INDEX idx_mobile_device_audit_device
    ON mobile_device_audit (device_id, seq);

CREATE TRIGGER mobile_device_audit_no_update
BEFORE UPDATE ON mobile_device_audit
BEGIN
    SELECT RAISE(ABORT, 'mobile audit is append-only');
END;

CREATE TRIGGER mobile_device_audit_no_delete
BEFORE DELETE ON mobile_device_audit
BEGIN
    SELECT RAISE(ABORT, 'mobile audit is append-only');
END;
