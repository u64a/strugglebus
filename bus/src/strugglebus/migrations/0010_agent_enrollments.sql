-- Single-use, short-lived, allowance-bound agent enrollment.
--
-- An enrollment is an operator-minted allowance, not an identity. It is stored
-- only as a one-way hash, it expires, it carries a bounded number of uses, and
-- it constrains the names a redeeming agent may claim. Redemption creates a new
-- agent and a normal pending credential; it can never adopt, resurrect, or
-- re-credential an existing agent.

CREATE TABLE agent_enrollments (
    id               TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    secret_hash      TEXT NOT NULL UNIQUE
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    name_prefix      TEXT NOT NULL
        CHECK (
            length(name_prefix) BETWEEN 1 AND 128
            AND name_prefix NOT GLOB '*[^0-9a-z-]*'
        ),
    description      TEXT NOT NULL DEFAULT ''
        CHECK (length(description) <= 1024),
    status           TEXT NOT NULL
        CHECK (status IN ('pending', 'exhausted', 'revoked')),
    uses_allowed     INTEGER NOT NULL
        CHECK (uses_allowed BETWEEN 1 AND 64),
    uses_remaining   INTEGER NOT NULL
        CHECK (uses_remaining >= 0),
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    last_redeemed_at TEXT,
    exhausted_at     TEXT,
    revoked_at       TEXT,
    revocation_reason TEXT
        CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256),
    actor_type       TEXT NOT NULL
        CHECK (actor_type IN ('system', 'local-admin', 'remote-admin')),
    actor_id         TEXT NOT NULL
        CHECK (length(actor_id) BETWEEN 1 AND 256),
    creation_reason  TEXT NOT NULL
        CHECK (length(creation_reason) BETWEEN 1 AND 256),
    version          INTEGER NOT NULL DEFAULT 0
        CHECK (version >= 0),
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
            AND revocation_reason IS NULL
        )
        OR (
            status = 'revoked'
            AND revoked_at IS NOT NULL
            AND revocation_reason IS NOT NULL
            AND exhausted_at IS NULL
        )
    )
);

CREATE INDEX idx_agent_enrollments_status_expiry
    ON agent_enrollments (status, expires_at);

-- Enrollment identity, verifier, allowance ceiling and constraint are fixed at
-- mint time. Only consumption and revocation may change, and uses_remaining is
-- monotonically non-increasing.
CREATE TRIGGER agent_enrollments_immutable_identity
BEFORE UPDATE ON agent_enrollments
WHEN new.id <> old.id
  OR new.secret_hash <> old.secret_hash
  OR new.name_prefix <> old.name_prefix
  OR new.description <> old.description
  OR new.uses_allowed <> old.uses_allowed
  OR new.created_at <> old.created_at
  OR new.expires_at <> old.expires_at
  OR new.actor_type <> old.actor_type
  OR new.actor_id <> old.actor_id
  OR new.creation_reason <> old.creation_reason
BEGIN
    SELECT RAISE(ABORT, 'enrollment identity and allowance are immutable');
END;

CREATE TRIGGER agent_enrollments_monotonic_consumption
BEFORE UPDATE ON agent_enrollments
WHEN new.uses_remaining > old.uses_remaining
  OR new.version <> old.version + 1
  OR old.status <> 'pending'
BEGIN
    SELECT RAISE(ABORT, 'enrollment allowance cannot increase or be reused');
END;

CREATE TRIGGER agent_enrollments_no_delete
BEFORE DELETE ON agent_enrollments
BEGIN
    SELECT RAISE(ABORT, 'enrollments cannot be deleted');
END;

-- One immutable row per successful redemption, binding the consumed allowance
-- to the exact agent and credential it produced.
CREATE TABLE agent_enrollment_redemptions (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id  TEXT NOT NULL
        REFERENCES agent_enrollments(id) ON DELETE RESTRICT,
    agent_id       TEXT NOT NULL UNIQUE
        REFERENCES agents(id) ON DELETE RESTRICT,
    credential_id  TEXT NOT NULL
        REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    claimed_name   TEXT NOT NULL
        CHECK (length(claimed_name) BETWEEN 1 AND 128),
    request_id     TEXT NOT NULL UNIQUE
        CHECK (length(request_id) BETWEEN 1 AND 128),
    redeemed_at    TEXT NOT NULL
);

CREATE INDEX idx_agent_enrollment_redemptions_enrollment
    ON agent_enrollment_redemptions (enrollment_id, seq DESC);

CREATE TRIGGER agent_enrollment_redemptions_no_update
BEFORE UPDATE ON agent_enrollment_redemptions
BEGIN
    SELECT RAISE(ABORT, 'enrollment redemptions are immutable');
END;

CREATE TRIGGER agent_enrollment_redemptions_no_delete
BEFORE DELETE ON agent_enrollment_redemptions
BEGIN
    SELECT RAISE(ABORT, 'enrollment redemptions are immutable');
END;
