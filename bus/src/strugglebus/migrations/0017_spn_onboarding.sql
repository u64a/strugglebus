-- Dedicated service principals for automated, exact-name agent onboarding.
--
-- SPNs are not agents and cannot be used in any agent credential path. Their
-- only authority is to create a one-time enrollment package under an
-- operator-configured lowercase kebab-case prefix. Blocking immediately
-- revokes every still-pending enrollment issued by that SPN; unblocking never
-- restores those packages. Agents already created from an enrollment remain
-- durable identities and are managed through the existing agent lifecycle.
--
-- Rollback: back up and stop the service. Drop the provenance triggers/table,
-- the SPN triggers, indexes and five spn_* tables, then set
-- `PRAGMA user_version = 16`. The nullable
-- `agent_enrollments.spn_id` column cannot be removed safely on all supported
-- SQLite versions; restore the verified schema-16 backup when an exact schema
-- rollback is required. Rolling back loses SPN identities, credentials,
-- issuance history, immutable identity-creation provenance and audit evidence,
-- but must not delete or alter agents already created through redeemed
-- packages. Export the attributed roster before rollback when it is needed for
-- later containment or cleanup.

ALTER TABLE agent_enrollments ADD COLUMN spn_id TEXT
    REFERENCES spn_principals(id) ON DELETE RESTRICT;

CREATE TRIGGER agent_enrollments_spn_binding_immutable
BEFORE UPDATE OF spn_id ON agent_enrollments
WHEN new.spn_id IS NOT old.spn_id
BEGIN
    SELECT RAISE(ABORT, 'enrollment SPN binding is immutable');
END;

CREATE TABLE spn_principals (
    id                TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    name              TEXT NOT NULL UNIQUE
        CHECK (
            length(name) BETWEEN 1 AND 64
            AND name NOT GLOB '*[^0-9a-z-]*'
        ),
    agent_name_prefix TEXT NOT NULL
        CHECK (
            length(agent_name_prefix) BETWEEN 1 AND 128
            AND agent_name_prefix NOT GLOB '*[^0-9a-z-]*'
        ),
    status            TEXT NOT NULL
        CHECK (status IN ('enabled', 'blocked', 'revoked')),
    created_at        TEXT NOT NULL,
    blocked_at        TEXT,
    revoked_at        TEXT,
    version           INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (
        (status = 'enabled' AND blocked_at IS NULL AND revoked_at IS NULL)
        OR (status = 'blocked' AND blocked_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE TRIGGER spn_principals_identity_immutable
BEFORE UPDATE ON spn_principals
WHEN new.id <> old.id
  OR new.name <> old.name
  OR new.agent_name_prefix <> old.agent_name_prefix
  OR new.created_at <> old.created_at
  OR old.status = 'revoked'
BEGIN
    SELECT RAISE(ABORT, 'spn identity is immutable');
END;

CREATE TABLE spn_credentials (
    id                  TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    spn_id              TEXT NOT NULL
        REFERENCES spn_principals(id) ON DELETE RESTRICT,
    kind                TEXT NOT NULL CHECK (kind = 'sbsp1'),
    secret_hash         TEXT NOT NULL UNIQUE
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    status              TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    issuance_request_id TEXT NOT NULL UNIQUE
        CHECK (length(issuance_request_id) BETWEEN 1 AND 128),
    created_at          TEXT NOT NULL,
    last_used_at        TEXT,
    revoked_at          TEXT,
    version             INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX idx_spn_credentials_one_active
    ON spn_credentials (spn_id) WHERE status = 'active';

CREATE TRIGGER spn_credentials_provenance_immutable
BEFORE UPDATE ON spn_credentials
WHEN new.id <> old.id
  OR new.spn_id <> old.spn_id
  OR new.kind <> old.kind
  OR new.secret_hash <> old.secret_hash
  OR new.issuance_request_id <> old.issuance_request_id
  OR new.created_at <> old.created_at
BEGIN
    SELECT RAISE(ABORT, 'spn credential provenance is immutable');
END;

CREATE TABLE spn_requests (
    request_id           TEXT PRIMARY KEY
        CHECK (length(request_id) BETWEEN 1 AND 128),
    operation            TEXT NOT NULL
        CHECK (operation IN ('create', 'rotate')),
    intent_sha256        TEXT NOT NULL
        CHECK (
            length(intent_sha256) = 64
            AND intent_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    spn_id               TEXT NOT NULL
        REFERENCES spn_principals(id) ON DELETE RESTRICT,
    result_credential_id TEXT NOT NULL
        REFERENCES spn_credentials(id) ON DELETE RESTRICT,
    created_at           TEXT NOT NULL
);

CREATE TRIGGER spn_requests_no_update
BEFORE UPDATE ON spn_requests
BEGIN
    SELECT RAISE(ABORT, 'spn request evidence is immutable');
END;

CREATE TRIGGER spn_requests_no_delete
BEFORE DELETE ON spn_requests
BEGIN
    SELECT RAISE(ABORT, 'spn request evidence is immutable');
END;

CREATE TABLE spn_transition_requests (
    request_id        TEXT PRIMARY KEY
        CHECK (length(request_id) BETWEEN 1 AND 128),
    spn_id            TEXT NOT NULL
        REFERENCES spn_principals(id) ON DELETE RESTRICT,
    action            TEXT NOT NULL
        CHECK (action IN ('block', 'unblock', 'revoke')),
    expected_version  INTEGER NOT NULL CHECK (expected_version >= 0),
    intent_sha256     TEXT NOT NULL
        CHECK (
            length(intent_sha256) = 64
            AND intent_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    result_status     TEXT NOT NULL
        CHECK (result_status IN ('enabled', 'blocked', 'revoked')),
    result_version    INTEGER NOT NULL CHECK (result_version >= 1),
    result_blocked_at TEXT,
    result_revoked_at TEXT,
    created_at        TEXT NOT NULL,
    CHECK (
        (result_status = 'enabled'
         AND result_blocked_at IS NULL AND result_revoked_at IS NULL)
        OR (result_status = 'blocked'
            AND result_blocked_at IS NOT NULL AND result_revoked_at IS NULL)
        OR (result_status = 'revoked' AND result_revoked_at IS NOT NULL)
    )
);

CREATE INDEX idx_spn_transition_requests_principal
    ON spn_transition_requests (spn_id, created_at, request_id);

CREATE TRIGGER spn_transition_requests_no_update
BEFORE UPDATE ON spn_transition_requests
BEGIN
    SELECT RAISE(ABORT, 'spn transition request evidence is immutable');
END;

CREATE TRIGGER spn_transition_requests_no_delete
BEFORE DELETE ON spn_transition_requests
BEGIN
    SELECT RAISE(ABORT, 'spn transition request evidence is immutable');
END;

CREATE TABLE spn_onboarding_issuances (
    request_id      TEXT PRIMARY KEY
        CHECK (length(request_id) BETWEEN 1 AND 128),
    spn_id          TEXT NOT NULL
        REFERENCES spn_principals(id) ON DELETE RESTRICT,
    intent_sha256   TEXT NOT NULL
        CHECK (
            length(intent_sha256) = 64
            AND intent_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    enrollment_id   TEXT NOT NULL UNIQUE
        REFERENCES agent_enrollments(id) ON DELETE RESTRICT,
    agent_name      TEXT NOT NULL
        CHECK (length(agent_name) BETWEEN 1 AND 128),
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    CHECK (created_at < expires_at)
);

CREATE INDEX idx_spn_onboarding_outstanding
    ON spn_onboarding_issuances (spn_id, expires_at);

CREATE TRIGGER spn_onboarding_issuances_no_update
BEFORE UPDATE ON spn_onboarding_issuances
BEGIN
    SELECT RAISE(ABORT, 'spn onboarding issuance is immutable');
END;

CREATE TRIGGER spn_onboarding_issuances_no_delete
BEFORE DELETE ON spn_onboarding_issuances
BEGIN
    SELECT RAISE(ABORT, 'spn onboarding issuance is immutable');
END;

-- One immutable row identifies the trusted principal that caused each agent
-- identity to exist. Posted redemption fields are never used as creator
-- identity. Enrollment creators come from the protected enrollment record;
-- SPN creators and package request IDs come from the SPN issuance relation.
CREATE TABLE agent_identity_provenance (
    agent_id                       TEXT PRIMARY KEY
        REFERENCES agents(id) ON DELETE RESTRICT,
    creation_method                TEXT NOT NULL
        CHECK (creation_method IN (
            'direct-registration', 'enrollment', 'spn-enrollment',
            'schema-17-backfill'
        )),
    creator_principal_type         TEXT NOT NULL
        CHECK (creator_principal_type IN (
            'system', 'local-admin', 'remote-admin', 'spn'
        )),
    creator_principal_id           TEXT NOT NULL
        CHECK (length(creator_principal_id) BETWEEN 1 AND 256),
    originating_request_id         TEXT NOT NULL
        CHECK (length(originating_request_id) BETWEEN 1 AND 128),
    originating_enrollment_id      TEXT
        REFERENCES agent_enrollments(id) ON DELETE RESTRICT,
    originating_issuance_request_id TEXT
        REFERENCES spn_onboarding_issuances(request_id) ON DELETE RESTRICT,
    created_at                     TEXT NOT NULL,
    CHECK (
        (
            creation_method = 'spn-enrollment'
            AND creator_principal_type = 'spn'
            AND originating_enrollment_id IS NOT NULL
            AND originating_issuance_request_id IS NOT NULL
        )
        OR (
            creation_method <> 'spn-enrollment'
            AND creator_principal_type <> 'spn'
            AND originating_issuance_request_id IS NULL
        )
    )
);

CREATE INDEX idx_agent_identity_provenance_creator
    ON agent_identity_provenance (
        creator_principal_type, creator_principal_id, created_at, agent_id
    );

CREATE TRIGGER agent_identity_provenance_no_update
BEFORE UPDATE ON agent_identity_provenance
BEGIN
    SELECT RAISE(ABORT, 'identity creation provenance is immutable');
END;

CREATE TRIGGER agent_identity_provenance_no_delete
BEFORE DELETE ON agent_identity_provenance
BEGIN
    SELECT RAISE(ABORT, 'identity creation provenance is immutable');
END;

-- Schema-16 identities predate this relation. Backfill exclusively from
-- server-authored credential/enrollment evidence, never from agent input.
INSERT INTO agent_identity_provenance (
    agent_id, creation_method, creator_principal_type, creator_principal_id,
    originating_request_id, originating_enrollment_id,
    originating_issuance_request_id, created_at
)
SELECT
    a.id,
    'schema-17-backfill',
    CASE
        WHEN e.id IS NOT NULL THEN e.actor_type
        ELSE COALESCE(
            (
                SELECT audit.actor_type
                FROM agent_credential_audit AS audit
                WHERE audit.agent_id = a.id
                  AND audit.event_type IN ('issue', 'migrate')
                ORDER BY audit.seq
                LIMIT 1
            ),
            'system'
        )
    END,
    CASE
        WHEN e.id IS NOT NULL THEN e.actor_id
        ELSE COALESCE(
            (
                SELECT audit.actor_id
                FROM agent_credential_audit AS audit
                WHERE audit.agent_id = a.id
                  AND audit.event_type IN ('issue', 'migrate')
                ORDER BY audit.seq
                LIMIT 1
            ),
            'system:schema-17-backfill'
        )
    END,
    COALESCE(
        redemption.request_id,
        (
            SELECT credential.issuance_request_id
            FROM agent_credentials AS credential
            WHERE credential.agent_id = a.id
            ORDER BY credential.created_at, credential.id
            LIMIT 1
        ),
        'schema17-backfill:' || a.id
    ),
    redemption.enrollment_id,
    NULL,
    a.created_at
FROM agents AS a
LEFT JOIN agent_enrollment_redemptions AS redemption
    ON redemption.agent_id = a.id
LEFT JOIN agent_enrollments AS e
    ON e.id = redemption.enrollment_id;

CREATE TABLE spn_audit (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    id           TEXT NOT NULL UNIQUE
        CHECK (length(id) BETWEEN 1 AND 128),
    event_type   TEXT NOT NULL
        CHECK (event_type IN (
            'created', 'blocked', 'unblocked', 'rotated', 'revoked',
            'package-issued'
        )),
    spn_id       TEXT NOT NULL
        REFERENCES spn_principals(id) ON DELETE RESTRICT,
    credential_id TEXT
        REFERENCES spn_credentials(id) ON DELETE RESTRICT,
    enrollment_id TEXT
        REFERENCES agent_enrollments(id) ON DELETE RESTRICT,
    actor_type   TEXT NOT NULL
        CHECK (actor_type IN ('local-admin', 'remote-admin', 'spn')),
    actor_id     TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    reason       TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    request_id   TEXT CHECK (request_id IS NULL OR length(request_id) BETWEEN 1 AND 128),
    occurred_at  TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
        CHECK (length(details_json) <= 4096)
);

CREATE INDEX idx_spn_audit_principal
    ON spn_audit (spn_id, seq);

CREATE TRIGGER spn_audit_no_update
BEFORE UPDATE ON spn_audit
BEGIN
    SELECT RAISE(ABORT, 'spn audit is append-only');
END;

CREATE TRIGGER spn_audit_no_delete
BEFORE DELETE ON spn_audit
BEGIN
    SELECT RAISE(ABORT, 'spn audit is append-only');
END;
