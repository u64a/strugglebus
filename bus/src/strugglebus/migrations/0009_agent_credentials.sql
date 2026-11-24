ALTER TABLE agents
    ADD COLUMN credential_epoch INTEGER NOT NULL DEFAULT 0
        CHECK (credential_epoch >= 0);

CREATE TABLE agent_credentials (
    id                    TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    agent_id              TEXT NOT NULL
        REFERENCES agents(id) ON DELETE RESTRICT,
    kind                  TEXT NOT NULL
        CHECK (kind IN ('legacy-sha256-v1', 'sb1')),
    secret_hash           TEXT NOT NULL
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'active', 'retired', 'revoked', 'expired')),
    predecessor_id        TEXT
        REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    creation_method       TEXT NOT NULL
        CHECK (length(creation_method) BETWEEN 1 AND 64),
    creation_reason       TEXT NOT NULL
        CHECK (length(creation_reason) BETWEEN 1 AND 256),
    issuance_request_id   TEXT NOT NULL UNIQUE
        CHECK (length(issuance_request_id) BETWEEN 1 AND 128),
    created_at            TEXT NOT NULL,
    activated_at          TEXT,
    identity_verified_at  TEXT,
    pending_expires_at    TEXT,
    last_used_at          TEXT,
    retired_at            TEXT,
    revoked_at            TEXT,
    expired_at            TEXT,
    version               INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (predecessor_id IS NULL OR predecessor_id <> id),
    CHECK (
        (
            status = 'pending'
            AND pending_expires_at IS NOT NULL
            AND activated_at IS NULL
            AND identity_verified_at IS NULL
            AND retired_at IS NULL
            AND revoked_at IS NULL
            AND expired_at IS NULL
        )
        OR (
            status = 'active'
            AND activated_at IS NOT NULL
            AND identity_verified_at IS NOT NULL
            AND retired_at IS NULL
            AND revoked_at IS NULL
            AND expired_at IS NULL
        )
        OR (
            status = 'retired'
            AND activated_at IS NOT NULL
            AND identity_verified_at IS NOT NULL
            AND retired_at IS NOT NULL
            AND revoked_at IS NULL
            AND expired_at IS NULL
        )
        OR (
            status = 'revoked'
            AND retired_at IS NULL
            AND revoked_at IS NOT NULL
            AND expired_at IS NULL
        )
        OR (
            status = 'expired'
            AND activated_at IS NULL
            AND identity_verified_at IS NULL
            AND retired_at IS NULL
            AND revoked_at IS NULL
            AND expired_at IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX idx_agent_credentials_legacy_hash
    ON agent_credentials (kind, secret_hash)
    WHERE kind = 'legacy-sha256-v1';

CREATE INDEX idx_agent_credentials_agent_status
    ON agent_credentials (agent_id, status, created_at);

CREATE INDEX idx_agent_credentials_predecessor
    ON agent_credentials (predecessor_id);

CREATE TRIGGER agent_credentials_immutable_identity
BEFORE UPDATE ON agent_credentials
WHEN new.id <> old.id
  OR new.agent_id <> old.agent_id
  OR new.kind <> old.kind
  OR new.secret_hash <> old.secret_hash
  OR new.predecessor_id IS NOT old.predecessor_id
  OR new.creation_method <> old.creation_method
  OR new.creation_reason <> old.creation_reason
  OR new.issuance_request_id <> old.issuance_request_id
  OR new.created_at <> old.created_at
BEGIN
    SELECT RAISE(ABORT, 'credential identity and verifier are immutable');
END;

CREATE TRIGGER agent_credentials_valid_update
BEFORE UPDATE ON agent_credentials
WHEN NOT (
    (
        new.status = old.status
        AND new.version = old.version
        AND new.activated_at IS old.activated_at
        AND new.identity_verified_at IS old.identity_verified_at
        AND new.pending_expires_at IS old.pending_expires_at
        AND new.retired_at IS old.retired_at
        AND new.revoked_at IS old.revoked_at
        AND new.expired_at IS old.expired_at
        AND (
            new.last_used_at IS old.last_used_at
            OR (
                new.last_used_at IS NOT NULL
                AND (old.last_used_at IS NULL OR new.last_used_at >= old.last_used_at)
            )
        )
    )
    OR (
        new.version = old.version + 1
        AND new.last_used_at IS old.last_used_at
        AND new.pending_expires_at IS old.pending_expires_at
        AND (
            (
                old.status = 'pending'
                AND new.status = 'active'
                AND new.activated_at IS NOT NULL
                AND new.identity_verified_at IS NOT NULL
                AND new.retired_at IS NULL
                AND new.revoked_at IS NULL
                AND new.expired_at IS NULL
            )
            OR (
                old.status = 'pending'
                AND new.status = 'revoked'
                AND new.activated_at IS NULL
                AND new.identity_verified_at IS NULL
                AND new.retired_at IS NULL
                AND new.revoked_at IS NOT NULL
                AND new.expired_at IS NULL
            )
            OR (
                old.status = 'pending'
                AND new.status = 'expired'
                AND new.activated_at IS NULL
                AND new.identity_verified_at IS NULL
                AND new.retired_at IS NULL
                AND new.revoked_at IS NULL
                AND new.expired_at IS NOT NULL
            )
            OR (
                old.status = 'active'
                AND new.status = 'retired'
                AND new.activated_at IS old.activated_at
                AND new.identity_verified_at IS old.identity_verified_at
                AND new.retired_at IS NOT NULL
                AND new.revoked_at IS NULL
                AND new.expired_at IS NULL
            )
            OR (
                old.status = 'active'
                AND new.status = 'revoked'
                AND new.activated_at IS old.activated_at
                AND new.identity_verified_at IS old.identity_verified_at
                AND new.retired_at IS NULL
                AND new.revoked_at IS NOT NULL
                AND new.expired_at IS NULL
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid credential lifecycle transition');
END;

CREATE TRIGGER agent_credentials_no_delete
BEFORE DELETE ON agent_credentials
BEGIN
    SELECT RAISE(ABORT, 'credentials cannot be deleted');
END;

CREATE TABLE agent_credential_requests (
    request_id           TEXT PRIMARY KEY
        CHECK (length(request_id) BETWEEN 1 AND 128),
    operation            TEXT NOT NULL
        CHECK (length(operation) BETWEEN 1 AND 64),
    input_sha256         TEXT NOT NULL
        CHECK (
            length(input_sha256) = 64
            AND input_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    agent_id             TEXT NOT NULL
        REFERENCES agents(id) ON DELETE RESTRICT,
    result_credential_id TEXT
        REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    created_at           TEXT NOT NULL
);

CREATE TRIGGER agent_credential_requests_no_update
BEFORE UPDATE ON agent_credential_requests
BEGIN
    SELECT RAISE(ABORT, 'credential requests are immutable');
END;

CREATE TRIGGER agent_credential_requests_no_delete
BEFORE DELETE ON agent_credential_requests
BEGIN
    SELECT RAISE(ABORT, 'credential requests are immutable');
END;

CREATE TABLE agent_credential_audit (
    seq                   INTEGER PRIMARY KEY AUTOINCREMENT,
    id                    TEXT NOT NULL UNIQUE
        CHECK (length(id) BETWEEN 1 AND 128),
    event_type            TEXT NOT NULL
        CHECK (
            event_type IN (
                'migrate', 'issue', 'rotate', 'prove',
                'retire', 'revoke', 'recover', 'expire',
                'agent-revoke'
            )
        ),
    agent_id              TEXT NOT NULL
        REFERENCES agents(id) ON DELETE RESTRICT,
    credential_id         TEXT NOT NULL
        REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    related_credential_id TEXT
        REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    actor_type            TEXT NOT NULL
        CHECK (actor_type IN ('system', 'local-admin', 'remote-admin', 'agent')),
    actor_id               TEXT NOT NULL
        CHECK (length(actor_id) BETWEEN 1 AND 256),
    method                 TEXT NOT NULL
        CHECK (length(method) BETWEEN 1 AND 64),
    reason                 TEXT NOT NULL
        CHECK (length(reason) BETWEEN 1 AND 256),
    request_id             TEXT NOT NULL
        CHECK (length(request_id) BETWEEN 1 AND 128),
    occurred_at            TEXT NOT NULL,
    details_json           TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(details_json))
);

CREATE INDEX idx_agent_credential_audit_agent_seq
    ON agent_credential_audit (agent_id, seq DESC);

CREATE UNIQUE INDEX idx_agent_credential_audit_request_event
    ON agent_credential_audit (request_id, event_type, credential_id);

CREATE TRIGGER agent_credential_audit_no_update
BEFORE UPDATE ON agent_credential_audit
BEGIN
    SELECT RAISE(ABORT, 'credential audit is append-only');
END;

CREATE TRIGGER agent_credential_audit_no_delete
BEFORE DELETE ON agent_credential_audit
BEGIN
    SELECT RAISE(ABORT, 'credential audit is append-only');
END;

INSERT INTO agent_credentials (
    id, agent_id, kind, secret_hash, status, predecessor_id,
    creation_method, creation_reason, issuance_request_id,
    created_at, activated_at, identity_verified_at, pending_expires_at,
    last_used_at, retired_at, revoked_at, expired_at, version
)
SELECT
    'legacy-agent:' || id,
    id,
    'legacy-sha256-v1',
    key_hash,
    CASE WHEN revoked_at IS NULL THEN 'active' ELSE 'revoked' END,
    NULL,
    'schema-9-migration',
    'preserve schema-8 credential',
    'schema9-migrate:' || id,
    created_at,
    CASE WHEN revoked_at IS NULL THEN created_at ELSE NULL END,
    CASE WHEN revoked_at IS NULL THEN created_at ELSE NULL END,
    NULL,
    last_seen_at,
    NULL,
    revoked_at,
    NULL,
    0
FROM agents;

INSERT INTO agent_credential_audit (
    id, event_type, agent_id, credential_id, related_credential_id,
    actor_type, actor_id, method, reason, request_id, occurred_at
)
SELECT
    'schema9-migrate:' || id,
    'migrate',
    id,
    'legacy-agent:' || id,
    NULL,
    'system',
    'system:schema-9-migration',
    'schema-9-migration',
    'preserve schema-8 credential',
    'schema9-migrate:' || id,
    created_at
FROM agents;

UPDATE agents SET credential_epoch = 1;

DROP TRIGGER roe_acknowledgements_no_update;
DROP TRIGGER roe_acknowledgements_no_delete;
DROP INDEX idx_roe_acknowledgements_agent_time;

ALTER TABLE roe_acknowledgements RENAME TO roe_acknowledgements_v8;

CREATE TABLE roe_acknowledgements (
    seq                        INTEGER PRIMARY KEY AUTOINCREMENT,
    id                         TEXT NOT NULL UNIQUE,
    agent_id                   TEXT NOT NULL
        REFERENCES agents(id) ON DELETE RESTRICT,
    credential_record_id       TEXT NOT NULL
        REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    global_revision_id         TEXT NOT NULL
        REFERENCES roe_revisions(id) ON DELETE RESTRICT,
    global_content_sha256      TEXT NOT NULL,
    agent_revision_id          TEXT
        REFERENCES roe_revisions(id) ON DELETE RESTRICT,
    agent_content_sha256       TEXT,
    effective_sha256           TEXT NOT NULL,
    acknowledged_at            TEXT NOT NULL,
    credential_kind            TEXT NOT NULL
        CHECK (length(credential_kind) BETWEEN 1 AND 64),
    credential_id              TEXT NOT NULL
        CHECK (length(credential_id) BETWEEN 1 AND 256),
    CHECK (
        length(credential_kind) + 1 + length(credential_id) <= 256
    ),
    CHECK (
        (agent_revision_id IS NULL AND agent_content_sha256 IS NULL)
        OR
        (agent_revision_id IS NOT NULL AND agent_content_sha256 IS NOT NULL)
    ),
    CHECK (
        length(global_content_sha256) = 64
        AND global_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(effective_sha256) = 64
        AND effective_sha256 NOT GLOB '*[^0-9a-f]*'
        AND (
            agent_content_sha256 IS NULL
            OR (
                length(agent_content_sha256) = 64
                AND agent_content_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        )
    ),
    UNIQUE (credential_record_id, effective_sha256)
);

INSERT INTO roe_acknowledgements (
    seq, id, agent_id, credential_record_id,
    global_revision_id, global_content_sha256,
    agent_revision_id, agent_content_sha256, effective_sha256,
    acknowledged_at, credential_kind, credential_id
)
SELECT
    seq, id, agent_id, 'legacy-agent:' || agent_id,
    global_revision_id, global_content_sha256,
    agent_revision_id, agent_content_sha256, effective_sha256,
    acknowledged_at, credential_kind, credential_id
FROM roe_acknowledgements_v8;

DROP TABLE roe_acknowledgements_v8;

CREATE INDEX idx_roe_acknowledgements_credential_time
    ON roe_acknowledgements (credential_record_id, seq DESC);

CREATE INDEX idx_roe_acknowledgements_agent_time
    ON roe_acknowledgements (agent_id, seq DESC);

CREATE TRIGGER roe_acknowledgements_no_update
BEFORE UPDATE ON roe_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'RoE acknowledgements are immutable');
END;

CREATE TRIGGER roe_acknowledgements_no_delete
BEFORE DELETE ON roe_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'RoE acknowledgements are immutable');
END;

DROP INDEX idx_agents_key_hash;
ALTER TABLE agents DROP COLUMN key_hash;

CREATE TRIGGER agents_immutable_identity
BEFORE UPDATE ON agents
WHEN new.id <> old.id OR new.name <> old.name
BEGIN
    SELECT RAISE(ABORT, 'agent identity is immutable');
END;
