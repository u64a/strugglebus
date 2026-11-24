CREATE TABLE roe_revisions (
    id                    TEXT PRIMARY KEY,
    target_key            TEXT NOT NULL,
    scope                 TEXT NOT NULL CHECK (scope IN ('global', 'agent')),
    agent_id              TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    version               INTEGER NOT NULL CHECK (version >= 1),
    policy_schema_version INTEGER NOT NULL CHECK (policy_schema_version = 1),
    content_json          TEXT NOT NULL CHECK (json_valid(content_json)),
    content_sha256        TEXT NOT NULL
        CHECK (
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    author_label          TEXT NOT NULL
        CHECK (length(author_label) BETWEEN 1 AND 128),
    publisher_type        TEXT NOT NULL
        CHECK (publisher_type IN ('system', 'local-admin')),
    publisher_identity    TEXT NOT NULL
        CHECK (length(publisher_identity) BETWEEN 1 AND 256),
    created_at            TEXT NOT NULL,
    superseded_at         TEXT,
    CHECK (
        (
            scope = 'global'
            AND target_key = 'global'
            AND agent_id IS NULL
        )
        OR (
            scope = 'agent'
            AND agent_id IS NOT NULL
            AND target_key = 'agent:' || agent_id
        )
    ),
    UNIQUE (target_key, version)
);

CREATE INDEX idx_roe_revisions_target_version
    ON roe_revisions (target_key, version DESC);

CREATE TRIGGER roe_revisions_no_delete
BEFORE DELETE ON roe_revisions
BEGIN
    SELECT RAISE(ABORT, 'RoE revisions are immutable');
END;

CREATE TRIGGER roe_revisions_restrict_update
BEFORE UPDATE ON roe_revisions
WHEN NOT (
    old.superseded_at IS NULL
    AND new.superseded_at IS NOT NULL
    AND new.id = old.id
    AND new.target_key = old.target_key
    AND new.scope = old.scope
    AND new.agent_id IS old.agent_id
    AND new.version = old.version
    AND new.policy_schema_version = old.policy_schema_version
    AND new.content_json = old.content_json
    AND new.content_sha256 = old.content_sha256
    AND new.author_label = old.author_label
    AND new.publisher_type = old.publisher_type
    AND new.publisher_identity = old.publisher_identity
    AND new.created_at = old.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'RoE revisions are immutable');
END;

CREATE TABLE roe_current (
    target_key  TEXT PRIMARY KEY,
    scope       TEXT NOT NULL CHECK (scope IN ('global', 'agent')),
    agent_id    TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL UNIQUE
        REFERENCES roe_revisions(id) ON DELETE RESTRICT,
    updated_at  TEXT NOT NULL,
    CHECK (
        (
            scope = 'global'
            AND target_key = 'global'
            AND agent_id IS NULL
        )
        OR (
            scope = 'agent'
            AND agent_id IS NOT NULL
            AND target_key = 'agent:' || agent_id
        )
    )
);

CREATE TRIGGER roe_current_revision_matches_insert
BEFORE INSERT ON roe_current
WHEN NOT EXISTS (
    SELECT 1
    FROM roe_revisions AS revision
    WHERE revision.id = new.revision_id
      AND revision.target_key = new.target_key
      AND revision.scope = new.scope
      AND revision.agent_id IS new.agent_id
)
BEGIN
    SELECT RAISE(ABORT, 'current RoE revision does not match target');
END;

CREATE TRIGGER roe_current_revision_matches_update
BEFORE UPDATE ON roe_current
WHEN NOT EXISTS (
    SELECT 1
    FROM roe_revisions AS revision
    WHERE revision.id = new.revision_id
      AND revision.target_key = new.target_key
      AND revision.scope = new.scope
      AND revision.agent_id IS new.agent_id
)
BEGIN
    SELECT RAISE(ABORT, 'current RoE revision does not match target');
END;

CREATE TABLE roe_acknowledgements (
    seq                        INTEGER PRIMARY KEY AUTOINCREMENT,
    id                         TEXT NOT NULL UNIQUE,
    agent_id                   TEXT NOT NULL
        REFERENCES agents(id) ON DELETE RESTRICT,
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
    UNIQUE (agent_id, effective_sha256, credential_kind, credential_id)
);

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

CREATE TABLE roe_audit (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    id                 TEXT NOT NULL UNIQUE,
    event_type         TEXT NOT NULL
        CHECK (event_type IN ('publish', 'supersede', 'acknowledge')),
    target_key         TEXT NOT NULL,
    agent_id           TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    revision_id        TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT,
    global_revision_id TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT,
    agent_revision_id  TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT,
    effective_sha256   TEXT,
    actor_type         TEXT NOT NULL
        CHECK (actor_type IN ('system', 'local-admin', 'agent')),
    actor_id            TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    occurred_at         TEXT NOT NULL,
    details_json        TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(details_json))
);

CREATE INDEX idx_roe_audit_target_seq ON roe_audit (target_key, seq DESC);

CREATE TRIGGER roe_audit_no_update
BEFORE UPDATE ON roe_audit
BEGIN
    SELECT RAISE(ABORT, 'RoE audit is append-only');
END;

CREATE TRIGGER roe_audit_no_delete
BEFORE DELETE ON roe_audit
BEGIN
    SELECT RAISE(ABORT, 'RoE audit is append-only');
END;
