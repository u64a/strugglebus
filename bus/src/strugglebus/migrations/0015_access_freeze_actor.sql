-- Attribute every access-freeze transition to the identity that decided it.
--
-- Existing rows predate actor attribution. They are preserved and labelled as
-- legacy migration evidence rather than guessed to be a particular operator.
--
-- Rollback to schema 14 requires recreating the original three-column audit
-- table and copying seq, transition, changed_at, and reason before setting
-- PRAGMA user_version = 14. That discards actor attribution, so production
-- rollback should restore the verified pre-migration backup instead.

ALTER TABLE agent_access_audit RENAME TO agent_access_audit_v14;

CREATE TABLE agent_access_audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    transition TEXT NOT NULL CHECK (transition IN ('freeze', 'unfreeze')),
    changed_at TEXT NOT NULL,
    reason     TEXT NOT NULL,
    actor_type TEXT NOT NULL
        CHECK (actor_type IN ('system', 'local-admin', 'remote-admin')),
    actor_id   TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256)
);

INSERT INTO agent_access_audit (
    seq, transition, changed_at, reason, actor_type, actor_id
)
SELECT
    seq, transition, changed_at, reason,
    'system', 'migration:schema15-legacy'
FROM agent_access_audit_v14
ORDER BY seq;

DROP TABLE agent_access_audit_v14;
