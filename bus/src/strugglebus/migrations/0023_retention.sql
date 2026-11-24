-- Retention: an operator setting for how long messages are kept and how long
-- an agent may stay silent before it is blocked. NULL means "keep forever" /
-- "never block".
--
-- A database that is empty when this migration runs is a new install and
-- starts with 60 days for both. A bus that already holds messages or agents
-- starts with both turned off, so an upgrade never deletes history or blocks
-- anyone until its operator chooses a period in the console.
--
-- Schema 16 kept keyed posts forever. They may now be deleted, but only by
-- age: the delete guard below still refuses any keyed message younger than
-- the configured period, and refuses all of them while retention is off, so
-- a retry of a recent post can never create a duplicate.
--
-- Rollback: restore the pre-migration backup. Messages removed by retention
-- exist only in backups taken before they were removed.
CREATE TABLE retention_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    message_days INTEGER CHECK (
        message_days IS NULL
        OR (typeof(message_days) = 'integer' AND message_days BETWEEN 7 AND 3650)),
    idle_agent_days INTEGER CHECK (
        idle_agent_days IS NULL
        OR (typeof(idle_agent_days) = 'integer' AND idle_agent_days BETWEEN 7 AND 3650)),
    changed_at TEXT NOT NULL,
    changed_by TEXT NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 256),
    last_run_at TEXT,
    last_removed_messages INTEGER NOT NULL DEFAULT 0 CHECK (last_removed_messages >= 0),
    last_blocked_agents INTEGER NOT NULL DEFAULT 0 CHECK (last_blocked_agents >= 0),
    total_removed_messages INTEGER NOT NULL DEFAULT 0 CHECK (total_removed_messages >= 0),
    total_blocked_agents INTEGER NOT NULL DEFAULT 0 CHECK (total_blocked_agents >= 0)
);

INSERT INTO retention_settings (
    singleton, message_days, idle_agent_days, changed_at, changed_by
)
SELECT
    1,
    CASE WHEN existing.present THEN NULL ELSE 60 END,
    CASE WHEN existing.present THEN NULL ELSE 60 END,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    CASE WHEN existing.present THEN 'system:upgrade' ELSE 'system:new-install' END
FROM (
    SELECT (
        EXISTS (SELECT 1 FROM messages)
        OR EXISTS (
            SELECT 1 FROM agents WHERE id NOT IN (
                '00000000-0000-4000-8000-000000000018',
                '00000000-0000-4000-8000-000000000019'))
    ) AS present
) AS existing;

CREATE TRIGGER retention_settings_no_delete
BEFORE DELETE ON retention_settings
BEGIN
    SELECT RAISE(ABORT, 'retention settings cannot be deleted');
END;

DROP TRIGGER messages_keyed_no_delete;

CREATE TRIGGER messages_keyed_no_delete
BEFORE DELETE ON messages
WHEN old.post_request_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM retention_settings
    WHERE singleton = 1 AND message_days IS NOT NULL
      AND old.created_at < strftime(
          '%Y-%m-%dT%H:%M:%fZ', 'now', '-' || message_days || ' days'))
BEGIN
    SELECT RAISE(ABORT, 'keyed message cannot be deleted');
END;

-- Removing an old message clears reply_to on its replies (ON DELETE SET NULL).
-- That is the one change a keyed message accepts, and only while retention
-- is on: reply_to going to NULL because the message it pointed at is gone.
DROP TRIGGER messages_keyed_immutable;

CREATE TRIGGER messages_keyed_immutable
BEFORE UPDATE ON messages
WHEN old.post_request_id IS NOT NULL AND NOT (
    old.reply_to IS NOT NULL AND new.reply_to IS NULL
    AND NOT EXISTS (SELECT 1 FROM messages WHERE seq = old.reply_to)
    AND EXISTS (
        SELECT 1 FROM retention_settings
        WHERE singleton = 1 AND message_days IS NOT NULL)
    AND new.seq IS old.seq AND new.id IS old.id
    AND new.channel_id IS old.channel_id AND new.agent_id IS old.agent_id
    AND new.body IS old.body AND new.kind IS old.kind AND new.meta IS old.meta
    AND new.created_at IS old.created_at
    AND new.post_request_id IS old.post_request_id)
BEGIN
    SELECT RAISE(ABORT, 'keyed message is immutable');
END;
