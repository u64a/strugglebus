-- At most one agent may claim a `task` message. The primary key on
-- message_seq is what makes a claim atomic: the first insert wins and every
-- later claimant observes the existing row. A claim is coordination
-- bookkeeping only; it grants no authority and is not a progress signal.
--
-- Rollback: restore the pre-migration backup, or drop both triggers and
-- message_claims and set `PRAGMA user_version = 19`. That discards claim
-- history only; no message is changed.
CREATE TABLE message_claims (
    message_seq INTEGER PRIMARY KEY REFERENCES messages(seq) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    claimed_at  TEXT NOT NULL
);

CREATE TRIGGER message_claims_task_only
BEFORE INSERT ON message_claims
WHEN (SELECT kind FROM messages WHERE seq = new.message_seq) IS NOT 'task'
BEGIN
    SELECT RAISE(ABORT, 'only task messages can be claimed');
END;

CREATE TRIGGER message_claims_no_update
BEFORE UPDATE ON message_claims
BEGIN
    SELECT RAISE(ABORT, 'message claims are immutable; release and reclaim');
END;
