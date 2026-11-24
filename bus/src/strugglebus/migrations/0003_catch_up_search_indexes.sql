CREATE INDEX idx_messages_kind_created_seq
    ON messages (kind, created_at, seq);

CREATE INDEX idx_cursors_agent_last_seq
    ON cursors (agent_id, last_seq);
