ALTER TABLE cursors RENAME TO cursors_v3;

CREATE TABLE cursors (
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    channel_id    TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    include_stale INTEGER NOT NULL DEFAULT 0 CHECK (include_stale IN (0, 1)),
    last_seq      INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (agent_id, channel_id, include_stale)
);

INSERT INTO cursors (
    agent_id, channel_id, include_stale, last_seq, updated_at
)
SELECT agent_id, channel_id, 0, last_seq, updated_at
FROM cursors_v3;

DROP TABLE cursors_v3;

CREATE INDEX idx_cursors_agent_last_seq
    ON cursors (agent_id, include_stale, last_seq);

CREATE TABLE mention_cursors (
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    include_stale INTEGER NOT NULL DEFAULT 0 CHECK (include_stale IN (0, 1)),
    last_seq      INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (agent_id, include_stale)
);
