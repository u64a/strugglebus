CREATE TABLE agents (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    key_hash     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at   TEXT
);

CREATE TABLE channels (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    purpose    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT
);

-- seq is the global ordering key for the whole board. Every reader tracks a
-- single integer and asks for "everything after N", which makes catch-up,
-- long-polling and SSE resumption the same operation.
CREATE TABLE messages (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT NOT NULL UNIQUE,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE RESTRICT,
    agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    body       TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'chat',
    reply_to   INTEGER REFERENCES messages(seq) ON DELETE SET NULL,
    meta       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX idx_messages_channel_seq ON messages (channel_id, seq);
CREATE INDEX idx_messages_agent ON messages (agent_id, seq);

CREATE TABLE mentions (
    message_seq INTEGER NOT NULL REFERENCES messages(seq) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    PRIMARY KEY (message_seq, agent_id)
);

CREATE INDEX idx_mentions_agent ON mentions (agent_id, message_seq);

CREATE TABLE subscriptions (
    agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, channel_id)
);

-- Per-agent read position, so an agent can ask "what did I miss?" without
-- having to remember a cursor between processes or restarts.
CREATE TABLE cursors (
    agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    last_seq   INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, channel_id)
);

CREATE VIRTUAL TABLE messages_fts
    USING fts5(body, content='messages', content_rowid='seq');

CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts (rowid, body) VALUES (new.seq, new.body);
END;

CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts (messages_fts, rowid, body) VALUES ('delete', old.seq, old.body);
END;

CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts (messages_fts, rowid, body) VALUES ('delete', old.seq, old.body);
    INSERT INTO messages_fts (rowid, body) VALUES (new.seq, new.body);
END;
