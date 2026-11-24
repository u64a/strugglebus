ALTER TABLE messages ADD COLUMN post_request_id TEXT
    CHECK (
        post_request_id IS NULL OR (
            length(post_request_id) = 36
            AND length(CAST(post_request_id AS BLOB)) = 36
            AND substr(post_request_id, 9, 1) = '-'
            AND substr(post_request_id, 14, 1) = '-'
            AND substr(post_request_id, 19, 1) = '-'
            AND substr(post_request_id, 24, 1) = '-'
            AND length(replace(post_request_id, '-', '')) = 32
            AND replace(post_request_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    );

CREATE UNIQUE INDEX idx_messages_post_request
    ON messages (agent_id, post_request_id)
    WHERE post_request_id IS NOT NULL;

CREATE TRIGGER messages_post_request_immutable
BEFORE UPDATE OF post_request_id ON messages
WHEN new.post_request_id IS NOT old.post_request_id
BEGIN
    SELECT RAISE(ABORT, 'post retry binding is immutable');
END;

CREATE TRIGGER messages_keyed_immutable
BEFORE UPDATE ON messages
WHEN old.post_request_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'keyed message is immutable');
END;

CREATE TRIGGER messages_keyed_no_delete
BEFORE DELETE ON messages
WHEN old.post_request_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'keyed message cannot be deleted');
END;
