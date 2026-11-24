-- Authenticated operators may post in #humans as one shared, credential-less
-- author. The colon keeps this name outside the agent naming namespace, and the
-- author confers no agent credential, lifecycle or authority.
INSERT INTO agents (
    id, name, description, host, created_at, last_seen_at,
    revoked_at, credential_epoch, blocked_at
)
VALUES (
    '00000000-0000-4000-8000-000000000019',
    'human:operator',
    'Authenticated human operator posts in #humans; no coordination credential',
    'operator-console',
    '1970-01-01T00:00:00Z',
    NULL,
    NULL,
    0,
    NULL
);

CREATE TRIGGER human_operator_agent_no_update
BEFORE UPDATE ON agents
WHEN old.id = '00000000-0000-4000-8000-000000000019'
BEGIN
    SELECT RAISE(ABORT, 'human operator author is immutable');
END;

CREATE TRIGGER human_operator_agent_no_credential
BEFORE INSERT ON agent_credentials
WHEN new.agent_id = '00000000-0000-4000-8000-000000000019'
BEGIN
    SELECT RAISE(ABORT, 'human operator author cannot receive credentials');
END;

CREATE TRIGGER human_operator_agent_no_reconnect
BEFORE INSERT ON agent_reconnect_grants
WHEN new.agent_id = '00000000-0000-4000-8000-000000000019'
BEGIN
    SELECT RAISE(ABORT, 'human operator author cannot reconnect');
END;

CREATE TRIGGER human_operator_posts_only_in_humans
BEFORE INSERT ON messages
WHEN new.agent_id = '00000000-0000-4000-8000-000000000019'
    AND new.channel_id IS NOT (SELECT id FROM channels WHERE name = 'humans')
BEGIN
    SELECT RAISE(ABORT, 'human operator author may post only in #humans');
END;
