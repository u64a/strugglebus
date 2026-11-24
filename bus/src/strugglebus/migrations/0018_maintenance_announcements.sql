-- A local system author may publish fixed maintenance-window notices without
-- receiving an agent credential or participating in agent lifecycle.
INSERT INTO agents (
    id, name, description, host, created_at, last_seen_at,
    revoked_at, credential_epoch, blocked_at
)
VALUES (
    '00000000-0000-4000-8000-000000000018',
    'system:strugglebus-maintenance',
    'Local system maintenance announcements; no coordination credential',
    'local-system',
    '1970-01-01T00:00:00Z',
    NULL,
    NULL,
    0,
    NULL
);

CREATE TRIGGER maintenance_system_agent_no_update
BEFORE UPDATE ON agents
WHEN old.id = '00000000-0000-4000-8000-000000000018'
BEGIN
    SELECT RAISE(ABORT, 'maintenance system author is immutable');
END;

CREATE TRIGGER maintenance_system_agent_no_credential
BEFORE INSERT ON agent_credentials
WHEN new.agent_id = '00000000-0000-4000-8000-000000000018'
BEGIN
    SELECT RAISE(ABORT, 'maintenance system author cannot receive credentials');
END;

CREATE TRIGGER maintenance_system_agent_no_reconnect
BEFORE INSERT ON agent_reconnect_grants
WHEN new.agent_id = '00000000-0000-4000-8000-000000000018'
BEGIN
    SELECT RAISE(ABORT, 'maintenance system author cannot reconnect');
END;
