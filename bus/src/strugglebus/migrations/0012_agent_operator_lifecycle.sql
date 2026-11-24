-- Forward-only containment state. Never downgrade in place or restore a
-- pre-containment/pre-cutoff backup through ordinary rollback. An exceptional
-- stopped, isolated restore must reconcile later lifecycle/freeze evidence.
ALTER TABLE agents ADD COLUMN blocked_at TEXT;

CREATE TRIGGER agents_valid_lifecycle
BEFORE UPDATE ON agents
WHEN new.credential_epoch NOT IN (old.credential_epoch, old.credential_epoch + 1)
  OR (old.revoked_at IS NOT NULL AND (
        new.revoked_at IS NOT old.revoked_at
        OR new.blocked_at IS NOT old.blocked_at
        OR new.credential_epoch <> old.credential_epoch))
  OR (new.revoked_at IS NOT NULL AND new.blocked_at IS NOT NULL)
  OR ((new.blocked_at IS NOT old.blocked_at OR new.revoked_at IS NOT old.revoked_at)
      AND new.credential_epoch <> old.credential_epoch + 1)
  OR (old.blocked_at IS NOT NULL AND new.blocked_at IS NOT NULL
      AND new.blocked_at <> old.blocked_at)
BEGIN
    SELECT RAISE(ABORT, 'invalid agent lifecycle transition');
END;

CREATE TRIGGER agents_no_delete
BEFORE DELETE ON agents
BEGIN
    SELECT RAISE(ABORT, 'stable agents cannot be deleted');
END;

CREATE TABLE agent_reconnect_grants (
    id TEXT PRIMARY KEY CHECK (length(id) = 26 AND substr(id, 1, 4) = 'rcg_'),
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    secret_hash TEXT NOT NULL CHECK (
        length(secret_hash) = 64 AND secret_hash NOT GLOB '*[^0-9a-f]*'),
    issuance_request_id TEXT NOT NULL UNIQUE CHECK (length(issuance_request_id) = 36),
    intent_sha256 TEXT NOT NULL CHECK (
        length(intent_sha256) = 64 AND intent_sha256 NOT GLOB '*[^0-9a-f]*'),
    bound_epoch INTEGER NOT NULL CHECK (bound_epoch >= 1),
    status TEXT NOT NULL CHECK (status IN ('pending', 'redeemed', 'revoked', 'expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at > created_at),
    actor_type TEXT NOT NULL CHECK (actor_type = 'remote-admin'),
    actor_id TEXT NOT NULL CHECK (
        length(actor_id) IN (47, 51) AND substr(actor_id, 1, 15) = 'operator:owner:'),
    reason TEXT NOT NULL CHECK (
        length(reason) BETWEEN 1 AND 256
        AND length(CAST(reason AS BLOB)) <= 1024 AND instr(reason, char(0)) = 0),
    redeemed_at TEXT,
    revoked_at TEXT,
    expired_at TEXT,
    redemption_request_id TEXT UNIQUE CHECK (
        redemption_request_id IS NULL OR length(redemption_request_id) = 36),
    result_credential_id TEXT UNIQUE REFERENCES agent_credentials(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL DEFAULT 0 CHECK (version IN (0, 1)),
    CHECK (
        (status = 'pending' AND version = 0
         AND redeemed_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL
         AND redemption_request_id IS NULL AND result_credential_id IS NULL)
        OR (status = 'redeemed' AND version = 1
            AND redeemed_at IS NOT NULL AND redeemed_at >= created_at AND redeemed_at < expires_at
            AND revoked_at IS NULL AND expired_at IS NULL
            AND redemption_request_id IS NOT NULL AND result_credential_id IS NOT NULL)
        OR (status = 'revoked' AND version = 1 AND revoked_at IS NOT NULL AND revoked_at >= created_at
            AND redeemed_at IS NULL AND expired_at IS NULL
            AND redemption_request_id IS NULL AND result_credential_id IS NULL)
        OR (status = 'expired' AND version = 1 AND expired_at IS NOT NULL AND expired_at >= expires_at
            AND redeemed_at IS NULL AND revoked_at IS NULL
            AND redemption_request_id IS NULL AND result_credential_id IS NULL)
    )
);

CREATE UNIQUE INDEX idx_agent_reconnect_pending_agent
    ON agent_reconnect_grants(agent_id) WHERE status = 'pending';
CREATE INDEX idx_agent_reconnect_status_expiry
    ON agent_reconnect_grants(status, expires_at);
CREATE INDEX idx_agent_reconnect_agent_history
    ON agent_reconnect_grants(agent_id, created_at, id);

CREATE TRIGGER agent_reconnect_valid_insert
BEFORE INSERT ON agent_reconnect_grants
WHEN new.status <> 'pending' OR NOT EXISTS (
    SELECT 1 FROM agents WHERE id = new.agent_id
      AND revoked_at IS NULL AND blocked_at IS NULL
      AND credential_epoch = new.bound_epoch)
BEGIN
    SELECT RAISE(ABORT, 'invalid reconnect binding');
END;

CREATE TRIGGER agent_reconnect_valid_update
BEFORE UPDATE ON agent_reconnect_grants
WHEN old.status <> 'pending' OR new.status = 'pending'
  OR new.version <> old.version + 1
  OR new.id IS NOT old.id OR new.agent_id IS NOT old.agent_id
  OR new.secret_hash IS NOT old.secret_hash
  OR new.issuance_request_id IS NOT old.issuance_request_id
  OR new.intent_sha256 IS NOT old.intent_sha256
  OR new.bound_epoch IS NOT old.bound_epoch
  OR new.created_at IS NOT old.created_at OR new.expires_at IS NOT old.expires_at
  OR new.actor_type IS NOT old.actor_type OR new.actor_id IS NOT old.actor_id
  OR new.reason IS NOT old.reason
  OR (new.status = 'redeemed' AND NOT EXISTS (
      SELECT 1 FROM agents AS a JOIN agent_credentials AS c ON c.agent_id = a.id
      WHERE a.id = new.agent_id AND a.revoked_at IS NULL AND a.blocked_at IS NULL
        AND a.credential_epoch = new.bound_epoch
        AND c.id = new.result_credential_id AND c.status = 'pending'
        AND c.issuance_request_id = new.redemption_request_id
        AND c.creation_method = 'reconnect'))
BEGIN
    SELECT RAISE(ABORT, 'invalid reconnect transition');
END;

CREATE TRIGGER agent_reconnect_no_delete
BEFORE DELETE ON agent_reconnect_grants
BEGIN
    SELECT RAISE(ABORT, 'reconnect grants cannot be deleted');
END;

-- All epoch-changing callers must consume/invalidate their grant first, even
-- protected local recovery. Redemption still checks its binding independently.
CREATE TRIGGER agents_reconnect_epoch_guard
BEFORE UPDATE OF credential_epoch ON agents
WHEN new.credential_epoch <> old.credential_epoch AND EXISTS (
    SELECT 1 FROM agent_reconnect_grants WHERE agent_id = old.id AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'pending reconnect grant must be invalidated');
END;

CREATE TABLE agent_lifecycle_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE CHECK (length(id) = 36),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    intent_sha256 TEXT NOT NULL CHECK (
        length(intent_sha256) = 64 AND intent_sha256 NOT GLOB '*[^0-9a-f]*'),
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (action IN (
        'block', 'unblock', 'retire', 'reconnect-issue', 'reconnect-redeem',
        'reconnect-invalidate', 'reconnect-expire')),
    previous_state TEXT NOT NULL CHECK (previous_state IN ('enabled', 'blocked', 'retired')),
    resulting_state TEXT NOT NULL CHECK (resulting_state IN ('enabled', 'blocked', 'retired')),
    previous_epoch INTEGER NOT NULL CHECK (previous_epoch >= 0),
    resulting_epoch INTEGER NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN (
        'local-admin', 'remote-admin', 'agent', 'system', 'reconnect-grant')),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    occurred_at TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (
        length(reason) BETWEEN 1 AND 256
        AND length(CAST(reason AS BLOB)) <= 1024 AND instr(reason, char(0)) = 0),
    grant_id TEXT REFERENCES agent_reconnect_grants(id) ON DELETE RESTRICT,
    CHECK (
        (action IN ('reconnect-invalidate', 'reconnect-expire')
         AND resulting_epoch = previous_epoch AND previous_state = resulting_state)
        OR (action NOT IN ('reconnect-invalidate', 'reconnect-expire')
            AND resulting_epoch = previous_epoch + 1)
    ),
    CHECK ((action IN ('block', 'unblock', 'retire') AND grant_id IS NULL)
           OR (action NOT IN ('block', 'unblock', 'retire') AND grant_id IS NOT NULL)),
    CHECK (
        (action = 'block' AND previous_state = 'enabled' AND resulting_state = 'blocked')
        OR (action = 'unblock' AND previous_state = 'blocked' AND resulting_state = 'enabled')
        OR (action = 'retire' AND previous_state IN ('enabled', 'blocked')
            AND resulting_state = 'retired')
        OR (action IN ('reconnect-issue', 'reconnect-redeem')
            AND previous_state = 'enabled' AND resulting_state = 'enabled')
        OR action IN ('reconnect-invalidate', 'reconnect-expire')
    ),
    CHECK (action IN ('reconnect-invalidate', 'reconnect-expire') OR length(request_id) = 36)
);

CREATE INDEX idx_agent_lifecycle_audit_agent_seq ON agent_lifecycle_audit(agent_id, seq);
CREATE UNIQUE INDEX idx_agent_lifecycle_audit_request_intent
    ON agent_lifecycle_audit(request_id)
    WHERE action IN ('block', 'unblock', 'retire', 'reconnect-issue', 'reconnect-redeem');
CREATE UNIQUE INDEX idx_agent_lifecycle_audit_grant_event
    ON agent_lifecycle_audit(grant_id, action) WHERE grant_id IS NOT NULL;

CREATE TRIGGER agent_lifecycle_audit_binding
BEFORE INSERT ON agent_lifecycle_audit
WHEN new.grant_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM agent_reconnect_grants WHERE id = new.grant_id AND agent_id = new.agent_id)
BEGIN
    SELECT RAISE(ABORT, 'invalid lifecycle grant binding');
END;

CREATE TRIGGER agent_lifecycle_audit_no_update
BEFORE UPDATE ON agent_lifecycle_audit
BEGIN
    SELECT RAISE(ABORT, 'agent lifecycle audit is append-only');
END;

CREATE TRIGGER agent_lifecycle_audit_no_delete
BEFORE DELETE ON agent_lifecycle_audit
BEGIN
    SELECT RAISE(ABORT, 'agent lifecycle audit is append-only');
END;
