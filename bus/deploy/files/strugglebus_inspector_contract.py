#!/usr/bin/python3
"""Verify bounded freeze decisions for legacy and reviewed schemas through 12."""

from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile


# Offline fixture snapshot of sqlite_schema after packaged migrations 0001-0010.
# Kept in this installed, checksummed helper so verification never imports or
# executes candidate release code or trusts candidate-supplied schema metadata.
# Tests compare it with the real packaged migrations, not just user_version.
# FTS shadow tables are created by SQLite; migration data is not needed here.
_SCHEMA_10_SQL = """
CREATE TABLE agent_access_audit ( seq INTEGER PRIMARY KEY AUTOINCREMENT, transition TEXT NOT NULL CHECK (transition IN ('freeze', 'unfreeze')), changed_at TEXT NOT NULL, reason TEXT NOT NULL );
CREATE TABLE agent_access_state ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)), transition TEXT NOT NULL CHECK (transition IN ('initialized', 'freeze', 'unfreeze')), changed_at TEXT, reason TEXT, CHECK ( ( transition = 'initialized' AND frozen = 0 AND changed_at IS NULL AND reason IS NULL ) OR ( transition = 'freeze' AND frozen = 1 AND changed_at IS NOT NULL AND reason IS NOT NULL ) OR ( transition = 'unfreeze' AND frozen = 0 AND changed_at IS NOT NULL AND reason IS NOT NULL ) ) );
CREATE TABLE agent_credential_audit ( seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 128), event_type TEXT NOT NULL CHECK ( event_type IN ( 'migrate', 'issue', 'rotate', 'prove', 'retire', 'revoke', 'recover', 'expire', 'agent-revoke' ) ), agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT, credential_id TEXT NOT NULL REFERENCES agent_credentials(id) ON DELETE RESTRICT, related_credential_id TEXT REFERENCES agent_credentials(id) ON DELETE RESTRICT, actor_type TEXT NOT NULL CHECK (actor_type IN ('system', 'local-admin', 'remote-admin', 'agent')), actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256), method TEXT NOT NULL CHECK (length(method) BETWEEN 1 AND 64), reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256), request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128), occurred_at TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)) );
CREATE TABLE agent_credential_requests ( request_id TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 128), operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 64), input_sha256 TEXT NOT NULL CHECK ( length(input_sha256) = 64 AND input_sha256 NOT GLOB '*[^0-9a-f]*' ), agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT, result_credential_id TEXT REFERENCES agent_credentials(id) ON DELETE RESTRICT, created_at TEXT NOT NULL );
CREATE TABLE agent_credentials ( id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 256), agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT, kind TEXT NOT NULL CHECK (kind IN ('legacy-sha256-v1', 'sb1')), secret_hash TEXT NOT NULL CHECK ( length(secret_hash) = 64 AND secret_hash NOT GLOB '*[^0-9a-f]*' ), status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'retired', 'revoked', 'expired')), predecessor_id TEXT REFERENCES agent_credentials(id) ON DELETE RESTRICT, creation_method TEXT NOT NULL CHECK (length(creation_method) BETWEEN 1 AND 64), creation_reason TEXT NOT NULL CHECK (length(creation_reason) BETWEEN 1 AND 256), issuance_request_id TEXT NOT NULL UNIQUE CHECK (length(issuance_request_id) BETWEEN 1 AND 128), created_at TEXT NOT NULL, activated_at TEXT, identity_verified_at TEXT, pending_expires_at TEXT, last_used_at TEXT, retired_at TEXT, revoked_at TEXT, expired_at TEXT, version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0), CHECK (predecessor_id IS NULL OR predecessor_id <> id), CHECK ( ( status = 'pending' AND pending_expires_at IS NOT NULL AND activated_at IS NULL AND identity_verified_at IS NULL AND retired_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL ) OR ( status = 'active' AND activated_at IS NOT NULL AND identity_verified_at IS NOT NULL AND retired_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL ) OR ( status = 'retired' AND activated_at IS NOT NULL AND identity_verified_at IS NOT NULL AND retired_at IS NOT NULL AND revoked_at IS NULL AND expired_at IS NULL ) OR ( status = 'revoked' AND retired_at IS NULL AND revoked_at IS NOT NULL AND expired_at IS NULL ) OR ( status = 'expired' AND activated_at IS NULL AND identity_verified_at IS NULL AND retired_at IS NULL AND revoked_at IS NULL AND expired_at IS NOT NULL ) ) );
CREATE TABLE agent_enrollment_redemptions ( seq INTEGER PRIMARY KEY AUTOINCREMENT, enrollment_id TEXT NOT NULL REFERENCES agent_enrollments(id) ON DELETE RESTRICT, agent_id TEXT NOT NULL UNIQUE REFERENCES agents(id) ON DELETE RESTRICT, credential_id TEXT NOT NULL REFERENCES agent_credentials(id) ON DELETE RESTRICT, claimed_name TEXT NOT NULL CHECK (length(claimed_name) BETWEEN 1 AND 128), request_id TEXT NOT NULL UNIQUE CHECK (length(request_id) BETWEEN 1 AND 128), redeemed_at TEXT NOT NULL );
CREATE TABLE agent_enrollments ( id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 256), secret_hash TEXT NOT NULL UNIQUE CHECK ( length(secret_hash) = 64 AND secret_hash NOT GLOB '*[^0-9a-f]*' ), name_prefix TEXT NOT NULL CHECK ( length(name_prefix) BETWEEN 1 AND 128 AND name_prefix NOT GLOB '*[^0-9a-z-]*' ), description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 1024), status TEXT NOT NULL CHECK (status IN ('pending', 'exhausted', 'revoked')), uses_allowed INTEGER NOT NULL CHECK (uses_allowed BETWEEN 1 AND 64), uses_remaining INTEGER NOT NULL CHECK (uses_remaining >= 0), created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_redeemed_at TEXT, exhausted_at TEXT, revoked_at TEXT, revocation_reason TEXT CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256), actor_type TEXT NOT NULL CHECK (actor_type IN ('system', 'local-admin', 'remote-admin')), actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256), creation_reason TEXT NOT NULL CHECK (length(creation_reason) BETWEEN 1 AND 256), version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0), CHECK (uses_remaining <= uses_allowed), CHECK (created_at < expires_at), CHECK ( ( status = 'pending' AND uses_remaining > 0 AND exhausted_at IS NULL AND revoked_at IS NULL AND revocation_reason IS NULL ) OR ( status = 'exhausted' AND uses_remaining = 0 AND exhausted_at IS NOT NULL AND revoked_at IS NULL AND revocation_reason IS NULL ) OR ( status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL AND exhausted_at IS NULL ) ) );
CREATE TABLE agents ( id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT , credential_epoch INTEGER NOT NULL DEFAULT 0 CHECK (credential_epoch >= 0));
CREATE TABLE channels ( id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, purpose TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, created_by TEXT );
CREATE TABLE cursors ( agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, include_stale INTEGER NOT NULL DEFAULT 0 CHECK (include_stale IN (0, 1)), last_seq INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY (agent_id, channel_id, include_stale) );
CREATE TABLE mention_cursors ( agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, include_stale INTEGER NOT NULL DEFAULT 0 CHECK (include_stale IN (0, 1)), last_seq INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY (agent_id, include_stale) );
CREATE TABLE mentions ( message_seq INTEGER NOT NULL REFERENCES messages(seq) ON DELETE CASCADE, agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, PRIMARY KEY (message_seq, agent_id) );
CREATE TABLE messages ( seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE RESTRICT, agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT, body TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'chat', reply_to INTEGER REFERENCES messages(seq) ON DELETE SET NULL, meta TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL );
CREATE VIRTUAL TABLE messages_fts USING fts5(body, content='messages', content_rowid='seq');
CREATE TABLE roe_acknowledgements ( seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT, credential_record_id TEXT NOT NULL REFERENCES agent_credentials(id) ON DELETE RESTRICT, global_revision_id TEXT NOT NULL REFERENCES roe_revisions(id) ON DELETE RESTRICT, global_content_sha256 TEXT NOT NULL, agent_revision_id TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT, agent_content_sha256 TEXT, effective_sha256 TEXT NOT NULL, acknowledged_at TEXT NOT NULL, credential_kind TEXT NOT NULL CHECK (length(credential_kind) BETWEEN 1 AND 64), credential_id TEXT NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 256), CHECK ( length(credential_kind) + 1 + length(credential_id) <= 256 ), CHECK ( (agent_revision_id IS NULL AND agent_content_sha256 IS NULL) OR (agent_revision_id IS NOT NULL AND agent_content_sha256 IS NOT NULL) ), CHECK ( length(global_content_sha256) = 64 AND global_content_sha256 NOT GLOB '*[^0-9a-f]*' AND length(effective_sha256) = 64 AND effective_sha256 NOT GLOB '*[^0-9a-f]*' AND ( agent_content_sha256 IS NULL OR ( length(agent_content_sha256) = 64 AND agent_content_sha256 NOT GLOB '*[^0-9a-f]*' ) ) ), UNIQUE (credential_record_id, effective_sha256) );
CREATE TABLE roe_audit ( seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, event_type TEXT NOT NULL CHECK (event_type IN ('publish', 'supersede', 'acknowledge')), target_key TEXT NOT NULL, agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT, revision_id TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT, global_revision_id TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT, agent_revision_id TEXT REFERENCES roe_revisions(id) ON DELETE RESTRICT, effective_sha256 TEXT, actor_type TEXT NOT NULL CHECK (actor_type IN ('system', 'local-admin', 'agent')), actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256), occurred_at TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)) );
CREATE TABLE roe_current ( target_key TEXT PRIMARY KEY, scope TEXT NOT NULL CHECK (scope IN ('global', 'agent')), agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT, revision_id TEXT NOT NULL UNIQUE REFERENCES roe_revisions(id) ON DELETE RESTRICT, updated_at TEXT NOT NULL, CHECK ( ( scope = 'global' AND target_key = 'global' AND agent_id IS NULL ) OR ( scope = 'agent' AND agent_id IS NOT NULL AND target_key = 'agent:' || agent_id ) ) );
CREATE TABLE roe_revisions ( id TEXT PRIMARY KEY, target_key TEXT NOT NULL, scope TEXT NOT NULL CHECK (scope IN ('global', 'agent')), agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT, version INTEGER NOT NULL CHECK (version >= 1), policy_schema_version INTEGER NOT NULL CHECK (policy_schema_version = 1), content_json TEXT NOT NULL CHECK (json_valid(content_json)), content_sha256 TEXT NOT NULL CHECK ( length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*' ), author_label TEXT NOT NULL CHECK (length(author_label) BETWEEN 1 AND 128), publisher_type TEXT NOT NULL CHECK (publisher_type IN ('system', 'local-admin')), publisher_identity TEXT NOT NULL CHECK (length(publisher_identity) BETWEEN 1 AND 256), created_at TEXT NOT NULL, superseded_at TEXT, CHECK ( ( scope = 'global' AND target_key = 'global' AND agent_id IS NULL ) OR ( scope = 'agent' AND agent_id IS NOT NULL AND target_key = 'agent:' || agent_id ) ), UNIQUE (target_key, version) );
CREATE TABLE subscriptions ( agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, created_at TEXT NOT NULL, PRIMARY KEY (agent_id, channel_id) );
CREATE INDEX idx_agent_credential_audit_agent_seq ON agent_credential_audit (agent_id, seq DESC);
CREATE UNIQUE INDEX idx_agent_credential_audit_request_event ON agent_credential_audit (request_id, event_type, credential_id);
CREATE INDEX idx_agent_credentials_agent_status ON agent_credentials (agent_id, status, created_at);
CREATE UNIQUE INDEX idx_agent_credentials_legacy_hash ON agent_credentials (kind, secret_hash) WHERE kind = 'legacy-sha256-v1';
CREATE INDEX idx_agent_credentials_predecessor ON agent_credentials (predecessor_id);
CREATE INDEX idx_agent_enrollment_redemptions_enrollment ON agent_enrollment_redemptions (enrollment_id, seq DESC);
CREATE INDEX idx_agent_enrollments_status_expiry ON agent_enrollments (status, expires_at);
CREATE INDEX idx_cursors_agent_last_seq ON cursors (agent_id, include_stale, last_seq);
CREATE INDEX idx_mentions_agent ON mentions (agent_id, message_seq);
CREATE INDEX idx_messages_agent ON messages (agent_id, seq);
CREATE INDEX idx_messages_channel_agent_seq ON messages (channel_id, agent_id, seq);
CREATE INDEX idx_messages_channel_seq ON messages (channel_id, seq);
CREATE INDEX idx_messages_kind_created_seq ON messages (kind, created_at, seq);
CREATE INDEX idx_messages_reply_to_seq ON messages (reply_to, seq);
CREATE INDEX idx_roe_acknowledgements_agent_time ON roe_acknowledgements (agent_id, seq DESC);
CREATE INDEX idx_roe_acknowledgements_credential_time ON roe_acknowledgements (credential_record_id, seq DESC);
CREATE INDEX idx_roe_audit_target_seq ON roe_audit (target_key, seq DESC);
CREATE INDEX idx_roe_revisions_target_version ON roe_revisions (target_key, version DESC);
CREATE TRIGGER agent_credential_audit_no_delete BEFORE DELETE ON agent_credential_audit BEGIN SELECT RAISE(ABORT, 'credential audit is append-only'); END;
CREATE TRIGGER agent_credential_audit_no_update BEFORE UPDATE ON agent_credential_audit BEGIN SELECT RAISE(ABORT, 'credential audit is append-only'); END;
CREATE TRIGGER agent_credential_requests_no_delete BEFORE DELETE ON agent_credential_requests BEGIN SELECT RAISE(ABORT, 'credential requests are immutable'); END;
CREATE TRIGGER agent_credential_requests_no_update BEFORE UPDATE ON agent_credential_requests BEGIN SELECT RAISE(ABORT, 'credential requests are immutable'); END;
CREATE TRIGGER agent_credentials_immutable_identity BEFORE UPDATE ON agent_credentials WHEN new.id <> old.id OR new.agent_id <> old.agent_id OR new.kind <> old.kind OR new.secret_hash <> old.secret_hash OR new.predecessor_id IS NOT old.predecessor_id OR new.creation_method <> old.creation_method OR new.creation_reason <> old.creation_reason OR new.issuance_request_id <> old.issuance_request_id OR new.created_at <> old.created_at BEGIN SELECT RAISE(ABORT, 'credential identity and verifier are immutable'); END;
CREATE TRIGGER agent_credentials_no_delete BEFORE DELETE ON agent_credentials BEGIN SELECT RAISE(ABORT, 'credentials cannot be deleted'); END;
CREATE TRIGGER agent_credentials_valid_update BEFORE UPDATE ON agent_credentials WHEN NOT ( ( new.status = old.status AND new.version = old.version AND new.activated_at IS old.activated_at AND new.identity_verified_at IS old.identity_verified_at AND new.pending_expires_at IS old.pending_expires_at AND new.retired_at IS old.retired_at AND new.revoked_at IS old.revoked_at AND new.expired_at IS old.expired_at AND ( new.last_used_at IS old.last_used_at OR ( new.last_used_at IS NOT NULL AND (old.last_used_at IS NULL OR new.last_used_at >= old.last_used_at) ) ) ) OR ( new.version = old.version + 1 AND new.last_used_at IS old.last_used_at AND new.pending_expires_at IS old.pending_expires_at AND ( ( old.status = 'pending' AND new.status = 'active' AND new.activated_at IS NOT NULL AND new.identity_verified_at IS NOT NULL AND new.retired_at IS NULL AND new.revoked_at IS NULL AND new.expired_at IS NULL ) OR ( old.status = 'pending' AND new.status = 'revoked' AND new.activated_at IS NULL AND new.identity_verified_at IS NULL AND new.retired_at IS NULL AND new.revoked_at IS NOT NULL AND new.expired_at IS NULL ) OR ( old.status = 'pending' AND new.status = 'expired' AND new.activated_at IS NULL AND new.identity_verified_at IS NULL AND new.retired_at IS NULL AND new.revoked_at IS NULL AND new.expired_at IS NOT NULL ) OR ( old.status = 'active' AND new.status = 'retired' AND new.activated_at IS old.activated_at AND new.identity_verified_at IS old.identity_verified_at AND new.retired_at IS NOT NULL AND new.revoked_at IS NULL AND new.expired_at IS NULL ) OR ( old.status = 'active' AND new.status = 'revoked' AND new.activated_at IS old.activated_at AND new.identity_verified_at IS old.identity_verified_at AND new.retired_at IS NULL AND new.revoked_at IS NOT NULL AND new.expired_at IS NULL ) ) ) ) BEGIN SELECT RAISE(ABORT, 'invalid credential lifecycle transition'); END;
CREATE TRIGGER agent_enrollment_redemptions_no_delete BEFORE DELETE ON agent_enrollment_redemptions BEGIN SELECT RAISE(ABORT, 'enrollment redemptions are immutable'); END;
CREATE TRIGGER agent_enrollment_redemptions_no_update BEFORE UPDATE ON agent_enrollment_redemptions BEGIN SELECT RAISE(ABORT, 'enrollment redemptions are immutable'); END;
CREATE TRIGGER agent_enrollments_immutable_identity BEFORE UPDATE ON agent_enrollments WHEN new.id <> old.id OR new.secret_hash <> old.secret_hash OR new.name_prefix <> old.name_prefix OR new.description <> old.description OR new.uses_allowed <> old.uses_allowed OR new.created_at <> old.created_at OR new.expires_at <> old.expires_at OR new.actor_type <> old.actor_type OR new.actor_id <> old.actor_id OR new.creation_reason <> old.creation_reason BEGIN SELECT RAISE(ABORT, 'enrollment identity and allowance are immutable'); END;
CREATE TRIGGER agent_enrollments_monotonic_consumption BEFORE UPDATE ON agent_enrollments WHEN new.uses_remaining > old.uses_remaining OR new.version <> old.version + 1 OR old.status <> 'pending' BEGIN SELECT RAISE(ABORT, 'enrollment allowance cannot increase or be reused'); END;
CREATE TRIGGER agent_enrollments_no_delete BEFORE DELETE ON agent_enrollments BEGIN SELECT RAISE(ABORT, 'enrollments cannot be deleted'); END;
CREATE TRIGGER agents_immutable_identity BEFORE UPDATE ON agents WHEN new.id <> old.id OR new.name <> old.name BEGIN SELECT RAISE(ABORT, 'agent identity is immutable'); END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN INSERT INTO messages_fts (messages_fts, rowid, body) VALUES ('delete', old.seq, old.body); END;
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN INSERT INTO messages_fts (rowid, body) VALUES (new.seq, new.body); END;
CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN INSERT INTO messages_fts (messages_fts, rowid, body) VALUES ('delete', old.seq, old.body); INSERT INTO messages_fts (rowid, body) VALUES (new.seq, new.body); END;
CREATE TRIGGER roe_acknowledgements_no_delete BEFORE DELETE ON roe_acknowledgements BEGIN SELECT RAISE(ABORT, 'RoE acknowledgements are immutable'); END;
CREATE TRIGGER roe_acknowledgements_no_update BEFORE UPDATE ON roe_acknowledgements BEGIN SELECT RAISE(ABORT, 'RoE acknowledgements are immutable'); END;
CREATE TRIGGER roe_audit_no_delete BEFORE DELETE ON roe_audit BEGIN SELECT RAISE(ABORT, 'RoE audit is append-only'); END;
CREATE TRIGGER roe_audit_no_update BEFORE UPDATE ON roe_audit BEGIN SELECT RAISE(ABORT, 'RoE audit is append-only'); END;
CREATE TRIGGER roe_current_revision_matches_insert BEFORE INSERT ON roe_current WHEN NOT EXISTS ( SELECT 1 FROM roe_revisions AS revision WHERE revision.id = new.revision_id AND revision.target_key = new.target_key AND revision.scope = new.scope AND revision.agent_id IS new.agent_id ) BEGIN SELECT RAISE(ABORT, 'current RoE revision does not match target'); END;
CREATE TRIGGER roe_current_revision_matches_update BEFORE UPDATE ON roe_current WHEN NOT EXISTS ( SELECT 1 FROM roe_revisions AS revision WHERE revision.id = new.revision_id AND revision.target_key = new.target_key AND revision.scope = new.scope AND revision.agent_id IS new.agent_id ) BEGIN SELECT RAISE(ABORT, 'current RoE revision does not match target'); END;
CREATE TRIGGER roe_revisions_no_delete BEFORE DELETE ON roe_revisions BEGIN SELECT RAISE(ABORT, 'RoE revisions are immutable'); END;
CREATE TRIGGER roe_revisions_restrict_update BEFORE UPDATE ON roe_revisions WHEN NOT ( old.superseded_at IS NULL AND new.superseded_at IS NOT NULL AND new.id = old.id AND new.target_key = old.target_key AND new.scope = old.scope AND new.agent_id IS old.agent_id AND new.version = old.version AND new.policy_schema_version = old.policy_schema_version AND new.content_json = old.content_json AND new.content_sha256 = old.content_sha256 AND new.author_label = old.author_label AND new.publisher_type = old.publisher_type AND new.publisher_identity = old.publisher_identity AND new.created_at = old.created_at ) BEGIN SELECT RAISE(ABORT, 'RoE revisions are immutable'); END;
"""

# Test-only duplication of B's 0011_enrollment_name_match.sql, reviewed from
# the Enrollment package reliability worktree on 2026-09-05.
_SCHEMA_11_SQL = """
-- Historical allowances remain prefix-bound, including old dashboard tokens.
ALTER TABLE agent_enrollments
ADD COLUMN name_match TEXT NOT NULL DEFAULT 'prefix'
    CHECK (name_match IN ('prefix', 'exact'));

CREATE TRIGGER agent_enrollments_immutable_name_match
BEFORE UPDATE ON agent_enrollments
WHEN new.name_match <> old.name_match
BEGIN
    SELECT RAISE(ABORT, 'enrollment name matching is immutable');
END;
"""

# Independently retained, reviewed schema12 delta. Never load candidate SQL here.
_SCHEMA_12_SQL = """
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
"""


class InspectorContractError(RuntimeError):
    """A contract verification failure."""


def _create_schema_database(path: Path, version: int, *, frozen: bool = False) -> None:
    """Create an offline fixture, with the full reviewed layout for 10-12."""
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(f"PRAGMA user_version = {version}")
        if version >= 10:
            conn.executescript(_SCHEMA_10_SQL)
            if version >= 11:
                conn.executescript(_SCHEMA_11_SQL)
            if version >= 12:
                conn.executescript(_SCHEMA_12_SQL)
            conn.execute(
                "INSERT INTO agent_access_state VALUES (1, 0, 'initialized', NULL, NULL)"
            )
        elif version >= 6:
            conn.execute("""
                CREATE TABLE agent_access_state (
                    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
                    frozen     INTEGER NOT NULL CHECK (frozen IN (0, 1)),
                    transition TEXT NOT NULL
                        CHECK (transition IN ('initialized', 'freeze', 'unfreeze')),
                    changed_at TEXT,
                    reason     TEXT,
                    CHECK (
                        (transition = 'initialized' AND frozen = 0
                         AND changed_at IS NULL AND reason IS NULL)
                        OR (transition = 'freeze' AND frozen = 1
                            AND changed_at IS NOT NULL AND reason IS NOT NULL)
                        OR (transition = 'unfreeze' AND frozen = 0
                            AND changed_at IS NOT NULL AND reason IS NOT NULL)
                    )
                )
            """)
            conn.execute("""
                INSERT INTO agent_access_state
                    (singleton, frozen, transition, changed_at, reason)
                VALUES (1, 0, 'initialized', NULL, NULL)
            """)
            conn.execute("""
                CREATE TABLE agent_access_audit (
                    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                    transition TEXT NOT NULL CHECK (transition IN ('freeze', 'unfreeze')),
                    changed_at TEXT NOT NULL,
                    reason     TEXT NOT NULL
                )
            """)
        if version >= 6 and frozen:
            conn.execute(
                """
                UPDATE agent_access_state
                SET frozen = 1, transition = 'freeze',
                    changed_at = '2026-01-02T03:04:05Z', reason = 'contract fixture'
                """
            )
    if os.name == "posix":
        path.chmod(0o600)


def _check_inspector(
    inspector_path: Path,
    python_path: Path,
    database_path: Path,
    expected: dict[str, bool] | None,
) -> bool:
    try:
        result = subprocess.run(  # nosec B603
            [str(python_path), "-I", str(inspector_path), str(database_path)],
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError as error:
        raise InspectorContractError("inspector could not be executed") from error
    if expected is None:
        return result.returncode == 1 and not result.stdout
    if result.returncode != 0 or result.stderr or len(result.stdout) > 1024:
        return False
    try:
        payload = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.keys() == expected.keys()
        and all(type(value) is bool for value in payload.values())
        and payload == expected
    )


def verify_inspector_contract(inspector_path: Path, python_path: Path) -> dict:
    """Verify exact decisions, layout rejection, and a fixed future boundary."""
    if not inspector_path.is_absolute() or not python_path.is_absolute():
        raise InspectorContractError("paths must be absolute")

    results: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="inspector-contract-") as tmpdir:
        tmp = Path(tmpdir)
        for version in (6, 7, 8, 9, 10, 11, 12):
            decisions = []
            for frozen in (False, True):
                db_path = tmp / f"schema_{version}_{int(frozen)}.db"
                _create_schema_database(db_path, version, frozen=frozen)
                decisions.append(_check_inspector(
                    inspector_path, python_path, db_path,
                    {"schema_supported": True, "frozen": frozen},
                ))
            results[f"schema_{version}_accepted"] = all(decisions)
        legacy = tmp / "legacy.db"
        _create_schema_database(legacy, 5)
        results["legacy_schema_unsupported"] = _check_inspector(
            inspector_path, python_path, legacy,
            {"schema_supported": False, "frozen": False},
        )
        for version, key in (
            (13, "schema_13_rejected"),
            (2147483647, "future_schema_rejected"),
        ):
            db_path = tmp / f"future_{version}.db"
            _create_schema_database(db_path, version, frozen=True)
            results[key] = _check_inspector(
                inspector_path, python_path, db_path, None
            )
        malformed = []
        for version in (10, 11, 12):
            for defect in ("version-only", "missing-trigger", "invalid-state"):
                db_path = tmp / f"malformed_{version}_{defect}.db"
                _create_schema_database(
                    db_path, 9 if defect == "version-only" else version
                )
                with closing(sqlite3.connect(db_path)) as conn, conn:
                    conn.execute(f"PRAGMA user_version = {version}")
                    if defect == "missing-trigger":
                        conn.execute(
                            "DROP TRIGGER agents_reconnect_epoch_guard"
                            if version == 12 else
                            "DROP TRIGGER agent_enrollments_immutable_name_match"
                            if version == 11 else
                            "DROP TRIGGER agent_enrollments_immutable_identity"
                        )
                    elif defect == "invalid-state":
                        conn.execute(
                            """
                            UPDATE agent_access_state
                            SET frozen = 1, transition = 'freeze',
                                changed_at = 'not-a-time', reason = 'contract fixture'
                            """
                        )
                malformed.append(_check_inspector(
                    inspector_path, python_path, db_path, None
                ))
        results["malformed_schema_rejected"] = all(malformed)
    return {"contract_version": 3, **results, "passed": all(results.values())}


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: inspector_contract INSPECTOR_PATH PYTHON_PATH",
            file=sys.stderr,
        )
        return 1

    inspector_path = Path(sys.argv[1])
    python_path = Path(sys.argv[2])

    try:
        result = verify_inspector_contract(inspector_path, python_path)
    except InspectorContractError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1

    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
