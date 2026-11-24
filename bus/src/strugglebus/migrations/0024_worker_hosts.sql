-- Worker hosts: single-use host enrolment codes, and a store for a site's
-- signed documents.
--
-- A host enrolment code is minted by an operator device for exactly one host
-- prefix (`host-<hostname>`). The host redeems it, with no other credential,
-- for its own service principal: one whose name and agent name prefix are
-- both that prefix. Only a hash of the code is kept. The redeeming request id
-- and source address are recorded so the operator can check that the host
-- that redeemed is the host they installed, before admitting it to the fleet.
--
-- A redeemed code may be presented again with the same request id until it
-- expires. The service principal's credential is replaced each time, because
-- only a hash of a credential is ever kept and a lost response could not
-- otherwise be recovered.
--
-- A site document is opaque signed bytes that the bus stores and returns. The
-- bus never verifies or interprets them: hosts do, against keys an
-- administrator pinned. A document's serial only ever goes up.
--
-- Rollback: back up and stop the service. Drop the triggers, indexes and
-- three tables below, restore `human_operator_posts_only_in_humans` to its
-- schema 19 text (no exception for host commands), then set
-- `PRAGMA user_version = 23`. Host command messages already posted stay. Service principals
-- already created by redeemed codes are ordinary service principals and are
-- not removed; block or revoke them through the existing controls first if
-- they should not survive. Rolling back loses pending codes, the record of
-- which request and address redeemed each code, and every stored document.

CREATE TABLE host_enrollments (
    id                TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 64),
    secret_hash       TEXT NOT NULL UNIQUE
        CHECK (
            length(secret_hash) = 64
            AND secret_hash NOT GLOB '*[^0-9a-f]*'
        ),
    host_prefix       TEXT NOT NULL
        CHECK (
            length(host_prefix) BETWEEN 2 AND 31
            AND host_prefix NOT GLOB '*[^0-9a-z-]*'
            AND host_prefix NOT GLOB '-*'
            AND host_prefix NOT GLOB '*-'
            AND host_prefix NOT GLOB '*--*'
        ),
    status            TEXT NOT NULL
        CHECK (status IN ('pending', 'redeemed', 'revoked')),
    mint_request_id   TEXT NOT NULL UNIQUE
        CHECK (length(mint_request_id) BETWEEN 1 AND 128),
    actor_type        TEXT NOT NULL
        CHECK (actor_type IN ('local-admin', 'remote-admin')),
    actor_id          TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    reason            TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    redeemed_at       TEXT,
    redeem_request_id TEXT
        CHECK (redeem_request_id IS NULL OR length(redeem_request_id) = 36),
    redeemed_from     TEXT
        CHECK (redeemed_from IS NULL OR length(redeemed_from) BETWEEN 1 AND 64),
    spn_id            TEXT REFERENCES spn_principals(id) ON DELETE RESTRICT,
    revoked_at        TEXT,
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'pending' AND redeemed_at IS NULL AND redeem_request_id IS NULL
            AND redeemed_from IS NULL AND spn_id IS NULL AND revoked_at IS NULL)
        OR (status = 'redeemed' AND redeemed_at IS NOT NULL
            AND redeem_request_id IS NOT NULL AND redeemed_from IS NOT NULL
            AND spn_id IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

-- One live code per host: minting again replaces the earlier one.
CREATE UNIQUE INDEX idx_host_enrollments_one_pending
    ON host_enrollments (host_prefix) WHERE status = 'pending';

CREATE UNIQUE INDEX idx_host_enrollments_spn
    ON host_enrollments (spn_id) WHERE spn_id IS NOT NULL;

CREATE TRIGGER host_enrollments_identity_immutable
BEFORE UPDATE ON host_enrollments
WHEN new.id <> old.id
  OR new.secret_hash <> old.secret_hash
  OR new.host_prefix <> old.host_prefix
  OR new.mint_request_id <> old.mint_request_id
  OR new.actor_type <> old.actor_type
  OR new.actor_id <> old.actor_id
  OR new.reason <> old.reason
  OR new.created_at <> old.created_at
  OR new.expires_at <> old.expires_at
  OR old.status = 'revoked'
  OR (old.status = 'redeemed' AND (
        new.status <> 'redeemed'
        OR new.redeemed_at <> old.redeemed_at
        OR new.redeem_request_id <> old.redeem_request_id
        OR new.redeemed_from <> old.redeemed_from
        OR new.spn_id <> old.spn_id))
BEGIN
    SELECT RAISE(ABORT, 'host enrollment is immutable');
END;

CREATE TRIGGER host_enrollments_no_delete
BEFORE DELETE ON host_enrollments
BEGIN
    SELECT RAISE(ABORT, 'host enrollments cannot be deleted');
END;

CREATE TABLE site_documents (
    name               TEXT PRIMARY KEY
        CHECK (
            length(name) BETWEEN 1 AND 64
            AND name NOT GLOB '*[^0-9a-z-]*'
        ),
    serial             INTEGER NOT NULL CHECK (serial >= 1),
    body               BLOB NOT NULL
        CHECK (typeof(body) = 'blob' AND length(body) BETWEEN 1 AND 65536),
    signature          TEXT NOT NULL CHECK (length(signature) BETWEEN 1 AND 4096),
    signer_fingerprint TEXT NOT NULL CHECK (length(signer_fingerprint) <= 128),
    stored_at          TEXT NOT NULL,
    actor_type         TEXT NOT NULL
        CHECK (actor_type IN ('local-admin', 'remote-admin')),
    actor_id           TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    reason             TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256)
);

CREATE TRIGGER site_documents_serial_rises
BEFORE UPDATE ON site_documents
WHEN new.name <> old.name OR new.serial <= old.serial
BEGIN
    SELECT RAISE(ABORT, 'site document serial must rise');
END;

CREATE TRIGGER site_documents_no_delete
BEFORE DELETE ON site_documents
BEGIN
    SELECT RAISE(ABORT, 'site documents cannot be deleted');
END;

-- What was stored, by whom and when. The bytes themselves are not kept here:
-- the hash is enough to tell which document a host accepted.
CREATE TABLE site_document_audit (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    serial             INTEGER NOT NULL CHECK (serial >= 1),
    body_sha256        TEXT NOT NULL
        CHECK (
            length(body_sha256) = 64
            AND body_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    signer_fingerprint TEXT NOT NULL CHECK (length(signer_fingerprint) <= 128),
    actor_type         TEXT NOT NULL
        CHECK (actor_type IN ('local-admin', 'remote-admin')),
    actor_id           TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    reason             TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    occurred_at        TEXT NOT NULL,
    UNIQUE (name, serial)
);

CREATE TRIGGER site_document_audit_no_update
BEFORE UPDATE ON site_document_audit
BEGIN
    SELECT RAISE(ABORT, 'site document audit is append-only');
END;

CREATE TRIGGER site_document_audit_no_delete
BEFORE DELETE ON site_document_audit
BEGIN
    SELECT RAISE(ABORT, 'site document audit is append-only');
END;

-- A signed host command is the one thing the operator author may post outside
-- #humans. It is a fixed-shape message whose metadata carries a small signed
-- document; the bus does not read or verify it. Worker hosts act on it only
-- if the signature checks against keys an administrator pinned on that host,
-- so the message itself still carries no authority.
DROP TRIGGER human_operator_posts_only_in_humans;

CREATE TRIGGER human_operator_posts_only_in_humans
BEFORE INSERT ON messages
WHEN new.agent_id = '00000000-0000-4000-8000-000000000019'
    AND new.channel_id IS NOT (SELECT id FROM channels WHERE name = 'humans')
    AND NOT (
        new.kind = 'question'
        AND new.reply_to IS NULL
        AND new.body = 'signed host command; see metadata'
        AND json_type(new.meta, '$.sb_host_command') IS 'object'
    )
BEGIN
    SELECT RAISE(ABORT, 'human operator author may post only in #humans');
END;
