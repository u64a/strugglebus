-- An SPN may issue a worker identity with a fixed expiry. The expiry is set
-- once, when the package is issued, and copied to the agent at redemption;
-- neither copy can change afterwards. An expired identity authenticates
-- nowhere and is retired by the issuing SPN's next sweep. NULL means the
-- durable identity every earlier package created.
--
-- Rollback: restore the pre-migration backup. The added columns are nullable
-- and unused by schema 21, so setting `PRAGMA user_version = 21` and dropping
-- the two triggers also works, but expired identities would
-- then authenticate again unless they were retired first.
ALTER TABLE agent_enrollments ADD COLUMN identity_expires_at TEXT;
ALTER TABLE agents ADD COLUMN expires_at TEXT;

CREATE TRIGGER agent_enrollments_identity_expiry_immutable
BEFORE UPDATE OF identity_expires_at ON agent_enrollments
WHEN new.identity_expires_at IS NOT old.identity_expires_at
BEGIN
    SELECT RAISE(ABORT, 'enrollment identity expiry is immutable');
END;

CREATE TRIGGER agents_expiry_immutable
BEFORE UPDATE OF expires_at ON agents
WHEN new.expires_at IS NOT old.expires_at
BEGIN
    SELECT RAISE(ABORT, 'agent expiry is immutable');
END;
