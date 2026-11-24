-- A satellite site is a remote machine admitted to the satellite path by a
-- client certificate the bus issued. It is a network admission record, not a
-- principal: agents on a site still authenticate with their own credentials,
-- and nothing here grants board access. The label stays reserved after
-- revocation so a site's history cannot be reattributed to a successor.
--
-- Rollback: restore the pre-migration backup, or drop satellite_sites and set
-- `PRAGMA user_version = 20`. That only removes site admission records.
CREATE TABLE satellite_sites (
    id                TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 256),
    label             TEXT NOT NULL UNIQUE
        CHECK (
            length(label) BETWEEN 1 AND 64
            AND label NOT GLOB '*[^0-9a-z-]*'
        ),
    cert_sha256       TEXT NOT NULL UNIQUE
        CHECK (length(cert_sha256) = 64 AND cert_sha256 NOT GLOB '*[^0-9a-f]*'),
    cert_expires_at   TEXT NOT NULL,
    status            TEXT NOT NULL
        CHECK (status IN ('enabled', 'revoked')),
    created_at        TEXT NOT NULL,
    created_by        TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 256),
    revoked_at        TEXT,
    revoked_by        TEXT CHECK (revoked_by IS NULL OR length(revoked_by) BETWEEN 1 AND 256),
    revocation_reason TEXT
        CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256),
    CHECK (
        (status = 'enabled' AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);
