-- The Hosts dashboard and the bus's stored event log.
--
-- A worker host reports what it is doing: its latest status snapshot is kept
-- whole, and a small sample of every report is kept for twelve hours, for
-- charts. Whose report it is always comes from the authenticated agent, never
-- from the report.
--
-- Only an agent marked as a host may report. The mark is the bus's own: it is
-- made when a host enrolment's service principal registers its
-- `<prefix>-host` agent, or by an administrator for a host enrolled before
-- that existed. An agent's name alone never counts. Every mark and unmark is
-- recorded and the record cannot be changed.
--
-- The event log is where a problem that has passed can still be found: a
-- failed update, a host that crashed overnight and recovered. An event is a
-- fixed type with a few checked fields; no free text from a host or from an
-- upstream server is stored. Each event id is stored once, so a retried
-- report never makes a duplicate. Events are deleted by age and by per-source
-- limits, never changed.
--
-- Rollback: back up and stop the service. Drop the triggers, indexes and five
-- tables below, then set `PRAGMA user_version = 24`. Rolling back loses the
-- host marks (hosts must be marked again after a later upgrade), every stored
-- status and sample, and the event log. Nothing else refers to these tables.

CREATE TABLE host_agents (
    agent_id        TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE RESTRICT,
    marked_at       TEXT NOT NULL,
    marked_by       TEXT NOT NULL CHECK (marked_by IN ('enrolment', 'admin')),
    -- When this host last reported, for the pause the bus asks between reports.
    last_status_at  TEXT,
    last_events_at  TEXT
);

CREATE TRIGGER host_agents_identity_immutable
BEFORE UPDATE ON host_agents
WHEN new.agent_id <> old.agent_id
  OR new.marked_at <> old.marked_at
  OR new.marked_by <> old.marked_by
BEGIN
    SELECT RAISE(ABORT, 'a host mark is immutable');
END;

CREATE TABLE host_agent_audit (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL CHECK (length(agent_id) = 36),
    agent_name   TEXT NOT NULL CHECK (length(agent_name) BETWEEN 1 AND 64),
    action       TEXT NOT NULL CHECK (action IN ('marked', 'unmarked')),
    actor_type   TEXT NOT NULL
        CHECK (actor_type IN ('host-enrolment', 'local-admin', 'remote-admin')),
    actor_id     TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    reason       TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    request_id   TEXT UNIQUE CHECK (request_id IS NULL OR length(request_id) = 36),
    occurred_at  TEXT NOT NULL
);

CREATE INDEX idx_host_agent_audit_agent ON host_agent_audit (agent_id, seq);

CREATE TRIGGER host_agent_audit_no_update
BEFORE UPDATE ON host_agent_audit
BEGIN
    SELECT RAISE(ABORT, 'host agent audit is append-only');
END;

CREATE TRIGGER host_agent_audit_no_delete
BEFORE DELETE ON host_agent_audit
BEGIN
    SELECT RAISE(ABORT, 'host agent audit is append-only');
END;

-- The latest snapshot of each host, exactly as the bus accepted it.
CREATE TABLE host_status (
    agent_id     TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE RESTRICT,
    received_at  TEXT NOT NULL,
    snapshot     TEXT NOT NULL
        CHECK (json_valid(snapshot) AND length(CAST(snapshot AS BLOB)) BETWEEN 2 AND 16384)
);

-- One small row per report, kept for twelve hours.
CREATE TABLE host_status_samples (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    received_at  TEXT NOT NULL,
    sample       TEXT NOT NULL
        CHECK (json_valid(sample) AND length(CAST(sample AS BLOB)) BETWEEN 2 AND 2048)
);

CREATE INDEX idx_host_status_samples_agent
    ON host_status_samples (agent_id, received_at);

CREATE INDEX idx_host_status_samples_age ON host_status_samples (received_at);

CREATE TRIGGER host_status_samples_no_update
BEFORE UPDATE ON host_status_samples
BEGIN
    SELECT RAISE(ABORT, 'a host status sample is immutable');
END;

CREATE TABLE bus_events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE CHECK (length(event_id) = 36),
    received_at  TEXT NOT NULL,
    -- The time the reporter gave, shown beside the bus's own. Never sorted by.
    reported_at  TEXT CHECK (reported_at IS NULL OR length(reported_at) = 20),
    source       TEXT NOT NULL CHECK (source IN ('host', 'update', 'security', 'bus')),
    level        TEXT NOT NULL CHECK (level IN ('info', 'warning', 'error')),
    type         TEXT NOT NULL
        CHECK (
            length(type) BETWEEN 1 AND 64
            AND type NOT GLOB '*[^0-9a-z-]*'
        ),
    -- Who or what the event is about: a host's agent name, a version, a device.
    subject      TEXT NOT NULL CHECK (length(subject) <= 128),
    fields       TEXT NOT NULL
        CHECK (
            json_valid(fields)
            AND json_type(fields) = 'object'
            AND length(CAST(fields AS BLOB)) <= 1024
        )
);

CREATE INDEX idx_bus_events_source_subject ON bus_events (source, subject, seq);

CREATE INDEX idx_bus_events_age ON bus_events (received_at);

CREATE TRIGGER bus_events_no_update
BEFORE UPDATE ON bus_events
BEGIN
    SELECT RAISE(ABORT, 'a bus event is immutable');
END;
