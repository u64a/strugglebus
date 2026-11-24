CREATE TABLE agent_access_state (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    frozen     INTEGER NOT NULL CHECK (frozen IN (0, 1)),
    transition TEXT NOT NULL
        CHECK (transition IN ('initialized', 'freeze', 'unfreeze')),
    changed_at TEXT,
    reason     TEXT,
    CHECK (
        (
            transition = 'initialized'
            AND frozen = 0
            AND changed_at IS NULL
            AND reason IS NULL
        )
        OR (
            transition = 'freeze'
            AND frozen = 1
            AND changed_at IS NOT NULL
            AND reason IS NOT NULL
        )
        OR (
            transition = 'unfreeze'
            AND frozen = 0
            AND changed_at IS NOT NULL
            AND reason IS NOT NULL
        )
    )
);

INSERT INTO agent_access_state (
    singleton, frozen, transition, changed_at, reason
)
VALUES (1, 0, 'initialized', NULL, NULL);

CREATE TABLE agent_access_audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    transition TEXT NOT NULL CHECK (transition IN ('freeze', 'unfreeze')),
    changed_at TEXT NOT NULL,
    reason     TEXT NOT NULL
);
