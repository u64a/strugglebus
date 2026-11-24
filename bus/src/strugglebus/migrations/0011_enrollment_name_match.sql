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
