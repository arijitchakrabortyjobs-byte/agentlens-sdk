-- AgentLens compliance schema for PostgreSQL
-- Mirrors compliance_db.py but production-grade (replaces SQLite)

CREATE TABLE IF NOT EXISTS sessions (
    id              SERIAL PRIMARY KEY,
    session_id      TEXT NOT NULL UNIQUE,
    entity          TEXT NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decisions       INTEGER NOT NULL DEFAULT 0,
    human_overrides INTEGER NOT NULL DEFAULT 0,
    guardrail_hits  INTEGER NOT NULL DEFAULT 0,
    chain_intact    BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS idx_sessions_entity ON sessions(entity);
CREATE INDEX IF NOT EXISTS idx_sessions_recorded_at ON sessions(recorded_at DESC);

CREATE TABLE IF NOT EXISTS responsibility_map (
    id          SERIAL PRIMARY KEY,
    entity_name TEXT NOT NULL,
    role        TEXT NOT NULL,
    party       TEXT NOT NULL,
    ref         TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (entity_name, role)
);

-- For RBI examiner read-only access (no INSERT/UPDATE/DELETE)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rbi_examiner') THEN
        CREATE ROLE rbi_examiner;
    END IF;
END
$$;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO rbi_examiner;

-- For AgentLens service account
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'agentlens_service') THEN
        CREATE ROLE agentlens_service;
    END IF;
END
$$;
GRANT SELECT, INSERT, UPDATE ON sessions, responsibility_map TO agentlens_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agentlens_service;
