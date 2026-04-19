-- PostgreSQL init script — runs once on first startup
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Health check: a simple marker so the app knows the DB is ready
SELECT 1;
