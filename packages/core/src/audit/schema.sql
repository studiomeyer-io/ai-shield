-- AI Shield Audit Schema
-- Append-only; stores hashes + metadata, never raw content (DSGVO/GDPR).
-- Mirrors the DDL that PostgresAuditStore.ensureSchema() runs at runtime.

CREATE TABLE IF NOT EXISTS ai_shield_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  session_id TEXT,
  agent_id TEXT,
  user_id_hash VARCHAR(64),
  request_type VARCHAR(20) NOT NULL,
  input_hash VARCHAR(64) NOT NULL,
  input_token_count INTEGER,
  model TEXT,
  security_decision VARCHAR(10) NOT NULL,
  security_reason TEXT,
  violations JSONB NOT NULL DEFAULT '[]',
  scan_duration_ms DOUBLE PRECISION,
  output_token_count INTEGER,
  tools_called TEXT[],
  cost_usd NUMERIC(10, 6)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ai_shield_audit_timestamp ON ai_shield_audit (timestamp);
CREATE INDEX IF NOT EXISTS idx_ai_shield_audit_agent ON ai_shield_audit (agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ai_shield_audit_decision ON ai_shield_audit (security_decision) WHERE security_decision != 'allow';
CREATE INDEX IF NOT EXISTS idx_ai_shield_audit_violations ON ai_shield_audit USING GIN (violations);

-- Cost tracking table
CREATE TABLE IF NOT EXISTS ai_shield_cost_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id VARCHAR(128) NOT NULL,
  model VARCHAR(64) NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  cost_usd NUMERIC(10, 6) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_shield_cost_entity ON ai_shield_cost_records (entity_id, timestamp);

-- Tool manifest pins
CREATE TABLE IF NOT EXISTS ai_shield_manifest_pins (
  server_id VARCHAR(128) PRIMARY KEY,
  tools_hash VARCHAR(64) NOT NULL,
  tool_count INTEGER NOT NULL,
  known_tools JSONB NOT NULL,
  pinned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
