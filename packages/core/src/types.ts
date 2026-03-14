// ============================================================
// AI Shield Core Types
// ============================================================

// --- Scanner Types ---

export type ScanDecision = "allow" | "warn" | "block";

export type ViolationType =
  | "prompt_injection"
  | "pii_detected"
  | "tool_denied"
  | "tool_rate_limit"
  | "budget_exceeded"
  | "content_policy"
  | "manifest_drift";

export interface Violation {
  type: ViolationType;
  scanner: string;
  score: number;
  threshold: number;
  message: string;
  detail?: string;
}

export interface ScanResult {
  safe: boolean;
  decision: ScanDecision;
  sanitized: string;
  violations: Violation[];
  meta: {
    scanDurationMs: number;
    scannersRun: string[];
    cached: boolean;
  };
}

export interface ScannerResult {
  decision: ScanDecision;
  violations: Violation[];
  sanitized?: string;
  durationMs: number;
}

export interface Scanner {
  name: string;
  scan(input: string, context: ScanContext): Promise<ScannerResult>;
}

// --- Context ---

export interface ScanContext {
  agentId?: string;
  sessionId?: string;
  userId?: string;
  userType?: string;
  locale?: string;
  preset?: PresetName;
  tools?: ToolCall[];
}

export type PresetName = "public_website" | "internal_support" | "ops_agent";

// --- PII Types ---

export type PIIType =
  | "email"
  | "phone"
  | "iban"
  | "credit_card"
  | "german_tax_id"
  | "german_personal_id"
  | "german_social_security"
  | "ip_address"
  | "url_with_credentials";

export type PIIAction = "block" | "mask" | "tokenize" | "allow";

export interface PIIEntity {
  type: PIIType;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

// --- Tool Policy Types ---

export interface ToolCall {
  name: string;
  arguments?: Record<string, unknown>;
  serverId?: string;
}

export interface ToolPermissions {
  allowed: string[];
  denied?: string[];
  maxCallsPerMinute?: number;
  maxCallsPerSession?: number;
  requireApproval?: string[];
}

export interface ToolPolicy {
  permissions: Record<string, ToolPermissions>;
  global?: {
    dangerousPatterns?: string[];
    readOnlyMode?: boolean;
    maxToolChainDepth?: number;
  };
}

export interface ToolManifestPin {
  serverId: string;
  toolsHash: string;
  toolCount: number;
  knownTools: string[];
  pinnedAt: Date;
}

// --- Cost Types ---

export type BudgetPeriod = "hourly" | "daily" | "monthly";

export interface BudgetConfig {
  softLimit: number;
  hardLimit: number;
  period: BudgetPeriod;
}

export interface CostEstimate {
  inputTokens: number;
  outputTokens: number;
  estimatedCost: number;
  model: string;
}

export interface CostRecord {
  entityId: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cost: number;
  timestamp: Date;
}

export interface BudgetCheckResult {
  allowed: boolean;
  currentSpend: number;
  remainingBudget: number;
  warning?: string;
}

// --- Audit Types ---

export interface AuditRecord {
  id: string;
  timestamp: Date;
  sessionId?: string;
  agentId?: string;
  userIdHash?: string;
  requestType: "chat" | "tool_call" | "agent_to_agent";
  inputHash: string;
  inputTokenCount?: number;
  model?: string;
  securityDecision: ScanDecision;
  securityReason?: string;
  violations: Violation[];
  scanDurationMs: number;
  outputTokenCount?: number;
  toolsCalled?: string[];
  costUsd?: number;
}

// --- Config Types ---

export interface InjectionConfig {
  enabled?: boolean;
  strictness?: "low" | "medium" | "high";
  action?: "block" | "warn" | "flag";
  threshold?: number;
  customPatterns?: RegExp[];
}

export interface PIIConfig {
  enabled?: boolean;
  action?: PIIAction;
  locale?: string;
  types?: Partial<Record<PIIType, PIIAction>>;
  allowedTypes?: PIIType[];
}

export interface CostConfig {
  enabled?: boolean;
  budgets?: Record<string, BudgetConfig>;
  pricing?: Record<string, { inputPer1M: number; outputPer1M: number }>;
  redisUrl?: string;
}

export interface AuditConfig {
  enabled?: boolean;
  store?: "postgresql" | "memory" | "console";
  connectionString?: string;
  batchSize?: number;
  flushIntervalMs?: number;
  retentionDays?: number;
}

export interface ToolConfig {
  enabled?: boolean;
  policies?: Record<string, ToolPermissions>;
  globalDangerousPatterns?: string[];
  maxToolChainDepth?: number;
  manifestPins?: ToolManifestPin[];
}

export interface CacheConfig {
  /** Disable caching (default: enabled when cache config is provided) */
  enabled?: boolean;
  /** Maximum cached entries (default: 1000) */
  maxSize?: number;
  /** TTL in milliseconds (default: 300_000 = 5 minutes) */
  ttlMs?: number;
}

export interface ShieldConfig {
  injection?: InjectionConfig;
  pii?: PIIConfig;
  cost?: CostConfig;
  audit?: AuditConfig;
  tools?: ToolConfig;
  cache?: CacheConfig;
  preset?: PresetName;
}

// --- Model Pricing ---

export interface ModelPricing {
  inputPer1M: number;
  outputPer1M: number;
  cachedInputPer1M?: number;
}
