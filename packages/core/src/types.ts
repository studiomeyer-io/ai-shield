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
  | "manifest_drift"
  | "ingested_injection"
  | "untrusted_instruction"
  | "memory_poisoning"
  | "circuit_breaker_open"
  | "blast_radius_exceeded"
  // --- Output-side (v0.3) — OWASP LLM05 Improper Output Handling ---
  /** LLM output carries an executable payload (SQL / shell / HTML/JS / template). */
  | "output_injection"
  /** LLM output leaks a secret (API key, token, private key, connection string). */
  | "secret_leak"
  /** LLM output echoes the system prompt / developer instructions. */
  | "system_prompt_leak"
  /** LLM output shows a successful jailbreak (compliance preamble, mode-switch acknowledgement). */
  | "jailbreak_indicator"
  // --- Multi-agent (v0.3) ---
  /** Trust violation propagating across an agent-to-agent chain (contagion). */
  | "trust_propagation";

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

/**
 * Where a piece of content came from. Determines how aggressively the
 * ingestion scanner treats instruction-like patterns.
 *
 * - `user`        — Direct user message. Treat normally.
 * - `rag`         — Retrieved document chunk (vector store, knowledge base).
 *                   Instructions here are almost always an indirect-injection
 *                   attempt.
 * - `tool-desc`   — MCP tool description / OpenAI function schema / tool args
 *                   that came from a remote MCP server. High-risk vector
 *                   per Lakera 2026 advisory + OX Security MCP CVEs.
 * - `tool-output` — The runtime *result* a tool returned (MCP tool result,
 *                   function-call output). Distinct from `tool-desc` (the
 *                   static schema): this is attacker-influenceable data the
 *                   tool fetched — the RAG-poisoning vector (PoisonedRAG:
 *                   5 docs → 90% ASR) and the dominant indirect-injection
 *                   channel in agentic loops.
 * - `memory`      — Persisted memory entry (knowledge graph, session
 *                   history, vector memory). Subject to persistence-poisoning.
 * - `web`         — Scraped web page / HTML. Hidden-instruction risk via
 *                   HTML comments, CSS-hidden text, unicode tricks.
 * - `agent-output`— Output from another agent flowing into this one
 *                   (multi-agent contagion).
 */
export type IngestionSource =
  | "user"
  | "rag"
  | "tool-desc"
  | "tool-output"
  | "memory"
  | "web"
  | "agent-output";

/**
 * Privilege tier of a content segment. The toolkit treats instructions
 * coming from `untrusted` sources differently from those in `system`
 * or `trusted` segments. See `wrapContext()`.
 */
export type TrustTier = "system" | "trusted" | "untrusted";

export interface ScanContext {
  agentId?: string;
  sessionId?: string;
  userId?: string;
  userType?: string;
  locale?: string;
  preset?: PresetName;
  tools?: ToolCall[];
  /**
   * Provenance of the content being scanned. Defaults to `"user"` when
   * unset. Set to `"rag"`/`"tool-desc"`/`"memory"`/`"web"`/`"agent-output"`
   * to engage indirect-injection heuristics.
   */
  source?: IngestionSource;
  /**
   * Privilege tier of the content. Defaults inferred from `source`:
   * `user` → untrusted, everything else → untrusted, `system` only when
   * explicitly set via `wrapContext()`.
   */
  trustTier?: TrustTier;
}

export type PresetName = "public_website" | "internal_support" | "ops_agent";

// --- Ingestion / Trust-Tier Context ---

/**
 * A single content segment with provenance + trust tagging.
 * Produced by `wrapContext()`, consumed by `assemblePrompt()` and
 * any policy that needs to enforce tier boundaries.
 */
export interface ContextSegment {
  /** Source of the segment. */
  source: IngestionSource;
  /** Privilege tier. */
  trust: TrustTier;
  /** Raw text content. */
  content: string;
  /** Optional human-readable origin label (e.g. "wikipedia.org/wiki/X"). */
  label?: string;
  /** Optional SHA-256 content hash for poisoning detection. */
  contentHash?: string;
}

export interface WrappedContext {
  /** All segments in the order they were added. */
  segments: ContextSegment[];
  /** Per-segment scan results (filled by `scanWrappedContext()`). */
  scanResults?: Array<{
    segmentIndex: number;
    decision: ScanDecision;
    violations: Violation[];
  }>;
  /** Aggregate decision across all segments. */
  decision?: ScanDecision;
}

// --- Memory Canary / Persistence Poisoning ---

/**
 * A memory entry sealed with a content hash + sentinel canary.
 * `verifyMemoryCanary()` re-derives the hash on read and flags
 * silent mutation.
 */
export interface MemoryCanaryEntry {
  /** Stable identifier of the memory entry (e.g. "fact:12345"). */
  id: string;
  /** Original content at write time. */
  content: string;
  /** SHA-256(`${id}\0${content}\0${canaryToken}`). */
  contentHash: string;
  /** Random sentinel token. Used to bind verification to this write. */
  canaryToken: string;
  /** When the canary was minted. */
  createdAt: Date;
  /** Optional tenant scope so leaks across tenants are detectable. */
  tenantId?: string;
}

export interface MemoryCanaryVerification {
  valid: boolean;
  reason?:
    | "content_mutated"
    | "canary_missing"
    | "tenant_mismatch"
    | "hash_mismatch";
  /** When invalid: the mutated content actually read. */
  observed?: string;
}

// --- Circuit Breaker / Tool Runtime Guard ---

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerConfig {
  /** Logical tool name this breaker applies to. */
  tool: string;
  /** Optional sub-scope (per-agent, per-session, per-tenant). */
  scope?: string;
  /** Anomaly count that trips the breaker. Default: 5. */
  failureThreshold?: number;
  /** Rolling window in ms for the failure count. Default: 60_000. */
  windowMs?: number;
  /** How long the breaker stays open after tripping (ms). Default: 60_000. */
  cooldownMs?: number;
  /** Max calls per `windowMs`. Default: unlimited. */
  maxCallsPerWindow?: number;
  /** Max "destructive" calls per `windowMs`. Default: unlimited. */
  maxWritesPerWindow?: number;
  /** Optional human-in-the-loop confirmation hook. */
  onDestructive?: (info: {
    tool: string;
    scope?: string;
    context: ScanContext;
  }) => boolean | Promise<boolean>;
  /** Treat this tool as destructive (default: inferred via wildcard list). */
  isDestructive?: boolean;
}

export interface CircuitBreakerDecision {
  /** Whether the call may proceed. */
  allowed: boolean;
  /** Current state. */
  state: CircuitState;
  /** Reason if `allowed = false`. */
  reason?:
    | "circuit_open"
    | "rate_limit"
    | "blast_radius_exceeded"
    | "hitl_denied";
  /** Detail for logs. */
  message?: string;
  /** Suggested retry-after in ms when state = open. */
  retryAfterMs?: number;
}

/**
 * Minimal counter store usable by the circuit breaker.
 * Compatible subset of `ioredis` so existing
 * `cost.tracker.RedisLike` deployments can be reused.
 */
export interface CounterStoreLike {
  get(key: string): Promise<string | null>;
  incrbyfloat(key: string, increment: number): Promise<string>;
  expire(key: string, seconds: number): Promise<number>;
}

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
