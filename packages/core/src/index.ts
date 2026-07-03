// ============================================================
// ai-shield-core — Public API
// ============================================================

// Main class
export { AIShield } from "./shield.js";

// Scanners (for custom chain building)
export {
  HeuristicScanner,
  normalizeForInjectionScan,
  collapseSpacedLetters,
  deTagForInjectionScan,
  hasTagChars,
  leetDecodeForInjectionScan,
  unscrambleForInjectionScan,
  damerauLevenshtein,
  type HeuristicConfig,
} from "./scanner/heuristic.js";
export { PIIScanner } from "./scanner/pii.js";
export { ScannerChain, type ChainConfig } from "./scanner/chain.js";
export { injectCanary, checkCanaryLeak } from "./scanner/canary.js";
export {
  IngestionScanner,
  scanIngested,
  scanToolOutput,
  trustTierForSource,
  tryDecodeObfuscation,
  type IngestionScannerConfig,
  type IngestionScanResult,
} from "./scanner/ingestion.js";

// Output scanning (v0.3) — OWASP LLM05 / LLM02 output side
export {
  OutputScanner,
  scanOutput,
  type OutputScanConfig,
  type OutputScanResult,
  type OutputSink,
} from "./scanner/output.js";

// Context / Trust-Tier
export {
  wrapContext,
  scanWrappedContext,
  assemblePrompt,
  flattenViolations,
  propagateTrust,
  type WrapContextInput,
  type AssembleOptions,
  type AgentHop,
  type PropagateTrustOptions,
  type TrustPropagationResult,
} from "./context/wrap-context.js";

// Async LLM-as-Judge (v0.3) — semantic detection, off the hot path
export {
  createAsyncJudge,
  type AsyncJudge,
  type AsyncJudgeConfig,
  type JudgeVerdict,
  type JudgeBackend,
  type JudgeBackendLike,
} from "./judge/async-judge.js";

// Dual-LLM privilege separation + action screening (v0.5) — OWASP-recommended
// architectural mitigation for indirect injection in agentic systems
export {
  createDualLLM,
  createActionScreener,
  type LLMBackend,
  type DualLLMConfig,
  type DualLLM,
  type QuarantineResult,
  type ActionScreenerConfig,
  type ActionScreenResult,
} from "./orchestration/dual-llm.js";

// Memory Canary / Persistence-Poisoning
export {
  mintMemoryCanary,
  verifyMemoryCanary,
  rotateMemoryCanary,
  buildSentinelEntry,
  bulkVerify,
  type MintMemoryCanaryOptions,
} from "./canary/memory.js";

// Policy
export { PolicyEngine, type PolicyPreset } from "./policy/engine.js";
export { ToolPolicyScanner } from "./policy/tools.js";
export {
  CircuitBreakerRegistry,
  makeBreakerScope,
  type CircuitBreakerOptions,
} from "./policy/circuit-breaker.js";

// Cost
export { CostTracker, type RedisLike } from "./cost/tracker.js";
export { detectAnomaly, type AnomalyResult } from "./cost/anomaly.js";
export {
  getModelPricing,
  estimateCost,
  MODEL_PRICING,
} from "./cost/pricing.js";

// Audit
export {
  AuditLogger,
  ConsoleAuditStore,
  MemoryAuditStore,
} from "./audit/logger.js";
export {
  PostgresAuditStore,
  type PostgresAuditStoreConfig,
  type PostgresConnectionOptions,
  type PgPoolLike,
  type PgQueryResultLike,
} from "./audit/postgres.js";
export type { AuditStore } from "./audit/types.js";

// Cache
export { ScanLRUCache, type LRUCacheConfig } from "./cache/lru.js";

// Types (re-export everything)
export type {
  // Scanner
  ScanDecision,
  ScanResult,
  ScannerResult,
  Scanner,
  ScanContext,
  Violation,
  ViolationType,
  // Ingestion / Trust-Tier (v0.2)
  IngestionSource,
  TrustTier,
  ContextSegment,
  WrappedContext,
  // Memory Canary (v0.2)
  MemoryCanaryEntry,
  MemoryCanaryVerification,
  // Circuit Breaker (v0.2)
  CircuitState,
  CircuitBreakerConfig,
  CircuitBreakerDecision,
  CounterStoreLike,
  // PII
  PIIType,
  PIIAction,
  PIIEntity,
  PIIConfig,
  // Tool
  ToolCall,
  ToolPermissions,
  ToolPolicy,
  ToolManifestPin,
  // Cost
  BudgetPeriod,
  BudgetConfig,
  CostEstimate,
  CostRecord,
  BudgetCheckResult,
  ModelPricing,
  // Audit
  AuditRecord,
  AuditConfig,
  // Config
  ShieldConfig,
  InjectionConfig,
  CostConfig,
  CacheConfig,
  ToolConfig,
  PresetName,
} from "./types.js";

// --- Convenience function ---

import { AIShield } from "./shield.js";
import type { ShieldConfig, ScanResult, ScanContext } from "./types.js";

/**
 * Quick scan — one line, maximum protection.
 *
 * **Performance warning:** This creates a new AIShield instance on every call.
 * For production use with multiple calls, create a single `new AIShield(config)`
 * instance and reuse it — this avoids repeated scanner chain setup and teardown.
 *
 * Use `createShieldSingleton()` for a cached version that reuses a single instance.
 */
export async function shield(
  input: string,
  configOrContext?: ShieldConfig | ScanContext,
): Promise<ScanResult> {
  // Decide whether the second arg is a ShieldConfig or a ScanContext.
  //
  // The two types share the ambiguous keys `preset` and `tools`, so key-
  // sniffing on `preset` alone is wrong: a real `{ preset, source: "rag" }`
  // ScanContext used to be misread as a config, silently dropping its
  // userId/sessionId/source and breaking ingestion routing. Route on a real
  // discriminant instead — context-only keys win over the shared ones — and
  // parenthesize explicitly so the `||`/`&&` precedence can't bite again.
  const config = isShieldConfig(configOrContext)
    ? (configOrContext as ShieldConfig)
    : {};
  const context = isShieldConfig(configOrContext)
    ? {}
    : ((configOrContext as ScanContext) ?? {});

  const instance = new AIShield(config);
  try {
    return await instance.scan(input, context);
  } finally {
    await instance.close();
  }
}

/** Keys that exist ONLY on ScanContext (never on ShieldConfig). */
const CONTEXT_ONLY_KEYS = [
  "agentId",
  "sessionId",
  "userId",
  "userType",
  "locale",
  "source",
  "trustTier",
] as const;

/** Keys that exist ONLY on ShieldConfig (never on ScanContext). */
const CONFIG_ONLY_KEYS = [
  "injection",
  "pii",
  "cost",
  "audit",
  "cache",
] as const;

/**
 * True when `arg` should be treated as a ShieldConfig (vs a ScanContext).
 *
 * Decision order:
 *  1. Any context-only key present (e.g. `source`, `userId`) → it's a context.
 *  2. Otherwise any config-only key present → it's a config.
 *  3. Only the ambiguous `preset`/`tools` (or empty/undefined) → default to a
 *     context, the lower-blast-radius interpretation (a stray `preset` on a
 *     context is harmless; misrouting a context loses ingestion metadata).
 */
function isShieldConfig(
  arg: ShieldConfig | ScanContext | undefined,
): arg is ShieldConfig {
  if (!arg || typeof arg !== "object") return false;
  for (const k of CONTEXT_ONLY_KEYS) {
    if (k in arg) return false;
  }
  for (const k of CONFIG_ONLY_KEYS) {
    if (k in arg) return true;
  }
  return false;
}

/**
 * Create a cached shield function that reuses a single AIShield instance.
 * Much better performance than `shield()` for repeated calls.
 *
 * @example
 * ```ts
 * const scan = createShieldSingleton({ injection: { strictness: "high" } });
 * const r1 = await scan("input 1");
 * const r2 = await scan("input 2");
 * // Call scan.close() when done (e.g., on process exit)
 * await scan.close();
 * ```
 */
export function createShieldSingleton(config: ShieldConfig = {}): {
  (input: string, context?: ScanContext): Promise<ScanResult>;
  close(): Promise<void>;
} {
  const instance = new AIShield(config);

  const scan = (input: string, context?: ScanContext): Promise<ScanResult> => {
    return instance.scan(input, context);
  };

  scan.close = (): Promise<void> => instance.close();

  return scan;
}
