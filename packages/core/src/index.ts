// ============================================================
// ai-shield-core — Public API
// ============================================================

// Main class
export { AIShield } from "./shield.js";

// Scanners (for custom chain building)
export { HeuristicScanner, type HeuristicConfig } from "./scanner/heuristic.js";
export { PIIScanner } from "./scanner/pii.js";
export { ScannerChain, type ChainConfig } from "./scanner/chain.js";
export { injectCanary, checkCanaryLeak } from "./scanner/canary.js";

// Policy
export { PolicyEngine, type PolicyPreset } from "./policy/engine.js";
export { ToolPolicyScanner } from "./policy/tools.js";

// Cost
export { CostTracker, type RedisLike } from "./cost/tracker.js";
export { detectAnomaly, type AnomalyResult } from "./cost/anomaly.js";
export { getModelPricing, estimateCost, MODEL_PRICING } from "./cost/pricing.js";

// Audit
export { AuditLogger, ConsoleAuditStore, MemoryAuditStore } from "./audit/logger.js";
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
  // Detect if second arg is config or context
  const isConfig = configOrContext && ("injection" in configOrContext || "pii" in configOrContext || "cost" in configOrContext || "preset" in configOrContext && typeof configOrContext.preset === "string" && !("agentId" in configOrContext));

  const config = isConfig ? (configOrContext as ShieldConfig) : {};
  const context = isConfig ? {} : (configOrContext as ScanContext) ?? {};

  const instance = new AIShield(config);
  try {
    return await instance.scan(input, context);
  } finally {
    await instance.close();
  }
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
