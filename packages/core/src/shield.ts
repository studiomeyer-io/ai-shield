import type { ShieldConfig, ScanResult, ScanContext, ToolPolicy } from "./types.js";
import { ScannerChain } from "./scanner/chain.js";
import { HeuristicScanner } from "./scanner/heuristic.js";
import { PIIScanner } from "./scanner/pii.js";
import { ToolPolicyScanner } from "./policy/tools.js";
import { PolicyEngine } from "./policy/engine.js";
import { CostTracker } from "./cost/tracker.js";
import { AuditLogger, ConsoleAuditStore } from "./audit/logger.js";
import type { AuditStore } from "./audit/types.js";
import { ScanLRUCache } from "./cache/lru.js";

// ============================================================
// AIShield — Main class, single entry point
// ============================================================

export class AIShield {
  private chain: ScannerChain;
  private policyEngine: PolicyEngine;
  private costTracker: CostTracker | null;
  private auditLogger: AuditLogger | null;
  private scanCache: ScanLRUCache<ScanResult> | null;
  private config: ShieldConfig;

  constructor(config: ShieldConfig = {}) {
    this.config = config;
    this.policyEngine = new PolicyEngine(config.preset ?? "public_website");
    this.chain = new ScannerChain({ earlyExit: true });

    // Build scanner chain based on config
    this.setupScanners(config);

    // Cost tracker (optional, needs Redis for distributed use)
    this.costTracker = config.cost?.enabled !== false && config.cost?.budgets
      ? new CostTracker(config.cost.budgets)
      : null;

    // Audit logger (optional)
    this.auditLogger = this.setupAudit(config);

    // Scan cache (enabled when cache config is provided)
    this.scanCache = config.cache && config.cache.enabled !== false
      ? new ScanLRUCache<ScanResult>({
          maxSize: config.cache.maxSize,
          ttlMs: config.cache.ttlMs,
        })
      : null;
  }

  /** Scan input text — the main API */
  async scan(input: string, context: ScanContext = {}): Promise<ScanResult> {
    // Input-length guard — without this a user-supplied multi-MB prompt would
    // trigger every regex scan on the full buffer, which is O(n) best-case
    // but pathological under ReDoS-prone patterns. 256 KB handles every
    // real chat/tool input we care about with plenty of headroom; override
    // via AI_SHIELD_MAX_INPUT_BYTES when needed.
    const maxInputBytes = Number(process.env.AI_SHIELD_MAX_INPUT_BYTES ?? 262_144);
    if (input.length > maxInputBytes) {
      input = input.slice(0, maxInputBytes);
    }

    // Apply preset if not set in context
    if (!context.preset) {
      context.preset = this.config.preset ?? "public_website";
    }

    // Check cache
    if (this.scanCache) {
      const cacheKey = this.buildCacheKey(input, context);
      const cached = this.scanCache.get(cacheKey);
      if (cached) {
        return { ...cached, meta: { ...cached.meta, cached: true } };
      }
    }

    const result = await this.chain.run(input, context);

    // Store in cache
    if (this.scanCache) {
      const cacheKey = this.buildCacheKey(input, context);
      this.scanCache.set(cacheKey, result);
    }

    // Log to audit if enabled — but never double-log the same input when
    // a downstream caller re-scans cached content (result.meta.cached is set
    // by the cache hit path above; here it is always false but we guard to
    // be explicit and so subclasses extending scan() stay safe).
    if (this.auditLogger && !result.meta.cached) {
      void this.auditLogger.log(input, result, context);
    }

    return result;
  }

  /** Check cost budget before making an LLM call */
  async checkBudget(
    entityId: string,
    model: string,
    estimatedInputTokens: number,
    estimatedOutputTokens?: number,
  ) {
    if (!this.costTracker) {
      return { allowed: true, currentSpend: 0, remainingBudget: Infinity };
    }
    return this.costTracker.checkBudget(
      entityId,
      model,
      estimatedInputTokens,
      estimatedOutputTokens,
    );
  }

  /** Record cost after receiving LLM response */
  async recordCost(
    entityId: string,
    model: string,
    inputTokens: number,
    outputTokens: number,
  ) {
    if (!this.costTracker) return null;
    return this.costTracker.recordCost(entityId, model, inputTokens, outputTokens);
  }

  /** Get current spend for an entity */
  async getCurrentSpend(entityId: string): Promise<number> {
    if (!this.costTracker) return 0;
    return this.costTracker.getCurrentSpend(entityId);
  }

  /** Get the policy engine */
  getPolicy(): PolicyEngine {
    return this.policyEngine;
  }

  /** Clear the scan cache */
  clearCache(): void {
    this.scanCache?.clear();
  }

  /** Get cache stats */
  get cacheSize(): number {
    return this.scanCache?.size ?? 0;
  }

  /** Graceful shutdown */
  async close(): Promise<void> {
    this.scanCache?.clear();
    if (this.auditLogger) {
      await this.auditLogger.close();
    }
  }

  // --- Private setup ---

  private buildCacheKey(input: string, context: ScanContext): string {
    // Include preset + tool names in key since they affect scan results
    const parts = [context.preset ?? "default"];
    if (context.tools?.length) {
      parts.push(context.tools.map((t) => t.name).sort().join(","));
    }
    parts.push(input);
    return parts.join("\x00");
  }

  private setupScanners(config: ShieldConfig): void {
    // 1. Heuristic injection scanner (always on unless explicitly disabled)
    if (config.injection?.enabled !== false) {
      const preset = this.policyEngine.getPreset();
      this.chain.add(
        new HeuristicScanner({
          strictness: config.injection?.strictness ?? "medium",
          threshold: config.injection?.threshold ?? preset.injection.threshold,
          customPatterns: config.injection?.customPatterns?.map((pattern, i) => ({
            id: `CUSTOM-${i + 1}`,
            category: "instruction_override" as const,
            pattern,
            weight: 0.25,
            description: `Custom pattern #${i + 1}`,
          })),
        }),
      );
    }

    // 2. PII scanner
    if (config.pii?.enabled !== false) {
      this.chain.add(
        new PIIScanner({
          action: config.pii?.action ?? this.policyEngine.getPIIAction(),
          locale: config.pii?.locale,
          types: config.pii?.types,
          allowedTypes: config.pii?.allowedTypes,
        }),
      );
    }

    // 3. Tool policy scanner
    if (config.tools?.enabled !== false && config.tools?.policies) {
      const toolPolicy: ToolPolicy = {
        permissions: config.tools.policies,
        global: {
          dangerousPatterns:
            config.tools.globalDangerousPatterns ??
            this.policyEngine.getDangerousToolPatterns(),
          maxToolChainDepth:
            config.tools.maxToolChainDepth ??
            this.policyEngine.getMaxToolChainDepth(),
        },
      };
      this.chain.add(
        new ToolPolicyScanner(toolPolicy, config.tools.manifestPins),
      );
    }
  }

  private setupAudit(config: ShieldConfig): AuditLogger | null {
    if (config.audit?.enabled === false) return null;

    let store: AuditStore;
    switch (config.audit?.store) {
      case "console":
        store = new ConsoleAuditStore();
        break;
      case "postgresql":
        // PostgreSQL store would be imported separately to keep core lightweight
        // For now, fall through to console
        store = new ConsoleAuditStore();
        break;
      case "memory":
      default:
        // If no store configured and audit not explicitly enabled, skip
        if (!config.audit?.store && config.audit?.enabled !== true) return null;
        store = new ConsoleAuditStore();
        break;
    }

    return new AuditLogger({
      store,
      batchSize: config.audit?.batchSize,
      flushIntervalMs: config.audit?.flushIntervalMs,
    });
  }
}
