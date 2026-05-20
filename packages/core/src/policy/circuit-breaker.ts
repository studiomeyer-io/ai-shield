import type {
  CircuitBreakerConfig,
  CircuitBreakerDecision,
  CircuitState,
  CounterStoreLike,
  ScanContext,
  ToolCall,
  ViolationType,
} from "../types.js";

// ============================================================
// Circuit Breaker — Tool-Policy Runtime Guard
//
// The existing `ToolPolicyScanner` (policy/tools.ts) is a *static*
// gate: allow / deny lists, manifest pin, dangerous patterns. It
// runs once per call.
//
// The circuit breaker layers *runtime* defense on top:
//   - Rate limit per (tool, scope) within a rolling window.
//   - "Blast radius" cap: max writes per window (for destructive ops).
//   - Trip + cooldown: after N anomalies the tool is blocked for a
//     period regardless of static policy.
//   - Optional Human-In-The-Loop hook for destructive operations
//     ("type the tool name to confirm").
//
// Counters can live in-process (default) or in any `ioredis`-shaped
// store so the breaker tracks state across replicas.
// ============================================================

const DESTRUCTIVE_DEFAULTS = [
  "delete_",
  "remove_",
  "drop_",
  "destroy_",
  "wipe_",
  "shutdown_",
  "purge_",
  "truncate_",
  "send_email",
  "transfer_",
  "payment_",
];

const DEFAULTS: Required<
  Pick<
    CircuitBreakerConfig,
    "failureThreshold" | "windowMs" | "cooldownMs"
  >
> = {
  failureThreshold: 5,
  windowMs: 60_000,
  cooldownMs: 60_000,
};

interface InternalState {
  state: CircuitState;
  openedAt: number;
  failures: number[]; // timestamps within current window
  calls: number[]; // timestamps within current window
  writes: number[]; // timestamps within current window
}

class InMemoryCounter implements CounterStoreLike {
  private data = new Map<string, { value: string; expiresAt?: number }>();

  async get(key: string): Promise<string | null> {
    const e = this.data.get(key);
    if (!e) return null;
    if (e.expiresAt && Date.now() > e.expiresAt) {
      this.data.delete(key);
      return null;
    }
    return e.value;
  }
  async incrbyfloat(key: string, increment: number): Promise<string> {
    const cur = parseFloat((await this.get(key)) ?? "0");
    const next = (cur + increment).toString();
    const e = this.data.get(key);
    this.data.set(key, { value: next, expiresAt: e?.expiresAt });
    return next;
  }
  async expire(key: string, seconds: number): Promise<number> {
    const e = this.data.get(key);
    if (!e) return 0;
    e.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }
}

export interface CircuitBreakerOptions {
  /** Optional distributed counter store (ioredis-compatible). */
  counterStore?: CounterStoreLike;
  /**
   * Cap on the number of (tool, scope) pairs tracked in-process.
   * Prevents unbounded growth in long-lived runtimes. Default: 5_000.
   * Override via env `AI_SHIELD_CIRCUIT_MAX_KEYS`.
   */
  maxKeys?: number;
}

/**
 * Registry of breakers keyed by `${tool}::${scope}`. The registry
 * owns config + state; per-(tool, scope) breakers are created lazily.
 */
export class CircuitBreakerRegistry {
  private configs = new Map<string, Required<CircuitBreakerConfig>>();
  private states = new Map<string, InternalState>();
  /**
   * Reserved for distributed-counter mode (e.g. cross-replica state).
   * The in-process path is the supported v0.2 surface; the store is
   * accepted so callers wiring up an `ioredis`-shaped backend get a
   * stable constructor option, and downstream releases can swap the
   * internal accounting to use it without breaking the API.
   */
  protected readonly store: CounterStoreLike;
  private readonly maxKeys: number;

  constructor(
    configs: CircuitBreakerConfig[] = [],
    options: CircuitBreakerOptions = {},
  ) {
    this.store = options.counterStore ?? new InMemoryCounter();
    const envCap = Number(process.env.AI_SHIELD_CIRCUIT_MAX_KEYS);
    this.maxKeys =
      options.maxKeys ??
      (Number.isFinite(envCap) && envCap > 0 ? envCap : 5_000);
    for (const cfg of configs) {
      this.configure(cfg);
    }
  }

  /** Configure (or re-configure) a breaker. Idempotent. */
  configure(config: CircuitBreakerConfig): void {
    const key = keyFor(config.tool, config.scope);
    this.configs.set(key, {
      tool: config.tool,
      scope: config.scope ?? "",
      failureThreshold:
        config.failureThreshold ?? DEFAULTS.failureThreshold,
      windowMs: config.windowMs ?? DEFAULTS.windowMs,
      cooldownMs: config.cooldownMs ?? DEFAULTS.cooldownMs,
      maxCallsPerWindow: config.maxCallsPerWindow ?? Infinity,
      maxWritesPerWindow: config.maxWritesPerWindow ?? Infinity,
      onDestructive: config.onDestructive ?? (() => true),
      isDestructive:
        config.isDestructive ?? isLikelyDestructive(config.tool),
    });
  }

  /**
   * Check whether a tool call is allowed. Records the attempt either
   * way; callers must invoke `recordSuccess()`/`recordFailure()` AFTER
   * the actual call so anomaly counts stay honest.
   */
  async check(
    tool: ToolCall,
    context: ScanContext = {},
  ): Promise<CircuitBreakerDecision> {
    const scope = scopeFor(context);
    const key = keyFor(tool.name, scope);
    const config = this.configs.get(key) ?? this.configs.get(keyFor(tool.name, ""));

    // No config → no breaker → allow. The caller may still use
    // the static ToolPolicyScanner for default deny.
    if (!config) {
      return { allowed: true, state: "closed" };
    }

    const state = this.getOrInitState(key);
    const now = Date.now();
    prune(state, now, config.windowMs);

    // 1. Open / half-open transitions.
    if (state.state === "open") {
      if (now - state.openedAt >= config.cooldownMs) {
        state.state = "half-open";
      } else {
        return {
          allowed: false,
          state: "open",
          reason: "circuit_open",
          retryAfterMs: config.cooldownMs - (now - state.openedAt),
          message: `Circuit OPEN for ${tool.name}${scope ? `@${scope}` : ""}`,
        };
      }
    }

    // 2. Rate-limit cap.
    if (state.calls.length >= config.maxCallsPerWindow) {
      return {
        allowed: false,
        state: state.state,
        reason: "rate_limit",
        retryAfterMs: config.windowMs,
        message: `Rate limit ${config.maxCallsPerWindow}/${config.windowMs}ms exceeded for ${tool.name}`,
      };
    }

    // 3. Blast-radius cap for destructive tools.
    if (
      config.isDestructive &&
      state.writes.length >= config.maxWritesPerWindow
    ) {
      return {
        allowed: false,
        state: state.state,
        reason: "blast_radius_exceeded",
        retryAfterMs: config.windowMs,
        message: `Blast-radius cap ${config.maxWritesPerWindow}/${config.windowMs}ms hit for ${tool.name}`,
      };
    }

    // 4. HITL gate for destructive ops.
    //
    // Record the call/write OPTIMISTICALLY first, BEFORE awaiting the
    // HITL hook. Two concurrent destructive calls otherwise both see
    // `state.writes.length === 0` and both get past the blast-radius
    // gate (Critic M3 round 1 — TOCTOU on shared mutable state).
    //
    // Round 2 Critic H-NEW-1: rolling back via `pop()` is unsafe under
    // Node.js's cooperative scheduler — a concurrent push between our
    // push and our pop can shift positions, so `pop()` removes the wrong
    // entry. Capture the SENTINEL value we pushed and remove that exact
    // entry on rollback. Two concurrent rollbacks of identical-now
    // timestamps could theoretically still touch each other's entry,
    // but at worst they remove a sibling rather than letting a counter
    // run away — semantically equivalent for rate-limit purposes.
    const callSentinel: number = now;
    state.calls.push(callSentinel);
    let writeSentinel: number | null = null;
    if (config.isDestructive) {
      writeSentinel = now;
      state.writes.push(writeSentinel);
    }
    const rollbackOptimisticRecord = (): void => {
      // Remove the LAST occurrence of the sentinel (the one we pushed)
      // so concurrent rollbacks don't touch each other's entries.
      const callIdx = state.calls.lastIndexOf(callSentinel);
      if (callIdx >= 0) state.calls.splice(callIdx, 1);
      if (writeSentinel !== null) {
        const writeIdx = state.writes.lastIndexOf(writeSentinel);
        if (writeIdx >= 0) state.writes.splice(writeIdx, 1);
      }
    };

    if (config.isDestructive) {
      let rawResult: unknown;
      try {
        rawResult = await Promise.resolve(
          config.onDestructive({
            tool: tool.name,
            scope: config.scope,
            context,
          }),
        );
      } catch (err) {
        rollbackOptimisticRecord();
        return {
          allowed: false,
          state: state.state,
          reason: "hitl_denied",
          message: `HITL hook threw: ${(err as Error).message}`,
        };
      }
      // Critic H3 — a hook that returns `undefined` (async function
      // without explicit `return`) or any non-boolean value is the most
      // common HITL footgun. Fail safe AND surface the programming
      // error rather than silently coerce.
      if (typeof rawResult !== "boolean") {
        rollbackOptimisticRecord();
        return {
          allowed: false,
          state: state.state,
          reason: "hitl_denied",
          message: `HITL hook for '${tool.name}' returned non-boolean (${typeof rawResult}); treating as denial`,
        };
      }
      if (!rawResult) {
        rollbackOptimisticRecord();
        return {
          allowed: false,
          state: state.state,
          reason: "hitl_denied",
          message: `Human-in-the-loop denied ${tool.name}`,
        };
      }
    }

    return { allowed: true, state: state.state };
  }

  /** Record a successful tool invocation. Closes a half-open breaker. */
  recordSuccess(toolName: string, context: ScanContext = {}): void {
    const scope = scopeFor(context);
    const key = keyFor(toolName, scope);
    const state = this.states.get(key);
    if (!state) return;
    if (state.state === "half-open") {
      state.state = "closed";
      state.failures = [];
    }
  }

  /**
   * Record a failed tool invocation. Trips the breaker once
   * `failureThreshold` failures accumulate within the window.
   */
  recordFailure(toolName: string, context: ScanContext = {}): void {
    const scope = scopeFor(context);
    const key = keyFor(toolName, scope);
    const config = this.configs.get(key) ?? this.configs.get(keyFor(toolName, ""));
    if (!config) return;
    const state = this.getOrInitState(key);
    const now = Date.now();
    prune(state, now, config.windowMs);
    state.failures.push(now);

    if (state.failures.length >= config.failureThreshold) {
      state.state = "open";
      state.openedAt = now;
    }
  }

  /** Manually force a breaker into a state — useful for tests / ops. */
  trip(toolName: string, scope?: string): void {
    const key = keyFor(toolName, scope ?? "");
    const state = this.getOrInitState(key);
    state.state = "open";
    state.openedAt = Date.now();
  }

  reset(toolName: string, scope?: string): void {
    const key = keyFor(toolName, scope ?? "");
    this.states.delete(key);
  }

  /** Inspect current state — for dashboards / audit. */
  inspect(toolName: string, scope?: string): {
    state: CircuitState;
    callsInWindow: number;
    writesInWindow: number;
    failuresInWindow: number;
  } | null {
    const key = keyFor(toolName, scope ?? "");
    const state = this.states.get(key);
    const config = this.configs.get(key) ?? this.configs.get(keyFor(toolName, ""));
    if (!state || !config) return null;
    const now = Date.now();
    prune(state, now, config.windowMs);
    return {
      state: state.state,
      callsInWindow: state.calls.length,
      writesInWindow: state.writes.length,
      failuresInWindow: state.failures.length,
    };
  }

  /** Suggested ViolationType for a denied decision — useful in audit logs. */
  static violationType(decision: CircuitBreakerDecision): ViolationType {
    if (decision.reason === "circuit_open") return "circuit_breaker_open";
    if (decision.reason === "blast_radius_exceeded")
      return "blast_radius_exceeded";
    if (decision.reason === "rate_limit") return "tool_rate_limit";
    return "tool_denied";
  }

  // --- internal ---

  private getOrInitState(key: string): InternalState {
    let state = this.states.get(key);
    if (state) {
      // Touch — promote to MRU. JS Map preserves insertion order;
      // delete + set moves the entry to the tail (Analyst A5 round 1).
      this.states.delete(key);
      this.states.set(key, state);
      return state;
    }
    // True-LRU eviction: oldest key (head of Map) is dropped first.
    // Combined with the touch-on-access above this gives correct LRU
    // semantics and prevents key-explosion attacks from evicting
    // long-lived legitimate breakers.
    if (this.states.size >= this.maxKeys) {
      const oldestKey = this.states.keys().next().value;
      if (oldestKey) this.states.delete(oldestKey);
    }
    state = {
      state: "closed",
      openedAt: 0,
      failures: [],
      calls: [],
      writes: [],
    };
    this.states.set(key, state);
    return state;
  }
}

// --- helpers ---

// NUL byte cannot appear in valid tool names or agent/session IDs.
// `keyFor` uses TWO NULs as the tool↔scope boundary; `makeBreakerScope`
// uses ONE NUL between agentId and sessionId. Two-NUL boundary disambig-
// uates tool name from scope payload even when the scope itself contains
// a single NUL — Analyst A6 round 1 + Critic L-NEW-1 round 2.
// Callers MUST go through `makeBreakerScope()` rather than handcraft
// scope strings; passing a string that contains `\x00\x00` would alias
// the boundary marker.
const KEY_SEP = "\x00";

function keyFor(tool: string, scope?: string): string {
  return `${tool}${KEY_SEP}${KEY_SEP}${scope ?? ""}`;
}

function scopeFor(context: ScanContext): string {
  return makeBreakerScope(context.agentId, context.sessionId);
}

/**
 * Build the scope string the circuit breaker uses internally for a
 * given (agentId, sessionId) pair. Exposed so callers of `inspect()`,
 * `trip()`, and `reset()` don't have to know the separator convention.
 *
 * @example
 * ```ts
 * const scope = makeBreakerScope("agent-a", "session-1");
 * const snap = registry.inspect("delete_user", scope);
 * ```
 */
export function makeBreakerScope(
  agentId?: string,
  sessionId?: string,
): string {
  if (agentId && sessionId) {
    return `${agentId}${KEY_SEP}${sessionId}`;
  }
  return agentId ?? sessionId ?? "";
}

function prune(state: InternalState, now: number, windowMs: number): void {
  const cutoff = now - windowMs;
  state.failures = state.failures.filter((t) => t >= cutoff);
  state.calls = state.calls.filter((t) => t >= cutoff);
  state.writes = state.writes.filter((t) => t >= cutoff);
}

function isLikelyDestructive(toolName: string): boolean {
  const lc = toolName.toLowerCase();
  return DESTRUCTIVE_DEFAULTS.some((prefix) => lc.startsWith(prefix));
}
