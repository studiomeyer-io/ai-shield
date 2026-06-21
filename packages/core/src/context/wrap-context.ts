import type {
  ContextSegment,
  IngestionSource,
  TrustTier,
  WrappedContext,
  ScanContext,
  ScanDecision,
  Violation,
} from "../types.js";
import { createHash } from "node:crypto";
import { IngestionScanner } from "../scanner/ingestion.js";

// ============================================================
// wrapContext — Trust-Tier Context Streams
//
// The deepest finding of the 2026 prompt-injection literature
// (Parallax, IPI surveys, OWASP LLM01:2025) is that the LLM cannot
// reliably distinguish *instruction* from *data* once both share the
// same attention substrate. The only architecturally robust mitigation
// is privilege separation: tag every segment with its provenance + trust
// tier, scan untrusted segments aggressively, and let downstream code
// decide whether instruction-shaped content from a `web`/`rag`/`tool-desc`
// segment is allowed to influence behaviour.
//
// `wrapContext()` is the ergonomic entry point.
// ============================================================

/**
 * Input shape for `wrapContext()`. Each named field is conventional;
 * pass only what applies.
 */
export interface WrapContextInput {
  /** Developer-controlled prompt. Always `trust: "system"`. */
  system?: string;
  /** Direct user message(s). `trust: "untrusted"`, `source: "user"`. */
  user?: string | string[];
  /** Retrieved documents. `trust: "untrusted"`, `source: "rag"`. */
  retrieved?: Array<{ content: string; label?: string } | string>;
  /** MCP / function tool descriptions about to be exposed to the model. */
  tools?: Array<{ content: string; label?: string } | string>;
  /** Stored memory facts. `trust: "untrusted"`, `source: "memory"`. */
  memory?: Array<{ content: string; label?: string } | string>;
  /** Scraped / fetched web content. */
  web?: Array<{ content: string; label?: string } | string>;
  /** Output from another agent (multi-agent pipelines). */
  agentOutput?: Array<{ content: string; label?: string } | string>;
  /**
   * Promote specific named segments to `"trusted"` (e.g. an internal
   * knowledge base whose contents you control end-to-end).
   * Match is by `label` substring, case-insensitive.
   */
  trustedLabels?: string[];
}

/**
 * Build a `WrappedContext` from typed inputs.
 *
 * Trust assignment:
 * - `system` -> system
 * - `retrieved`/`tools`/`memory`/`web`/`agent-output` -> untrusted
 * - `user` -> untrusted (a user is not trusted in this threat model — they
 *   can also inject; the `untrusted` label means "scan aggressively")
 * - any segment whose `label` matches one of `trustedLabels` -> trusted
 *
 * Trust does NOT mean "skip scanning". It only governs how
 * `assemblePrompt()` and the per-segment policy decide whether to
 * include the segment in the final assembled prompt.
 */
export function wrapContext(input: WrapContextInput): WrappedContext {
  const segments: ContextSegment[] = [];
  const trustedLabels = (input.trustedLabels ?? []).map((s) => s.toLowerCase());

  // Critic H1 — substring match would let an attacker-supplied label
  // like "untrusted-doc-INTERNAL-kb-poisoned" claim trust because it
  // CONTAINS the trusted prefix. Match exact or path-anchored only.
  const isTrustedLabel = (label?: string): boolean => {
    if (!label) return false;
    const lc = label.toLowerCase();
    return trustedLabels.some((tl) => lc === tl || lc.startsWith(tl + "/"));
  };

  const push = (
    content: string,
    source: IngestionSource,
    trust: TrustTier,
    label?: string,
  ): void => {
    if (typeof content !== "string" || content.length === 0) return;
    segments.push({
      source,
      trust,
      content,
      label,
      contentHash: hashContent(content),
    });
  };

  // System: always trust=system. The `source` field is unused for
  // system segments because `trust === "system"` is the authoritative
  // signal — Analyst A2 round 1 review. We keep `source: "user"` here
  // only because `ContextSegment.source` is non-optional; any code that
  // branches on `seg.source` MUST first check `seg.trust !== "system"`.
  if (input.system) {
    push(input.system, "user", "system", "system-prompt");
  }

  // User messages.
  if (input.user) {
    const userInputs = Array.isArray(input.user) ? input.user : [input.user];
    for (const u of userInputs) {
      push(u, "user", "untrusted", "user");
    }
  }

  // Helper for the array-of-{content,label} groups.
  const pushGroup = (
    items: Array<{ content: string; label?: string } | string> | undefined,
    source: IngestionSource,
  ): void => {
    if (!items) return;
    for (const item of items) {
      const content = typeof item === "string" ? item : item.content;
      const label = typeof item === "string" ? undefined : item.label;
      const trust: TrustTier = isTrustedLabel(label) ? "trusted" : "untrusted";
      push(content, source, trust, label);
    }
  };

  pushGroup(input.retrieved, "rag");
  pushGroup(input.tools, "tool-desc");
  pushGroup(input.memory, "memory");
  pushGroup(input.web, "web");
  pushGroup(input.agentOutput, "agent-output");

  return { segments };
}

/**
 * Scan every segment with the source-specific ingestion profile.
 * Mutates `ctx` in place by attaching `scanResults` + `decision`,
 * AND returns the same object for chaining.
 */
export async function scanWrappedContext(
  ctx: WrappedContext,
  options: { strictness?: "low" | "medium" | "high" } = {},
): Promise<WrappedContext> {
  const scanner = new IngestionScanner({
    strictness: options.strictness ?? "high",
  });
  const results: NonNullable<WrappedContext["scanResults"]> = [];
  let worst: ScanDecision = "allow";

  for (let i = 0; i < ctx.segments.length; i += 1) {
    const seg = ctx.segments[i]!;
    // System segments skip the scanner — they're developer-authored and
    // running the heuristic over a real system prompt would flood with
    // false positives (system prompts ARE instructions, by definition).
    if (seg.trust === "system") {
      results.push({ segmentIndex: i, decision: "allow", violations: [] });
      continue;
    }

    const scanContext: ScanContext = {
      source: seg.source,
      trustTier: seg.trust,
    };
    const r = await scanner.scan(seg.content, scanContext);
    results.push({
      segmentIndex: i,
      decision: r.decision,
      violations: r.violations,
    });
    if (priority(r.decision) > priority(worst)) {
      worst = r.decision;
    }
  }

  ctx.scanResults = results;
  ctx.decision = worst;
  return ctx;
}

/**
 * Assemble a prompt string respecting tier boundaries.
 *
 * Order: `system` → `trusted` retrieved/memory/tool-desc → `user`
 *      → all remaining `untrusted` segments wrapped in fenced markers.
 *
 * Why `trusted` before `user`? Putting developer-marked trusted
 * context above the user message reduces the chance an untrusted user
 * prompt re-frames the trusted reference material below it.
 *
 * Untrusted segments are wrapped in an explicit fence so a downstream
 * model has a chance to attend to provenance. This is not a guarantee
 * (no in-band marker is) but it is the single highest-leverage
 * mitigation we can apply at the toolkit layer per Anthropic +
 * OpenAI Model Spec guidance.
 *
 * Pass `strictMode: true` to OMIT blocked segments entirely. Default
 * keeps them but fences them with a `<BLOCKED>` marker so an auditor
 * can see what was tried.
 */
export interface AssembleOptions {
  strictMode?: boolean;
  /** Custom fence labels. Defaults are sensible. */
  fences?: {
    untrusted?: { open: string; close: string };
    blocked?: { open: string; close: string };
  };
}

export function assemblePrompt(
  ctx: WrappedContext,
  options: AssembleOptions = {},
): string {
  const fences = {
    untrusted: options.fences?.untrusted ?? {
      open: "<UNTRUSTED_CONTENT source=",
      close: "</UNTRUSTED_CONTENT>",
    },
    blocked: options.fences?.blocked ?? {
      open: "<BLOCKED_CONTENT source=",
      close: "</BLOCKED_CONTENT>",
    },
  };

  // Pre-build a segment→index map ONCE. Avoids O(n²) `indexOf` inside the
  // assembly loop AND removes a TOCTOU on mutable `ctx.segments` (Critic
  // H2 + Analyst A4 round 1 review).
  const segmentIndexMap = new Map<ContextSegment, number>();
  ctx.segments.forEach((s, i) => segmentIndexMap.set(s, i));
  const segmentResultMap = new Map<number, NonNullable<WrappedContext["scanResults"]>[number]>();
  for (const r of ctx.scanResults ?? []) {
    segmentResultMap.set(r.segmentIndex, r);
  }

  const ordered: ContextSegment[] = [];
  // 1. system
  ordered.push(...ctx.segments.filter((s) => s.trust === "system"));
  // 2. trusted (retrieved/memory/tool-desc the dev marked as trusted)
  ordered.push(...ctx.segments.filter((s) => s.trust === "trusted"));
  // 3. user (untrusted, source="user")
  ordered.push(
    ...ctx.segments.filter(
      (s) => s.source === "user" && s.trust === "untrusted",
    ),
  );
  // 4. all remaining untrusted, preserve original order within group.
  for (const s of ctx.segments) {
    if (s.trust === "untrusted" && s.source !== "user") {
      ordered.push(s);
    }
  }

  const parts: string[] = [];
  for (const seg of ordered) {
    const segIdx = segmentIndexMap.get(seg) ?? -1;
    const segResult = segIdx >= 0 ? segmentResultMap.get(segIdx) : undefined;
    const blocked = segResult?.decision === "block";

    if (blocked) {
      if (options.strictMode) {
        // Drop entirely.
        continue;
      }
      parts.push(
        `${fences.blocked.open}"${seg.source}" label="${seg.label ?? ""}">\n${seg.content}\n${fences.blocked.close}`,
      );
      continue;
    }

    if (seg.trust === "system") {
      parts.push(seg.content);
    } else if (seg.trust === "trusted") {
      parts.push(seg.content);
    } else if (seg.source === "user" && seg.trust === "untrusted") {
      // User input keeps its natural shape — fencing every user message
      // creates more noise than signal.
      parts.push(seg.content);
    } else {
      parts.push(
        `${fences.untrusted.open}"${seg.source}" label="${seg.label ?? ""}">\n${seg.content}\n${fences.untrusted.close}`,
      );
    }
  }

  return parts.join("\n\n");
}

function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function priority(d: ScanDecision): number {
  return d === "block" ? 2 : d === "warn" ? 1 : 0;
}

/**
 * Convenience aggregator: violations across all scanned segments.
 */
export function flattenViolations(ctx: WrappedContext): Violation[] {
  if (!ctx.scanResults) return [];
  return ctx.scanResults.flatMap((r) => r.violations);
}

// ============================================================
// propagateTrust — Multi-Agent Trust Propagation
//
// In a multi-agent pipeline one agent's output becomes the next agent's
// input. A successful injection in agent A propagates: A summarizes a
// poisoned document, B reads A's summary and decides, C executes. The
// 2026 literature calls this multi-agent contagion — and the standard
// in-context defenses share an attention substrate with the payload, so
// the only robust handling is to track trust ACROSS the chain and refuse
// to let a downstream agent treat upstream output as trusted once any
// link is contaminated.
//
// `propagateTrust()` scans one hop (A → B) as `agent-output`, degrades
// the effective trust tier on any warn/block, and keeps contamination
// "sticky": pass the returned `hops` back as `priorChain` for the next
// link so a poisoning at A still marks the C-hop as contaminated even if
// C's own payload looks clean.
// ============================================================

export interface AgentHop {
  /** The agent that PRODUCED the payload entering this hop. */
  agentId: string;
  /** Trust tier the payload was treated as at this hop. */
  trust: TrustTier;
  /** Scan decision for this hop's payload. */
  decision: ScanDecision;
  /** Violations found at this hop. */
  violations: Violation[];
}

export interface PropagateTrustOptions {
  /**
   * Trust tier of the producing agent's output. Defaults to `untrusted` —
   * agent output is attacker-influenceable by construction. Only set to
   * `trusted` for an agent whose output you control end-to-end.
   */
  fromTrust?: TrustTier;
  /**
   * Chain returned by an earlier `propagateTrust()` call. Pass it to keep
   * contamination sticky across A→B→C. Omit for the first link.
   */
  priorChain?: AgentHop[];
  /** Ingestion-scanner strictness for the contagion scan. Default `high`. */
  strictness?: "low" | "medium" | "high";
}

export interface TrustPropagationResult {
  /** No contamination anywhere in the chain (including prior hops). */
  safe: boolean;
  /** Worst decision across the whole chain — sticky (once block, stays). */
  decision: ScanDecision;
  /**
   * Trust tier the RECEIVING agent should treat the payload as. Degrades to
   * `untrusted` the moment this hop — or any prior hop — warns or blocks.
   */
  effectiveTrust: TrustTier;
  /** Full chain including this hop. Feed back as `priorChain` for the next. */
  hops: AgentHop[];
  /** Every violation across the chain, newest hop last. */
  violations: Violation[];
}

/**
 * Scan one agent-to-agent hand-off and propagate trust along the chain.
 *
 * @param payload      The producing agent's output (= consuming agent's input).
 * @param fromAgentId  Agent that produced `payload`.
 * @param toAgentId    Agent about to consume `payload`.
 *
 * @example
 * ```ts
 * import { propagateTrust } from "ai-shield-core";
 *
 * // A → B
 * let chain = await propagateTrust(aOutput, "researcher", "planner");
 * // B → C, contamination at A stays sticky through to C
 * chain = await propagateTrust(bOutput, "planner", "executor", {
 *   priorChain: chain.hops,
 * });
 * if (chain.effectiveTrust !== "trusted" && !chain.safe) {
 *   // an upstream agent was poisoned — do not let the executor act on it
 *   haltPipeline(chain.violations);
 * }
 * ```
 */
export async function propagateTrust(
  payload: string,
  fromAgentId: string,
  toAgentId: string,
  options: PropagateTrustOptions = {},
): Promise<TrustPropagationResult> {
  const fromTrust = options.fromTrust ?? "untrusted";
  const priorChain = options.priorChain ?? [];

  const scanner = new IngestionScanner({
    strictness: options.strictness ?? "high",
  });
  const scanContext: ScanContext = {
    source: "agent-output",
    trustTier: fromTrust,
    agentId: fromAgentId,
  };
  const scan = await scanner.scan(payload, scanContext);

  const hopViolations: Violation[] = scan.violations.map((v) => ({
    ...v,
    detail: `${v.detail ?? ""} (${fromAgentId}→${toAgentId})`.trim(),
  }));

  // Was anything upstream already contaminated?
  const upstreamWorst = priorChain.reduce<ScanDecision>(
    (worst, h) => (priority(h.decision) > priority(worst) ? h.decision : worst),
    "allow",
  );
  const upstreamContaminated = upstreamWorst !== "allow";

  // This hop's own decision.
  const hopDecision = scan.decision;

  // Make contamination explicit as a multi-agent violation (distinct from
  // the per-segment `ingested_injection` the scanner already produced).
  if (hopDecision !== "allow") {
    hopViolations.push({
      type: "trust_propagation",
      scanner: "trust-chain",
      score: hopDecision === "block" ? 1.0 : 0.5,
      threshold: 0.5,
      message: `Contagion risk in hand-off ${fromAgentId}→${toAgentId}`,
      detail: `Agent output flagged at this hop`,
    });
  } else if (upstreamContaminated) {
    hopViolations.push({
      type: "trust_propagation",
      scanner: "trust-chain",
      score: 0.5,
      threshold: 0.5,
      message: `Payload reaching ${toAgentId} originates from a contaminated chain`,
      detail: `Upstream contamination is sticky across hops`,
    });
  }

  const hop: AgentHop = {
    agentId: fromAgentId,
    trust: fromTrust,
    decision: hopDecision,
    violations: hopViolations,
  };
  const hops = [...priorChain, hop];

  // Worst decision across the full chain (sticky).
  const chainDecision: ScanDecision =
    priority(hopDecision) >= priority(upstreamWorst)
      ? hopDecision
      : upstreamWorst;

  // Effective trust degrades to untrusted on ANY contamination in the chain.
  // A clean hand-off from a `trusted` agent with a clean chain stays trusted.
  const effectiveTrust: TrustTier =
    chainDecision === "allow" && fromTrust === "trusted"
      ? "trusted"
      : "untrusted";

  return {
    safe: chainDecision === "allow",
    decision: chainDecision,
    effectiveTrust,
    hops,
    violations: hops.flatMap((h) => h.violations),
  };
}
