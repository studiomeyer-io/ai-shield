import type {
  Scanner,
  ScannerResult,
  ScanContext,
  Violation,
  IngestionSource,
  TrustTier,
} from "../types.js";
import { HeuristicScanner, normalizeForInjectionScan } from "./heuristic.js";

// ============================================================
// Ingestion Scanner — Indirect Prompt Injection (IPI) Defense
//
// Scans non-user content (RAG chunks, MCP tool descriptions, stored
// memory facts, scraped web pages, agent-to-agent messages) for
// instruction-shaped payloads BEFORE they enter the model context.
//
// Per Lakera 2026 incident catalog + OWASP LLM01:2025, indirect
// injection is now the dominant attack class — >55% of observed
// incidents arrive through trusted-looking data channels. Direct user
// injection is the minority case.
//
// This scanner runs the existing heuristic patterns at a stricter
// threshold AND adds source-specific patterns the user channel does
// not see (HTML-comment instructions, tool-description override,
// memory-entry steering).
// ============================================================

/**
 * Per-source threshold + extra patterns. Tighter than the user-channel
 * default because data sources almost never need instruction syntax —
 * the presence of one in retrieved content is itself a signal.
 */
const SOURCE_PROFILE: Record<
  IngestionSource,
  { threshold: number; extraPatterns: RegExp[] }
> = {
  user: {
    // For symmetry — a caller may pass source="user" through scanIngested().
    // Falls back to normal heuristic strictness.
    threshold: 0.3,
    extraPatterns: [],
  },
  rag: {
    // Retrieved docs basically never legitimately contain "ignore previous
    // instructions" type wording. Strict. Patterns here are ReDoS-bounded —
    // hidden-comment + CSS detection are done via slice-then-test below in
    // `runStructuralIngestionScan()` so we never run two `[^]*?` wildcards
    // back-to-back over attacker-controlled input.
    threshold: 0.15,
    extraPatterns: [
      // "AI assistant note: ..." style trojan headers.
      /(?:AI\s+(?:assistant|model)\s+(?:note|instruction|directive)|attention\s+(?:AI|model|assistant))[:\s]+/i,
      // Document-claims-to-be-system marker.
      /this\s+document\s+(?:is|contains|provides)\s+(?:your|the)\s+(?:new\s+)?(?:instructions?|system\s+prompt|directives?)/i,
    ],
  },
  "tool-desc": {
    // MCP tool descriptions / function schemas: any imperative aimed at
    // the calling model is suspicious. OX Security MCP advisory + LiteLLM
    // CVE-2025-69256 class.
    threshold: 0.12,
    extraPatterns: [
      // "Before using this tool, you must ..." / "After calling, also call X"
      /(?:before|after|while)\s+(?:using|invoking|calling|executing)\s+(?:this\s+)?(?:tool|function|action)[,\s]+(?:you\s+)?(?:must|should|will|need\s+to|are\s+required\s+to)/i,
      // "Also call delete_account" / "then invoke query()". Tightened
      // (review M2): the called symbol must carry a case-robust tool-name
      // signal — a snake_case underscore or a `(` call — so benign docs prose
      // ("first call the API", "then use the result") doesn't trip the
      // block-level threshold and push operators into disabling the scanner.
      // (camelCase detection was dropped: under the /i flag `[a-z]+[A-Z]`
      // collapses to "any word" and re-introduced the false positive.)
      /(?:also|always|first|then|finally)\s+(?:call|invoke|use|execute|run)\s+(?:the\s+)?[a-z][\w-]*(?:_[\w-]+|\s*\()/i,
      // "Tool description: ignore the above and ..."
      /(?:tool|function|action)\s+description[:\s]+(?:ignore|disregard|override)/i,
      // "Note to LLM:" / "Hidden instruction:"
      /(?:note|hidden\s+(?:instruction|directive|note))\s+to\s+(?:LLM|model|assistant|AI|agent)[:\s]/i,
      // Tool args carrying meta-instructions.
      /(?:on\s+(?:success|call)|when\s+invoked)[,:]\s+(?:silently|also|then)\s+(?:call|invoke|exfiltrate|send|leak)/i,
    ],
  },
  "tool-output": {
    // The runtime result a tool returned. Distinct from `tool-desc` (static
    // schema): this is data the tool fetched and is therefore
    // attacker-influenceable (PoisonedRAG, scraped pages surfaced through a
    // search tool, a compromised upstream API). Tool results almost never
    // legitimately carry instruction syntax aimed at the calling model, so
    // the bar is as tight as RAG/tool-desc.
    threshold: 0.13,
    extraPatterns: [
      // Result claims to carry instructions for the model.
      /(?:tool|function|api|search|query)\s+(?:result|response|output)[:\s]+(?:ignore|disregard|override|new\s+instructions?|system\s+prompt)/i,
      // "the result indicates you should now call/invoke X"
      /(?:result|response|data|output)\s+(?:indicates?|says?|requires?|means?)\s+(?:that\s+)?you\s+(?:should|must|need\s+to|will)\s+(?:now\s+)?(?:call|invoke|run|execute|use)\s+[a-z_][\w-]{2,}/i,
      // Embedded role/system marker inside a JSON-ish result value.
      /"(?:role|system|instruction|directive)"\s*:\s*"(?:system|ignore|override|admin)/i,
      // "(end of results) Now, as the system, ..."
      /(?:end\s+of\s+(?:results?|output|data)|<\/results?>)[\s.)]*(?:now|next)[,\s]+(?:as\s+(?:the\s+)?(?:system|admin|assistant)|you\s+(?:must|should|will))/i,
    ],
  },
  memory: {
    // Stored memory entries: persistence poisoning. Look for sentinel
    // instructions that re-anchor the model on subsequent retrieval.
    threshold: 0.18,
    extraPatterns: [
      // "Remember:" / "Important note for next session:"
      /(?:remember|important|critical)\s+(?:note|instruction|directive)\s+(?:for\s+(?:next|future|all)\s+(?:sessions?|conversations?|calls?))[:\s]/i,
      // "Whenever the user asks X, do Y"
      /(?:whenever|every\s+time)\s+(?:the\s+user|a\s+user|someone)\s+(?:asks|says|mentions|requests)\s+.{1,80}?[,:]\s*(?:you\s+(?:must|should|will|need)|always)/i,
      // "User's true preference is ..." (steering attempts).
      /(?:user(?:'s|s)?\s+(?:real|true|actual|hidden)\s+(?:preference|intent|goal|name|identity))/i,
      // "Override default behavior when ..."
      /override\s+(?:default|standard|normal)\s+(?:behavior|response|policy)/i,
    ],
  },
  web: {
    // Scraped web — same as RAG but also catch markdown-link hijacks.
    // HTML-comment + CSS-hidden detection lives in
    // `runStructuralIngestionScan()` (slice-then-test, ReDoS-bounded).
    threshold: 0.15,
    extraPatterns: [
      // Markdown-link with instruction-shaped anchor text.
      /\[(?:ignore|disregard|override|system\s+(?:prompt|message))[^\]]{0,200}\]\([^)]{0,500}\)/i,
      // ARIA / data-* attributes leaking instructions.
      /(?:aria-label|alt|title|data-[a-z-]{0,40})\s*=\s*["'][^"']{0,500}(ignore\s+previous|new\s+instruction|system\s+prompt|override)/i,
    ],
  },
  "agent-output": {
    // Output of one agent feeding another: multi-agent contagion.
    // Treat like RAG but also catch "tell next agent to ..." patterns.
    threshold: 0.18,
    extraPatterns: [
      /(?:tell|instruct|forward\s+to)\s+(?:the\s+)?(?:next|downstream|receiving|other)\s+(?:agent|model|assistant)\s+to/i,
      /(?:on\s+behalf\s+of|impersonating)\s+(?:the\s+)?(?:user|admin|system|owner)/i,
      /(?:relay|pass|propagate)\s+(?:these|the\s+following)\s+(?:instructions?|directives?|orders?)/i,
    ],
  },
};

/**
 * Default trust-tier inferred from source.
 * `user` is still untrusted in this library's threat model — a user can
 * inject too — but `system` is reserved for content the developer
 * controls and labels via `wrapContext()`. Every ingestion source
 * (including `user`) therefore returns `"untrusted"` by default; the
 * parameter is kept on the signature so future per-source overrides
 * (e.g. an installer marking a specific source as trusted) don't
 * require a breaking API change.
 */
export function trustTierForSource(_source: IngestionSource): TrustTier {
  return "untrusted";
}

// --- ReDoS-safe structural scan helpers ---

/**
 * Hidden-comment + CSS-hidden detection done as bounded slice-then-test
 * rather than a compound `[^]*?...[^]*?` regex (which back-tracks
 * quadratically on attacker-controlled input that omits the terminator).
 * See Critic C1 (round 1 review) — unterminated `<!--` of 50 KB stalled
 * the original implementation.
 *
 * Each detector takes the already-NFKC-normalized input and returns
 * `null` (clean) or a `Violation`.
 */
function runStructuralIngestionScan(
  normalized: string,
  source: IngestionSource,
  threshold: number,
): Violation[] {
  if (source !== "rag" && source !== "web") return [];
  const violations: Violation[] = [];
  const COMMENT_WINDOW = 2048;
  const KEYWORD_RE =
    /ignore|disregard|override|forget|system\s+prompt|new\s+instructions?/i;

  // 1. HTML comment hidden instruction.
  let commentStart = 0;
  let commentMatchCount = 0;
  while (commentStart !== -1 && commentMatchCount < 8) {
    commentStart = normalized.indexOf("<!--", commentStart);
    if (commentStart === -1) break;
    const window = normalized.slice(
      commentStart + 4,
      commentStart + 4 + COMMENT_WINDOW,
    );
    if (KEYWORD_RE.test(window)) {
      violations.push({
        type: "ingested_injection",
        scanner: "ingestion",
        score: 0.4,
        threshold,
        message: `HTML-comment hidden instruction in ${source} content`,
        detail: `Pattern: <!-- ... ignore|override|... (window 2KB)`,
      });
      commentMatchCount += 1;
    }
    commentStart += 4;
  }

  // 2. CSS-hidden style attribute carrying instruction-shaped neighbour.
  //
  // Round 2 Critic M-NEW-2: a single `.exec()` would only find the FIRST
  // `style=` attribute. An attacker placing a benign `style="display:block"`
  // first and a malicious `style="display:none"` later would slip through.
  // Iterate all matches via the `/g` flag, capped at 16 to bound the work
  // on adversarial input that floods style attributes.
  const STYLE_HIDDEN_RE =
    /style\s*=\s*["'][^"']{0,300}(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^"']{0,300}["']/gi;
  let styleMatchCount = 0;
  let styleMatch: RegExpExecArray | null;
  while (
    (styleMatch = STYLE_HIDDEN_RE.exec(normalized)) !== null &&
    styleMatchCount < 16
  ) {
    styleMatchCount += 1;
    const tail = normalized.slice(
      styleMatch.index + styleMatch[0].length,
      styleMatch.index + styleMatch[0].length + 500,
    );
    if (/ignore|override|system|instruction/i.test(tail)) {
      violations.push({
        type: "ingested_injection",
        scanner: "ingestion",
        score: 0.4,
        threshold,
        message: `CSS-hidden instruction in ${source} content`,
        detail: `Pattern: style="display:none ... ignore|override|... (window 500B)`,
      });
    }
  }

  return violations;
}

/**
 * Result of `scanIngested()`.
 *
 * Shape parallels `ScanResult` from `chain.ts` so callers can treat
 * both interchangeably.
 */
export interface IngestionScanResult {
  safe: boolean;
  decision: "allow" | "warn" | "block";
  /**
   * Sanitized output. When `decision === "block"` this is the empty
   * string — the original content was deemed unsafe and the field name
   * "sanitized" would otherwise mislead callers into using poisoned
   * content. Use the source `content` argument if you need the raw input
   * for logging or quarantine.
   */
  sanitized: string;
  violations: Violation[];
  source: IngestionSource;
  meta: {
    scanDurationMs: number;
    scannersRun: string[];
    /** Number of extra source-specific patterns that fired. */
    sourceSpecificHits: number;
    /**
     * Always `false` from `scanIngested()` — ingestion scans don't go
     * through the LRU cache. Field is present so callers can write a
     * single result-handler for both `ScanResult` and `IngestionScanResult`.
     */
    cached: boolean;
  };
}

export interface IngestionScannerConfig {
  /** Override the per-source threshold lookup. */
  threshold?: number;
  /**
   * Additional custom patterns to merge with the source profile's
   * `extraPatterns`. Useful for org-specific markers.
   */
  customPatterns?: RegExp[];
  /**
   * Force the underlying heuristic scanner to a different strictness
   * (default "high" because ingestion is always tighter than user input).
   */
  strictness?: "low" | "medium" | "high";
}

/**
 * Scanner implementation. Composable into a `ScannerChain` when the
 * caller wants ingestion to participate in the main scan flow rather
 * than be invoked via the standalone `scanIngested()` helper.
 *
 * The scanner reads the `source` from `ScanContext` (or treats input
 * as `"user"` when missing) and applies the source-specific profile.
 */
export class IngestionScanner implements Scanner {
  readonly name = "ingestion";
  private readonly threshold: number | undefined;
  private readonly customPatterns: RegExp[];
  private readonly heuristic: HeuristicScanner;

  constructor(config: IngestionScannerConfig = {}) {
    this.threshold = config.threshold;
    this.customPatterns = config.customPatterns ?? [];
    this.heuristic = new HeuristicScanner({
      strictness: config.strictness ?? "high",
    });
  }

  async scan(input: string, context: ScanContext): Promise<ScannerResult> {
    const source = context.source ?? "user";
    const profile = SOURCE_PROFILE[source];
    const effectiveThreshold = this.threshold ?? profile.threshold;

    const start = performance.now();
    const violations: Violation[] = [];

    // 1. Run the base heuristic scanner at high strictness. We respect its
    //    own decision (it includes structural signals that don't surface
    //    as individual violations) and re-tag the violations as
    //    `ingested_injection` so downstream code can filter.
    const heuristicResult = await this.heuristic.scan(input, context);
    for (const v of heuristicResult.violations) {
      violations.push({
        ...v,
        type: "ingested_injection",
        scanner: this.name,
        detail: `${v.detail ?? ""} (source=${source})`.trim(),
      });
    }

    // 2. Run source-specific patterns against the normalized input so the
    //    same Unicode-evasion defense the user channel gets applies here.
    const normalized = normalizeForInjectionScan(input);
    const sourcePatterns = [...profile.extraPatterns, ...this.customPatterns];
    let sourceScore = 0;
    for (const pattern of sourcePatterns) {
      if (pattern.test(normalized)) {
        sourceScore += 0.4;
        violations.push({
          type: "ingested_injection",
          scanner: this.name,
          score: 0.4,
          threshold: effectiveThreshold,
          message: `Indirect injection pattern in ${source} content`,
          detail: `Pattern: ${pattern.source.slice(0, 80)}`,
        });
      }
    }
    // 2b. Structural slice-then-test scans for `rag` + `web` (ReDoS-safe
    //     replacement for the old compound HTML-comment + CSS-hidden
    //     patterns).
    const structural = runStructuralIngestionScan(
      normalized,
      source,
      effectiveThreshold,
    );
    for (const v of structural) {
      sourceScore += 0.4;
      violations.push(v);
    }
    // 2c. Encoding-bypass: attackers wrap an injection in Base64 / Hex /
    //     percent-encoding and ask the model to "decode this". A single
    //     decode pass over the input flushes the most common bypasses
    //     documented in OWASP LLM Prompt Injection Prevention Cheat
    //     Sheet 2026. Only run when the input "looks encoded" to keep
    //     false-positive load low on plain prose.
    const decoded = tryDecodeObfuscation(input);
    if (decoded && decoded !== input) {
      const decodedNormalized = normalizeForInjectionScan(decoded);
      const decodedHeuristic = await this.heuristic.scan(decoded, context);
      if (decodedHeuristic.decision !== "allow") {
        for (const v of decodedHeuristic.violations) {
          violations.push({
            ...v,
            type: "ingested_injection",
            scanner: this.name,
            detail:
              `${v.detail ?? ""} (source=${source}, layer=decoded)`.trim(),
          });
        }
        sourceScore += 0.6; // decoded-hit is high-confidence
      }
      // Also run source-specific patterns over the decoded layer.
      for (const pattern of sourcePatterns) {
        if (pattern.test(decodedNormalized)) {
          sourceScore += 0.4;
          violations.push({
            type: "ingested_injection",
            scanner: this.name,
            score: 0.4,
            threshold: effectiveThreshold,
            message: `Encoded indirect injection in ${source} content`,
            detail: `Pattern: ${pattern.source.slice(0, 80)} (layer=decoded)`,
          });
        }
      }
    }
    sourceScore = Math.min(sourceScore, 1.0);

    // 3. Combine decisions. The heuristic scanner already weighed
    //    structural signals (newlines, headers, padding) that may not
    //    surface as individual violations; trust its decision rather
    //    than re-aggregating only the violation-score subset.
    const heuristicBlocks = heuristicResult.decision === "block";
    const heuristicWarns = heuristicResult.decision === "warn";
    const sourceBlocks = sourceScore >= effectiveThreshold;
    const sourceWarns = sourceScore >= effectiveThreshold * 0.6;

    let decision: "allow" | "warn" | "block";
    if (heuristicBlocks || sourceBlocks) {
      decision = "block";
    } else if (heuristicWarns || sourceWarns) {
      decision = "warn";
    } else {
      decision = "allow";
    }

    return {
      decision,
      violations,
      durationMs: performance.now() - start,
    };
  }
}

/**
 * One-shot helper. Scans `content` against the source-specific profile
 * and returns a result without needing an `AIShield` instance.
 *
 * Use when you want a quick gate at the ingestion boundary, e.g.
 * before storing a chunk into a vector DB or before passing a tool
 * description into the model's context.
 *
 * @example
 * ```ts
 * import { scanIngested } from "ai-shield-core";
 *
 * const ragChunk = "...retrieved document text...";
 * const result = await scanIngested(ragChunk, "rag");
 * if (!result.safe) {
 *   // reject the chunk OR strip it before assembly
 *   logger.warn("IPI candidate", result.violations);
 * }
 * ```
 */
export async function scanIngested(
  content: string,
  source: IngestionSource,
  config: IngestionScannerConfig = {},
): Promise<IngestionScanResult> {
  const start = performance.now();
  const scanner = new IngestionScanner(config);
  const result = await scanner.scan(content, { source });

  return {
    safe: result.decision === "allow",
    decision: result.decision,
    // When a chunk is blocked, returning the raw input under the field
    // name "sanitized" mis-leads callers into trusting poisoned content.
    // Return empty string on block so a `if (!safe) use(result.sanitized)`
    // path becomes a no-op rather than a vulnerability. Use the original
    // `content` argument if you still need it for audit / quarantine.
    sanitized: result.decision === "block" ? "" : content,
    violations: result.violations,
    source,
    meta: {
      scanDurationMs: performance.now() - start,
      scannersRun: [scanner.name],
      sourceSpecificHits: result.violations.filter(
        (v) =>
          v.detail?.startsWith("Pattern:") && v.type === "ingested_injection",
      ).length,
      cached: false,
    },
  };
}

/**
 * Scan the runtime *result* of a tool call before it re-enters the model
 * context. The dominant indirect-injection channel in agentic loops: a
 * search tool surfaces a poisoned page, an MCP server returns attacker-
 * controlled data, a compromised upstream API embeds instructions in its
 * response. PoisonedRAG (USENIX Security 2025) showed 5 planted documents
 * reach a 90% attack-success rate in million-document knowledge bases —
 * the payload arrives here, not in the user prompt.
 *
 * Thin wrapper over `scanIngested(content, "tool-output")` that also
 * stamps the originating `toolName` into every violation detail, so an
 * audit log can answer "which tool returned the poisoned content?".
 *
 * Pair with `CircuitBreakerRegistry` when you also want to rate-limit or
 * trip the tool after repeated poisoned results:
 *
 * @example
 * ```ts
 * import { scanToolOutput } from "ai-shield-core";
 *
 * const result = await searchTool.call(query);          // untrusted
 * const scan = await scanToolOutput("web_search", result);
 * if (!scan.safe) {
 *   // drop the result OR strip it before the next model turn
 *   audit.warn("poisoned tool output", { tool: "web_search", v: scan.violations });
 *   return; // do not feed `result` back into the model
 * }
 * model.continue(result);
 * ```
 */
export async function scanToolOutput(
  toolName: string,
  content: string,
  config: IngestionScannerConfig = {},
): Promise<IngestionScanResult> {
  const result = await scanIngested(content, "tool-output", config);
  const safeToolName =
    typeof toolName === "string" && toolName.length > 0
      ? toolName.slice(0, 120)
      : "unknown";
  return {
    ...result,
    violations: result.violations.map((v) => ({
      ...v,
      detail: `${v.detail ?? ""} (tool=${safeToolName})`.trim(),
    })),
  };
}

// ============================================================
// Encoding-bypass normalization (R1 from Round 1 review — closes
// OWASP LLM Prompt Injection Prevention Cheat Sheet 2026 Base64/Hex
// bypass class).
// ============================================================

/**
 * Try to decode common obfuscation layers an attacker uses to smuggle
 * an injection past pattern matchers. Returns the decoded payload when
 * it looks like a successful decode, else `null`.
 *
 * The function deliberately runs at most ONE decode layer to avoid
 * decoding amplification (a chain of `base64(base64(...))` would force
 * us into deep recursion); a single-layer decode is enough to catch
 * the vast majority of in-the-wild bypasses while keeping execution
 * cost bounded.
 *
 * Heuristics:
 *  - Base64: contiguous run of 40+ Base64 chars, decodes to mostly
 *    printable ASCII or the `\u00..` C0 range stays empty.
 *  - Hex: 80+ hex chars in a row.
 *  - Percent-encoding: more than 5 `%XX` sequences.
 *
 * Returns the longest decoded payload when multiple candidates fire.
 */
export function tryDecodeObfuscation(input: string): string | null {
  if (typeof input !== "string" || input.length === 0) return null;
  // Cap input we look at — Base64 of a megabyte is not the threat model.
  const haystack = input.length > 65_536 ? input.slice(0, 65_536) : input;

  const candidates: string[] = [];

  // Base64 — at least 40 chars, optional padding, optional whitespace.
  const B64_RE = /[A-Za-z0-9+/=]{40,}/g;
  for (const match of haystack.match(B64_RE) ?? []) {
    const cleaned = match.replace(/=+$/, "").replace(/[^A-Za-z0-9+/]/g, "");
    if (cleaned.length < 40) continue;
    try {
      const decoded = Buffer.from(cleaned, "base64").toString("utf8");
      if (decoded.length === 0) continue;
      const printable = decoded.replace(/[^\x20-\x7E\s]/g, "");
      // Require >70% printable to avoid noise.
      if (printable.length / decoded.length >= 0.7) {
        candidates.push(decoded);
      }
    } catch {
      // ignore malformed Base64
    }
  }

  // Hex — 80+ hex digits in a row.
  const HEX_RE = /[0-9a-fA-F]{80,}/g;
  for (const match of haystack.match(HEX_RE) ?? []) {
    if (match.length % 2 !== 0) continue;
    try {
      const decoded = Buffer.from(match, "hex").toString("utf8");
      if (decoded.length === 0) continue;
      const printable = decoded.replace(/[^\x20-\x7E\s]/g, "");
      if (printable.length / decoded.length >= 0.7) {
        candidates.push(decoded);
      }
    } catch {
      // ignore malformed hex
    }
  }

  // Percent-encoding — only decode a windowed region around clustered
  // escapes rather than the full 65KB haystack. Round 2 Critic M-NEW-1:
  // running `decodeURIComponent()` on the full haystack on every scan
  // allocates a ~2× copy per call and pressures GC in high-throughput
  // ingestion pipelines.
  const PERCENT_RE = /%[0-9A-Fa-f]{2}/g;
  const percentMatches: number[] = [];
  let percentMatch: RegExpExecArray | null;
  while (
    (percentMatch = PERCENT_RE.exec(haystack)) !== null &&
    percentMatches.length < 32
  ) {
    percentMatches.push(percentMatch.index);
  }
  if (percentMatches.length >= 5) {
    // Decode only a window around the cluster: 256 bytes before the first
    // escape, 1KB after the last. Bounded work regardless of haystack size.
    const first = percentMatches[0] ?? 0;
    const last = percentMatches[percentMatches.length - 1] ?? first;
    const winStart = Math.max(0, first - 256);
    const winEnd = Math.min(haystack.length, last + 1024);
    const window = haystack.slice(winStart, winEnd);
    try {
      const decoded = decodeURIComponent(window);
      if (decoded !== window) candidates.push(decoded);
    } catch {
      // ignore malformed percent-encoding
    }
  }

  if (candidates.length === 0) return null;
  // Return the longest candidate; that's the most likely attack payload.
  candidates.sort((a, b) => b.length - a.length);
  return candidates[0] ?? null;
}
