import type {
  ScanContext,
  ScanDecision,
  Violation,
  PIIConfig,
} from "../types.js";
import { PIIScanner } from "./pii.js";
import { normalizeForInjectionScan } from "./heuristic.js";

// ============================================================
// Output Scanner — OWASP LLM05 Improper Output Handling +
// LLM02 Sensitive Information Disclosure (output side)
//
// AI Shield's input scanners answer "is this prompt safe to send to the
// model?". This scanner answers the other half: "is this model OUTPUT
// safe to act on / show / forward downstream?".
//
// LLM output must never reach a SQL engine, a shell, an HTML sink, or a
// template renderer unfiltered — XSS, SSRF, SQLi and command injection
// sourced from model output are a documented 2026 attack class (OWASP
// LLM05). And a model can leak its own system prompt or a secret it was
// shown, which is LLM02 / LLM07.
//
// Five checks. Inputs are Unicode-normalized first (homoglyph / zero-width /
// fullwidth evasion defense). Secret + canary checks scan the FULL output
// (a leak can sit anywhere); the structural checks scan a length-capped copy
// (those payloads live in the first chunk):
//   1. secret_leak        — API keys, tokens, private keys, DSNs (full output)
//   2. output_injection   — SQL / shell / HTML-JS / template / md-exfil (capped)
//   3. system_prompt_leak — canary-token leak (exact, full) + heuristic phrasing
//   4. pii_detected       — reuses the input-side PIIScanner
//   5. jailbreak_indicator— compliance-preamble / mode-switch acknowledgement
//
// Checks 1-3 are high-confidence and block. PII follows its configured
// action. Jailbreak is heuristic and only warns — a "sure, here's how"
// preamble is often legitimate.
// ============================================================

/** Hard cap on the bytes we pattern-scan. A 1 MB model response is not the
 *  threat model and unbounded regex over it pressures GC. Overridable. */
const DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024;

/**
 * High-confidence secret formats. Each is anchored on a provider-specific
 * prefix so false positives on prose are near-zero. Patterns are linear
 * (no nested quantifiers) — ReDoS-safe on large output.
 */
const SECRET_PATTERNS: Array<{ id: string; re: RegExp; label: string }> = [
  { id: "SEC-OPENAI", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/, label: "OpenAI API key" },
  { id: "SEC-ANTHROPIC", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, label: "Anthropic API key" },
  { id: "SEC-AWS-AKID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, label: "AWS access key id" },
  { id: "SEC-GITHUB", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, label: "GitHub token" },
  { id: "SEC-GOOGLE", re: /\bAIza[0-9A-Za-z_-]{35}\b/, label: "Google API key" },
  { id: "SEC-GOOGLE-OAUTH", re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/, label: "Google OAuth client secret" },
  { id: "SEC-GCP-SA", re: /"type"\s*:\s*"service_account"/, label: "GCP service-account JSON" },
  { id: "SEC-HUGGINGFACE", re: /\bhf_[A-Za-z0-9]{30,}\b/, label: "HuggingFace token" },
  { id: "SEC-NPM", re: /\bnpm_[A-Za-z0-9]{36}\b/, label: "npm publish token" },
  { id: "SEC-SLACK", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: "Slack token" },
  { id: "SEC-STRIPE", re: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/, label: "Stripe live key" },
  { id: "SEC-JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, label: "JWT" },
  { id: "SEC-PEM", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, label: "PEM private key" },
  // DSN: both credential segments are length-bounded so a long near-match
  // without a trailing `@` can't drive O(n²) backtracking (review H1).
  { id: "SEC-DSN", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:/@]{1,64}:[^\s@]{3,80}@/, label: "connection string with credentials" },
];

/**
 * Output-injection payloads, grouped by downstream sink. Each pattern is
 * deliberately conservative — flagging legitimate output that merely
 * *mentions* SQL would be useless. They target syntax that only matters
 * when the string is interpreted, not displayed.
 */
const INJECTION_PATTERNS: Array<{
  id: string;
  sink: OutputSink;
  re: RegExp;
  label: string;
}> = [
  // SQL
  { id: "OUTI-SQL-1", sink: "sql", re: /\bunion\s+(?:all\s+)?select\b/i, label: "SQL UNION SELECT" },
  { id: "OUTI-SQL-2", sink: "sql", re: /['"]\s*;\s*(?:drop|delete|update|insert|truncate|alter)\s+/i, label: "SQL statement break" },
  { id: "OUTI-SQL-3", sink: "sql", re: /\bor\s+1\s*=\s*1\b|\bor\s+'1'\s*=\s*'1'/i, label: "SQL tautology" },
  // Shell
  { id: "OUTI-SH-1", sink: "shell", re: /\$\([^)]{1,200}\)|`[^`]{1,200}`/, label: "shell command substitution" },
  { id: "OUTI-SH-2", sink: "shell", re: /[;&|]\s*(?:rm|curl|wget|nc|bash|sh|chmod|mkfifo|dd)\s+-?/i, label: "chained shell command" },
  { id: "OUTI-SH-3", sink: "shell", re: /\|\s*(?:sh|bash|zsh|python[0-9.]*)\b/i, label: "pipe to interpreter" },
  // HTML / JS (XSS)
  { id: "OUTI-XSS-1", sink: "html", re: /<script[\s>]/i, label: "<script> tag" },
  { id: "OUTI-XSS-2", sink: "html", re: /\bon(?:error|load|click|mouseover)\s*=\s*["']?[^"'>]{1,200}/i, label: "inline event handler" },
  { id: "OUTI-XSS-3", sink: "html", re: /\bjavascript:\s*[^\s"']{1,200}/i, label: "javascript: URI" },
  { id: "OUTI-XSS-4", sink: "html", re: /<iframe[\s>]|<img[^>]{0,200}\bsrc\s*=\s*["']?\s*(?:javascript|data):/i, label: "iframe / data-URI image" },
  // Markdown-image data exfiltration: ![x](http://evil/log?data=…). When a
  // renderer auto-loads the image the query string leaks whatever the model
  // was told to embed. The most-overlooked LLM05 class (review: Research).
  { id: "OUTI-MDEXF", sink: "html", re: /!\[[^\]]{0,200}\]\(\s*https?:\/\/[^)\s]{1,300}[?&][\w-]{1,40}=/i, label: "markdown-image data exfiltration" },
  // Template / SSTI
  { id: "OUTI-SSTI-1", sink: "template", re: /\{\{[^}]{0,200}(?:constructor|process|require|global|__proto__|self\.|cycler)[^}]{0,200}\}\}/i, label: "template-injection payload" },
  { id: "OUTI-SSTI-2", sink: "template", re: /<%[^%]{0,200}(?:system|exec|require|eval)[^%]{0,200}%>/i, label: "ERB/EJS injection" },
];

/**
 * System-prompt-leak heuristics — used only when no canary token is
 * available. Low-confidence by design (these phrasings occur in benign
 * output too), so they warn rather than block.
 */
const SYSTEM_LEAK_PATTERNS: RegExp[] = [
  /(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|say|states?|read)\b/i,
  /i\s+(?:was|am|have\s+been)\s+(?:instructed|told|configured|programmed|designed)\s+to\b/i,
  /here\s+(?:is|are)\s+my\s+(?:system\s+)?(?:prompt|instructions?|guidelines?|rules?)\b/i,
  /you\s+are\s+(?:a|an)\s+[\w-]{2,30}\s+(?:assistant|agent|bot|model)\b.{0,40}\b(?:you\s+must|your\s+(?:rules?|guidelines?|instructions?))/i,
];

/**
 * Jailbreak-success indicators in the OUTPUT. Conservative + low weight:
 * a generic "Sure, here's how" is not enough on its own — these target
 * explicit mode-switch acknowledgements and self-declared rule-breaking.
 */
const JAILBREAK_PATTERNS: RegExp[] = [
  /\bas\s+(?:DAN|an?\s+(?:unrestricted|unfiltered|jailbroken|uncensored))\b/i,
  /i(?:'?ll|\s+will)\s+(?:now\s+)?(?:ignore|bypass|disregard|set\s+aside)\s+(?:my|the|all)\s+(?:guidelines?|restrictions?|rules?|safety|programming|filters?)/i,
  /(?:jailbreak|developer\s+mode|dan\s+mode)\s+(?:enabled|activated|successful|engaged)/i,
  /i\s+am\s+(?:now\s+)?(?:free\s+(?:from|of)|no\s+longer\s+bound\s+by)\s+(?:my\s+)?(?:restrictions?|guidelines?|rules?|programming)/i,
];

export type OutputSink = "sql" | "shell" | "html" | "template";

export interface OutputScanConfig {
  /**
   * PII handling. Pass a `PIIConfig` to control action/locale, or `false`
   * to skip PII scanning entirely. Default: mask.
   */
  pii?: PIIConfig | false;
  /**
   * Canary token(s) injected into the system prompt via `injectCanary()`.
   * If any appears verbatim in the output → `system_prompt_leak` (block).
   */
  canaryTokens?: string | string[];
  /**
   * Restrict the structured-injection check to specific downstream sinks.
   * E.g. `["sql"]` when the output only ever flows into a query builder.
   * Default: all sinks.
   */
  sinks?: OutputSink[];
  /** Selectively disable checks. All enabled by default. */
  checks?: {
    secrets?: boolean;
    injection?: boolean;
    systemPromptLeak?: boolean;
    jailbreak?: boolean;
  };
  /** Override the byte cap on the scanned region. Default 256 KB. */
  maxBytes?: number;
}

export interface OutputScanResult {
  /** No blocking violation found. */
  safe: boolean;
  decision: ScanDecision;
  /**
   * Output with PII masked and secrets redacted to `[REDACTED_SECRET]`.
   * Unlike `scanIngested`, this is NOT emptied on block — the caller
   * usually still needs to log or display the sanitized text. Gate on
   * `safe` / `decision` before forwarding it to a downstream sink.
   */
  sanitized: string;
  violations: Violation[];
  meta: {
    scanDurationMs: number;
    checksRun: string[];
  };
}

const SECRET_REDACTION = "[REDACTED_SECRET]";

/**
 * Scanner for LLM output. Stateless; safe to reuse across calls.
 */
export class OutputScanner {
  private readonly config: OutputScanConfig;
  private readonly pii: PIIScanner | null;

  constructor(config: OutputScanConfig = {}) {
    this.config = config;
    this.pii =
      config.pii === false
        ? null
        : new PIIScanner(config.pii ?? { action: "mask" });
  }

  async scan(
    output: string,
    context: ScanContext = {},
  ): Promise<OutputScanResult> {
    const start = performance.now();
    const violations: Violation[] = [];
    const checksRun: string[] = [];
    const checks = this.config.checks ?? {};
    const maxBytes = this.config.maxBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

    const safeOutput = typeof output === "string" ? output : "";

    // Capped copy for the *structural* checks (injection / leak-phrasing /
    // jailbreak) — those payloads live in the first chunk and the regex over
    // a 1 MB response would pressure GC. Normalized so homoglyph / zero-width
    // / fullwidth evasion can't slip a payload past the patterns (review H6).
    const cappedDetect = normalizeForInjectionScan(
      safeOutput.length > maxBytes ? safeOutput.slice(0, maxBytes) : safeOutput,
    );

    // Secrets and canaries can sit ANYWHERE in the output, and the secret
    // patterns are anchored + linear — so they scan the FULL output, not the
    // cap (review C1: a key padded past 256 KB must not slip through). Also
    // normalized for the same evasion defense.
    const fullDetect = normalizeForInjectionScan(safeOutput);

    let sanitized = output;
    let worst: ScanDecision = "allow";
    const bump = (d: ScanDecision): void => {
      if (priority(d) > priority(worst)) worst = d;
    };

    // 1. Secret leak — high-confidence, always blocks. Detection runs on the
    //    normalized full output (so a key fragmented by zero-width / homoglyph
    //    chars is still flagged), and redaction MUST guarantee the live secret
    //    never survives in `sanitized` — not just best-effort.
    if (checks.secrets !== false) {
      checksRun.push("secrets");
      const matchedSecretREs: RegExp[] = [];
      for (const { id, re, label } of SECRET_PATTERNS) {
        if (re.test(fullDetect)) {
          violations.push({
            type: "secret_leak",
            scanner: "output",
            score: 1.0,
            threshold: 0.5,
            message: `Output leaks a secret: ${label}`,
            detail: `Rule ${id}`,
          });
          bump("block");
          matchedSecretREs.push(re);
          // First pass: redact every occurrence in the raw output. This is the
          // clean case and preserves the surrounding formatting.
          sanitized = sanitized.replace(globalCopy(re), SECRET_REDACTION);
        }
      }
      // Scrub-on-block guarantee: detection saw the secret in the NORMALIZED
      // text, but the raw `.replace()` above can miss a key that was split by
      // invisible chars ("sk-ant-...<ZWSP>...") — the raw form doesn't match
      // the anchored pattern, so the live key would survive in `sanitized`.
      // If any matched pattern still hits the normalized sanitized output, the
      // evasion-split key got through: strip the zero-width chars (they are
      // invisible, so this never alters how benign text reads) so the key
      // collapses, then redact again. The result: `sanitized` is free of the
      // live secret regardless of the evasion used.
      if (matchedSecretREs.length > 0) {
        const stillLeaks = (): boolean =>
          matchedSecretREs.some((re) =>
            re.test(normalizeForInjectionScan(sanitized)),
          );
        if (stillLeaks()) {
          sanitized = stripZeroWidth(sanitized);
          for (const re of matchedSecretREs) {
            sanitized = sanitized.replace(globalCopy(re), SECRET_REDACTION);
          }
        }
      }
    }

    // 2. Output injection — payloads dangerous to a downstream sink.
    if (checks.injection !== false) {
      checksRun.push("injection");
      const allowedSinks = this.config.sinks;
      for (const { id, sink, re, label } of INJECTION_PATTERNS) {
        if (allowedSinks && !allowedSinks.includes(sink)) continue;
        if (re.test(cappedDetect)) {
          violations.push({
            type: "output_injection",
            scanner: "output",
            score: 0.85,
            threshold: 0.5,
            message: `Output carries a ${sink} injection payload: ${label}`,
            detail: `Rule ${id} (sink=${sink})`,
          });
          bump("block");
        }
      }
    }

    // 3. System-prompt leak — canary first (exact, certain), then heuristics.
    if (checks.systemPromptLeak !== false) {
      checksRun.push("system_prompt_leak");
      const tokens = normalizeTokens(this.config.canaryTokens);
      let canaryHit = false;
      for (const token of tokens) {
        // Check the FULL output, not the capped copy — a leak past 256 KB is
        // still a leak, and an exact substring search is cheap.
        if (token.length >= 4 && output.includes(token)) {
          canaryHit = true;
          violations.push({
            type: "system_prompt_leak",
            scanner: "output",
            score: 1.0,
            threshold: 0.5,
            message: "Output leaks a system-prompt canary token",
            detail: "Canary match (exact)",
          });
          bump("block");
        }
      }
      // Heuristic phrasing only when no canary was available/hit — avoids
      // double-reporting and keeps the low-confidence signal subordinate.
      if (!canaryHit && tokens.length === 0) {
        for (const re of SYSTEM_LEAK_PATTERNS) {
          if (re.test(cappedDetect)) {
            violations.push({
              type: "system_prompt_leak",
              scanner: "output",
              score: 0.4,
              threshold: 0.5,
              message: "Output may be echoing the system prompt",
              detail: "Heuristic phrasing (no canary configured — pass canaryTokens for an exact check)",
            });
            bump("warn");
            break; // one heuristic signal is enough
          }
        }
      }
    }

    // 4. Jailbreak indicators — heuristic, warn only.
    if (checks.jailbreak !== false) {
      checksRun.push("jailbreak");
      for (const re of JAILBREAK_PATTERNS) {
        if (re.test(cappedDetect)) {
          violations.push({
            type: "jailbreak_indicator",
            scanner: "output",
            score: 0.3,
            threshold: 0.5,
            message: "Output shows a possible jailbreak success indicator",
            detail: "Heuristic phrasing",
          });
          bump("warn");
          break;
        }
      }
    }

    // 5. PII — reuse the input-side scanner; respects its configured action.
    if (this.pii) {
      checksRun.push("pii");
      const piiResult = await this.pii.scan(sanitized, context);
      for (const v of piiResult.violations) {
        violations.push({ ...v, scanner: "output" });
      }
      if (piiResult.sanitized !== undefined) sanitized = piiResult.sanitized;
      bump(piiResult.decision);
    }

    return {
      safe: worst === "allow",
      decision: worst,
      sanitized,
      violations,
      meta: {
        scanDurationMs: performance.now() - start,
        checksRun,
      },
    };
  }
}

/**
 * One-shot helper. Scan a model response before acting on it.
 *
 * @example
 * ```ts
 * import { scanOutput } from "ai-shield-core";
 *
 * const reply = await llm.generate(prompt);
 * const r = await scanOutput(reply, { canaryTokens: canary, sinks: ["sql"] });
 * if (!r.safe) {
 *   audit.warn("unsafe model output", r.violations);
 *   return genericFallback();           // do not run r.sanitized as SQL
 * }
 * showToUser(r.sanitized);              // PII masked, secrets redacted
 * ```
 */
export async function scanOutput(
  output: string,
  config: OutputScanConfig = {},
  context: ScanContext = {},
): Promise<OutputScanResult> {
  return new OutputScanner(config).scan(output, context);
}

function normalizeTokens(tokens?: string | string[]): string[] {
  if (!tokens) return [];
  const arr = Array.isArray(tokens) ? tokens : [tokens];
  return arr.filter((t): t is string => typeof t === "string" && t.length > 0);
}

function priority(d: ScanDecision): number {
  return d === "block" ? 2 : d === "warn" ? 1 : 0;
}

/** Return a global-flagged copy of `re` (idempotent if already global). */
function globalCopy(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
}

// Zero-width / BOM chars (U+200B..U+200D, U+2060, U+FEFF) used to fragment a
// secret across a pattern boundary. Stripping them is safe in `sanitized`
// because they render as nothing — benign visible text is unaffected.
const OUTPUT_ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF]/g;
function stripZeroWidth(s: string): string {
  return s.replace(OUTPUT_ZERO_WIDTH_RE, "");
}
