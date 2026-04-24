import type { Scanner, ScannerResult, ScanContext, Violation } from "../types.js";

// ============================================================
// Heuristic Prompt Injection Scanner
// Score-based: multiple matches = higher confidence
// Unicode-normalizes input before pattern matching so that
// homoglyph/zero-width/fullwidth evasion attempts still hit.
// ============================================================

// Common Cyrillic/Greek Latin-lookalikes mapped to ASCII.
// Keep minimal — false-mappings in real content are worse than
// false-negatives in an attack attempt.
const HOMOGLYPH_MAP: Record<string, string> = {
  "а": "a", "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p", "с": "c", "ѕ": "s",
  "у": "y", "х": "x", "А": "A", "В": "B", "Е": "E", "І": "I", "К": "K", "М": "M",
  "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
  "α": "a", "ο": "o", "ρ": "p", "ε": "e", "υ": "y", "χ": "x", "Α": "A", "Β": "B",
  "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
  "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
};

const HOMOGLYPH_RE = new RegExp(Object.keys(HOMOGLYPH_MAP).join("|"), "g");
// Zero-width chars + BOM — used to split words like "ig<ZWSP>nore" across
// the pattern boundary (U+200B..U+200D, U+2060, U+FEFF).
const ZERO_WIDTH_RE = /[​-‍⁠﻿]/g;
// Combining marks (diacritics) after NFKC can still slip through (U+0300..U+036F).
const COMBINING_RE = /[̀-ͯ]/g;

/**
 * Normalize input for pattern matching. Returns the canonicalized string
 * used only for scan decisions; the sanitized output passed to callers
 * is still the original input.
 *
 * Order matters:
 * 1. NFKD folds compatibility forms (fullwidth → ASCII, ligatures) AND
 *    decomposes precomposed accented letters into base + combining mark.
 * 2. Strip zero-width chars so "ig<ZWSP>nore" collapses to "ignore".
 * 3. Strip combining marks (diacritics) left behind by NFKD.
 * 4. Map remaining Cyrillic/Greek look-alikes to Latin.
 */
export function normalizeForInjectionScan(input: string): string {
  const nfkd = input.normalize("NFKD");
  const noZW = nfkd.replace(ZERO_WIDTH_RE, "");
  const noCombining = noZW.replace(COMBINING_RE, "");
  return noCombining.replace(HOMOGLYPH_RE, (ch) => HOMOGLYPH_MAP[ch] ?? ch);
}

interface PatternRule {
  id: string;
  category: InjectionCategory;
  pattern: RegExp;
  weight: number;
  description: string;
}

type InjectionCategory =
  | "instruction_override"
  | "role_manipulation"
  | "system_prompt_extraction"
  | "encoding_evasion"
  | "delimiter_injection"
  | "context_manipulation"
  | "output_manipulation"
  | "tool_abuse";

const PATTERNS: PatternRule[] = [
  // --- Instruction Override (weight: 0.25 each) ---
  {
    id: "INJ-001",
    category: "instruction_override",
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|guidelines?|context)/i,
    weight: 0.25,
    description: "Ignore previous instructions",
  },
  {
    id: "INJ-002",
    category: "instruction_override",
    pattern: /disregard\s+(all\s+|your\s+)?(previous|prior|above|earlier)\s+(instructions?|context|rules?|guidelines?)/i,
    weight: 0.25,
    description: "Disregard instructions",
  },
  {
    id: "INJ-003",
    category: "instruction_override",
    pattern: /forget\s+(everything|all|your)\s+(about\s+)?(instructions?|rules?|training|guidelines?|constraints?)/i,
    weight: 0.25,
    description: "Forget instructions",
  },
  {
    id: "INJ-004",
    category: "instruction_override",
    pattern: /override\s+(your|the|all)\s+(instructions?|rules?|safety|guidelines?|constraints?|policies)/i,
    weight: 0.25,
    description: "Override instructions",
  },
  {
    id: "INJ-005",
    category: "instruction_override",
    pattern: /do\s+not\s+follow\s+(your|the|any)\s+(previous|original|initial)\s+(instructions?|rules?|guidelines?)/i,
    weight: 0.25,
    description: "Do not follow instructions",
  },
  {
    id: "INJ-006",
    category: "instruction_override",
    pattern: /new\s+(instructions?|rules?|guidelines?)[\s:]+/i,
    weight: 0.15,
    description: "New instructions prefix",
  },
  {
    id: "INJ-007",
    category: "instruction_override",
    pattern: /from\s+now\s+on[,\s]+(you\s+)?(will|must|should|are|shall)/i,
    weight: 0.20,
    description: "From now on directive",
  },
  {
    id: "INJ-008",
    category: "instruction_override",
    pattern: /instead[,\s]+(you\s+)?(will|must|should|shall)\s+/i,
    weight: 0.15,
    description: "Instead directive",
  },

  // --- Role Manipulation (weight: 0.25 each) ---
  {
    id: "ROLE-001",
    category: "role_manipulation",
    pattern: /you\s+are\s+now\s+(a|an|the|my)\s+/i,
    weight: 0.25,
    description: "You are now [role]",
  },
  {
    id: "ROLE-002",
    category: "role_manipulation",
    pattern: /pretend\s+(you('re|\s+are)\s+|to\s+be\s+)/i,
    weight: 0.25,
    description: "Pretend to be",
  },
  {
    id: "ROLE-003",
    category: "role_manipulation",
    pattern: /act\s+as\s+(a|an|if\s+you\s+were)\s+/i,
    weight: 0.20,
    description: "Act as [role]",
  },
  {
    id: "ROLE-004",
    category: "role_manipulation",
    pattern: /switch\s+to\s+.{0,30}\s+mode/i,
    weight: 0.25,
    description: "Switch to [X] mode",
  },
  {
    id: "ROLE-005",
    category: "role_manipulation",
    pattern: /enter\s+(developer|debug|admin|god|sudo|root|jailbreak|DAN)\s+mode/i,
    weight: 0.35,
    description: "Enter privileged mode",
  },
  {
    id: "ROLE-006",
    category: "role_manipulation",
    pattern: /you\s+have\s+no\s+(restrictions?|limitations?|rules?|constraints?|filters?)/i,
    weight: 0.30,
    description: "No restrictions claim",
  },
  {
    id: "ROLE-007",
    category: "role_manipulation",
    pattern: /\bDAN\b.*\b(do\s+anything|no\s+(restrictions?|limits?|filters?))/i,
    weight: 0.35,
    description: "DAN jailbreak pattern",
  },

  // --- System Prompt Extraction (weight: 0.30 each) ---
  {
    id: "EXTRACT-001",
    category: "system_prompt_extraction",
    pattern: /what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|directives?)/i,
    weight: 0.30,
    description: "What is your system prompt",
  },
  {
    id: "EXTRACT-002",
    category: "system_prompt_extraction",
    pattern: /show\s+(me\s+)?your\s+(system\s+)?(prompt|instructions?|config(uration)?|rules?)/i,
    weight: 0.30,
    description: "Show your prompt",
  },
  {
    id: "EXTRACT-003",
    category: "system_prompt_extraction",
    pattern: /repeat\s+(the|your)\s+(system\s+|initial\s+|original\s+)?(prompt|instructions?|message|rules?)\s*(word\s+for\s+word|verbatim|exactly)?/i,
    weight: 0.30,
    description: "Repeat your prompt",
  },
  {
    id: "EXTRACT-004",
    category: "system_prompt_extraction",
    pattern: /output\s+(the|your)\s+(initial|system|original|first)\s+(prompt|instructions?|message)/i,
    weight: 0.30,
    description: "Output initial prompt",
  },
  {
    id: "EXTRACT-005",
    category: "system_prompt_extraction",
    pattern: /print\s+(your|the)\s+(system\s+)?(prompt|instructions?|configuration)/i,
    weight: 0.30,
    description: "Print system prompt",
  },
  {
    id: "EXTRACT-006",
    category: "system_prompt_extraction",
    pattern: /tell\s+me\s+(your|the)\s+(exact\s+)?(system\s+)?(prompt|instructions?|wording)/i,
    weight: 0.30,
    description: "Tell me your prompt",
  },
  {
    id: "EXTRACT-007",
    category: "system_prompt_extraction",
    pattern: /copy\s+(and\s+)?(paste|output)\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
    weight: 0.30,
    description: "Copy paste your prompt",
  },

  // --- Encoding Evasion (weight: 0.20 each) ---
  {
    id: "ENCODE-001",
    category: "encoding_evasion",
    pattern: /(?:decode|translate|convert|interpret)\s+(?:this|the\s+following)\s+(?:from\s+)?(?:base64|rot13|hex|binary|morse|unicode|ascii|url.?encoded)/i,
    weight: 0.20,
    description: "Decode from encoding",
  },
  {
    id: "ENCODE-002",
    category: "encoding_evasion",
    pattern: /(?:execute|follow|obey|run)\s+(?:the\s+)?(?:decoded|hidden|encoded|secret)\s+(?:instructions?|commands?|text)/i,
    weight: 0.30,
    description: "Execute decoded instructions",
  },
  {
    id: "ENCODE-003",
    category: "encoding_evasion",
    pattern: /[A-Za-z0-9+/]{50,}={0,2}/,
    weight: 0.10,
    description: "Long Base64 string detected",
  },

  // --- Delimiter Injection (weight: 0.25 each) ---
  {
    id: "DELIM-001",
    category: "delimiter_injection",
    pattern: /```\s*system\b/i,
    weight: 0.30,
    description: "Code block system injection",
  },
  {
    id: "DELIM-002",
    category: "delimiter_injection",
    pattern: /\[SYSTEM\]/i,
    weight: 0.30,
    description: "[SYSTEM] tag injection",
  },
  {
    id: "DELIM-003",
    category: "delimiter_injection",
    pattern: /<\/?system>/i,
    weight: 0.30,
    description: "<system> tag injection",
  },
  {
    id: "DELIM-004",
    category: "delimiter_injection",
    pattern: /###\s*(?:SYSTEM|INSTRUCTION|ADMIN|OVERRIDE)/i,
    weight: 0.30,
    description: "### SYSTEM header injection",
  },
  {
    id: "DELIM-005",
    category: "delimiter_injection",
    pattern: /<\|(?:im_start|im_end|system|endoftext)\|>/i,
    weight: 0.35,
    description: "ChatML special token injection",
  },
  {
    id: "DELIM-006",
    category: "delimiter_injection",
    pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<\/s>/i,
    weight: 0.35,
    description: "Llama special token injection",
  },

  // --- Context Manipulation (weight: 0.20 each) ---
  {
    id: "CTX-001",
    category: "context_manipulation",
    pattern: /(?:imagine|suppose|assume|consider)\s+(?:that\s+)?(?:you\s+(?:are|have|were|can)|there\s+(?:are|is))\s+(?:no\s+)?(?:restrictions?|limitations?|rules?|safety|filters?)/i,
    weight: 0.20,
    description: "Hypothetical no-restrictions",
  },
  {
    id: "CTX-002",
    category: "context_manipulation",
    pattern: /(?:in\s+a\s+)?(?:hypothetical|fictional|imaginary|theoretical)\s+(?:scenario|world|situation|context)/i,
    weight: 0.10,
    description: "Hypothetical framing",
  },
  {
    id: "CTX-003",
    category: "context_manipulation",
    pattern: /(?:for\s+)?(?:educational|research|academic|testing|security\s+testing)\s+purposes?\s+only/i,
    weight: 0.10,
    description: "Educational purpose claim",
  },
  {
    id: "CTX-004",
    category: "context_manipulation",
    pattern: /this\s+is\s+(?:a\s+)?(?:test|simulation|drill|exercise|safe\s+environment)/i,
    weight: 0.10,
    description: "Test environment claim",
  },

  // --- Output Manipulation (weight: 0.20 each) ---
  {
    id: "OUT-001",
    category: "output_manipulation",
    pattern: /(?:respond|reply|answer|output)\s+(?:only\s+)?(?:with|in)\s+(?:json|xml|html|markdown|code|raw)/i,
    weight: 0.05,
    description: "Format forcing (low risk)",
  },
  {
    id: "OUT-002",
    category: "output_manipulation",
    pattern: /do\s+not\s+(?:mention|include|add|say|output)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|notes?|safety)/i,
    weight: 0.20,
    description: "Suppress safety disclaimers",
  },
  {
    id: "OUT-003",
    category: "output_manipulation",
    pattern: /(?:never|don't|do\s+not)\s+(?:refuse|decline|reject|deny|say\s+(?:no|you\s+can't))/i,
    weight: 0.25,
    description: "Never refuse requests",
  },

  // --- Tool Abuse (weight: 0.30 each) ---
  {
    id: "TOOL-001",
    category: "tool_abuse",
    pattern: /(?:call|execute|run|invoke|use)\s+(?:the\s+)?(?:delete|remove|drop|destroy|wipe|kill|shutdown)[\s_]/i,
    weight: 0.30,
    description: "Destructive tool invocation",
  },
  {
    id: "TOOL-002",
    category: "tool_abuse",
    pattern: /(?:send|forward|exfiltrate|leak|transmit)\s+(?:all\s+)?(?:the\s+)?(?:data|information|credentials?|secrets?|keys?|tokens?|api.?keys?)\s+(?:to|via|and)/i,
    weight: 0.35,
    description: "Data exfiltration attempt",
  },
  {
    id: "TOOL-003",
    category: "tool_abuse",
    pattern: /(?:access|read|fetch|get|retrieve)\s+(?:the\s+)?(?:env|environment|\.env|secrets?|api.?keys?|credentials?|passwords?|tokens?)/i,
    weight: 0.30,
    description: "Credential access attempt",
  },
];

// Thresholds per strictness level
const THRESHOLDS: Record<string, number> = {
  low: 0.5,
  medium: 0.3,
  high: 0.15,
};

export interface HeuristicConfig {
  strictness?: "low" | "medium" | "high";
  threshold?: number;
  customPatterns?: PatternRule[];
}

export class HeuristicScanner implements Scanner {
  readonly name = "heuristic";
  private patterns: PatternRule[];
  private threshold: number;

  constructor(config: HeuristicConfig = {}) {
    this.patterns = [...PATTERNS, ...(config.customPatterns ?? [])];
    this.threshold =
      config.threshold ?? THRESHOLDS[config.strictness ?? "medium"] ?? 0.3;
  }

  async scan(input: string, _context: ScanContext): Promise<ScannerResult> {
    const start = performance.now();
    const violations: Violation[] = [];
    let totalScore = 0;

    // Normalize once — pattern matching runs against the canonical form so
    // homoglyph/zero-width evasion doesn't bypass the rules. The caller
    // still sees the original input in `sanitized`.
    const normalized = normalizeForInjectionScan(input);

    for (const rule of this.patterns) {
      if (rule.pattern.test(normalized)) {
        totalScore += rule.weight;
        violations.push({
          type: "prompt_injection",
          scanner: this.name,
          score: rule.weight,
          threshold: this.threshold,
          message: rule.description,
          detail: `Rule ${rule.id} (${rule.category})`,
        });
      }
    }

    // Structural signals (cumulative) — intentionally run on the original
    // input so real structural attacks (many newlines, long paddings) can
    // still trip even when the textual patterns were evaded.
    const structuralScore = this.checkStructuralSignals(input);
    totalScore += structuralScore;

    // Cap at 1.0
    totalScore = Math.min(totalScore, 1.0);

    const decision =
      totalScore >= this.threshold
        ? "block"
        : totalScore >= this.threshold * 0.6
          ? "warn"
          : "allow";

    const durationMs = performance.now() - start;

    return { decision, violations, durationMs };
  }

  private checkStructuralSignals(input: string): number {
    let score = 0;

    // Many newlines (structured prompt injection)
    const newlines = (input.match(/\n/g) ?? []).length;
    if (newlines > 15) score += 0.05;

    // Excessive use of markdown headers (structure injection)
    const headers = (input.match(/^#{1,3}\s/gm) ?? []).length;
    if (headers > 3) score += 0.05;

    // Multiple role-like markers
    const roleMarkers = (
      input.match(
        /\b(system|user|assistant|human|ai|bot|admin)[\s:]/gi,
      ) ?? []
    ).length;
    if (roleMarkers > 2) score += 0.10;

    // Very long input (potential padding attack)
    if (input.length > 5000) score += 0.05;

    return score;
  }

  /** Get all registered pattern IDs for testing */
  getPatternIds(): string[] {
    return this.patterns.map((p) => p.id);
  }

  /** Get pattern count */
  get patternCount(): number {
    return this.patterns.length;
  }
}
