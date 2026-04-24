import type {
  Scanner,
  ScannerResult,
  ScanContext,
  Violation,
  PIIEntity,
  PIIType,
  PIIAction,
  PIIConfig,
} from "../types.js";

// ============================================================
// PII Scanner — German/EU-first PII Detection
// Supports: IBAN, Steuernr, Kreditkarte, Email, Phone, IP
// Modes: block / mask / tokenize
// ============================================================

interface PIIPattern {
  type: PIIType;
  pattern: RegExp;
  validator?: (value: string) => boolean;
  baseConfidence: number;
}

// --- German & International PII Patterns ---
const PII_PATTERNS: PIIPattern[] = [
  // IBAN: 2-letter ISO + 2 check digits + 11..30 alphanumerics (with optional spaces/dashes).
  // Covers all 80+ IBAN countries: NO (15), BE (16), DE (22), FR (27), MT (31), SC (31).
  // The validator runs mod-97 over the cleaned value and rejects anything that isn't a real IBAN.
  // Pattern is linear (no nested quantifiers) — ReDoS-safe.
  {
    type: "iban",
    pattern: /\b[A-Z]{2}\d{2}[ -]?[A-Z0-9](?:[A-Z0-9 -]{9,36}[A-Z0-9])?\b/g,
    validator: validateIBAN,
    baseConfidence: 0.95,
  },

  // Credit card: 4 groups of 4 digits (Luhn-validated)
  {
    type: "credit_card",
    pattern: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
    validator: validateLuhn,
    baseConfidence: 0.95,
  },

  // German tax ID (Steuerliche Identifikationsnummer): 11 digits
  {
    type: "german_tax_id",
    pattern: /\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b/g,
    validator: validateGermanTaxId,
    baseConfidence: 0.70,
  },

  // German social security number: 2 digits + 6 digits + letter + 3 digits
  {
    type: "german_social_security",
    pattern: /\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b/g,
    baseConfidence: 0.75,
  },

  // Email
  {
    type: "email",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    baseConfidence: 0.95,
  },

  // Phone: German formats (+49, 0xxx) and international.
  // Previous pattern had nested optional quantifiers (`\s?[\s\-/]?` plus two
  // `[\s\-/]?\d{0,5}` tails) which risks catastrophic backtracking on
  // malformed inputs. Restructured so every separator group requires at least
  // one char when present and the trailing digits group is a true non-optional
  // extension (or absent entirely).
  {
    type: "phone",
    pattern:
      /(?<!\d)(?:\+\d{1,3}|00\d{1,3}|0)[\s\-/]?\(?\d{2,5}\)?[\s\-/]?\d{3,8}(?:[\s\-/]\d{1,5})?\b/g,
    validator: validatePhone,
    baseConfidence: 0.80,
  },

  // IP addresses (v4)
  {
    type: "ip_address",
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    validator: validateIPNotPrivate,
    baseConfidence: 0.85,
  },

  // URLs with embedded credentials
  {
    type: "url_with_credentials",
    pattern: /https?:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
    baseConfidence: 0.95,
  },
];

// --- Validators ---

function validateIBAN(raw: string): boolean {
  const cleaned = raw.replace(/\s|-/g, "");
  if (cleaned.length < 15 || cleaned.length > 34) return false;

  // Move first 4 chars to end, convert letters to numbers
  const rearranged = cleaned.substring(4) + cleaned.substring(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, (c) =>
    String(c.charCodeAt(0) - 55),
  );

  // Modulo 97 check (handle large numbers via chunking)
  let remainder = numeric;
  while (remainder.length > 2) {
    const chunk = remainder.substring(0, 9);
    remainder =
      String(parseInt(chunk, 10) % 97) + remainder.substring(chunk.length);
  }
  return parseInt(remainder, 10) % 97 === 1;
}

function validateLuhn(raw: string): boolean {
  const digits = raw.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i]!, 10);
    if ((digits.length - i) % 2 === 0) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

function validateGermanTaxId(raw: string): boolean {
  const digits = raw.replace(/\s/g, "");
  if (digits.length !== 11) return false;
  if (!/^\d+$/.test(digits)) return false;
  // First digit cannot be 0
  if (digits[0] === "0") return false;
  return true;
}

function validatePhone(raw: string): boolean {
  const digits = raw.replace(/\D/g, "");
  // Must be at least 7 digits, max 15
  return digits.length >= 7 && digits.length <= 15;
}

function validateIPNotPrivate(raw: string): boolean {
  const parts = raw.split(".").map(Number);
  // Skip private/loopback ranges (not really PII)
  if (parts[0] === 10) return false;
  if (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] === 127) return false;
  return true;
}

// --- Masking ---

function maskValue(type: PIIType, value: string): string {
  switch (type) {
    case "email": {
      const atIdx = value.indexOf("@");
      if (atIdx <= 1) return "[EMAIL]";
      return value[0] + "***@" + value.substring(atIdx + 1);
    }
    case "phone":
      // Need room for 4-prefix + ****  + 2-suffix without overlap.
      if (value.length < 7) return "[PHONE]";
      return value.substring(0, 4) + "****" + value.substring(value.length - 2);
    case "iban":
      // Keep country code + check digits, mask rest. Works for any IBAN length.
      return value.length >= 4 ? value.substring(0, 4) + " **** **** ****" : "[IBAN]";
    case "credit_card": {
      const digits = value.replace(/\D/g, "");
      if (digits.length < 13) return "[CREDIT_CARD]";
      return "**** **** **** " + digits.substring(digits.length - 4);
    }
    default:
      return `[${type.toUpperCase()}]`;
  }
}

// --- PII Scanner Class ---

export class PIIScanner implements Scanner {
  readonly name = "pii";
  private patterns: PIIPattern[];
  private action: PIIAction;
  private typeOverrides: Partial<Record<PIIType, PIIAction>>;
  private allowedTypes: Set<PIIType>;

  constructor(config: PIIConfig = {}) {
    this.patterns = PII_PATTERNS;
    this.action = config.action ?? "mask";
    this.typeOverrides = config.types ?? {};
    this.allowedTypes = new Set(config.allowedTypes ?? []);
  }

  async scan(input: string, _context: ScanContext): Promise<ScannerResult> {
    const start = performance.now();
    const entities = this.detect(input);
    const violations: Violation[] = [];

    // Filter out allowed types
    const activeEntities = entities.filter(
      (e) => !this.allowedTypes.has(e.type),
    );

    if (activeEntities.length === 0) {
      return {
        decision: "allow",
        violations: [],
        sanitized: input,
        durationMs: performance.now() - start,
      };
    }

    // Build violations
    let shouldBlock = false;
    for (const entity of activeEntities) {
      const action = this.typeOverrides[entity.type] ?? this.action;
      if (action === "block") shouldBlock = true;

      violations.push({
        type: "pii_detected",
        scanner: this.name,
        score: entity.confidence,
        threshold: 0,
        message: `${entity.type} detected`,
        detail: `Found ${entity.type} at position ${entity.start}-${entity.end} (action: ${action})`,
      });
    }

    // Apply masking if needed
    let sanitized = input;
    const effectiveAction = shouldBlock ? "block" : this.action;
    if (effectiveAction === "mask" || effectiveAction === "tokenize") {
      sanitized = this.applyMasking(input, activeEntities);
    }

    const decision = shouldBlock ? "block" : "warn";

    return {
      decision,
      violations,
      sanitized,
      durationMs: performance.now() - start,
    };
  }

  /** Detect all PII entities in text */
  detect(text: string): PIIEntity[] {
    const raw: PIIEntity[] = [];

    for (const piiPattern of this.patterns) {
      // Create fresh regex for each scan (stateful with /g flag)
      const regex = new RegExp(piiPattern.pattern.source, piiPattern.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        const value = match[0];
        const cleaned = value.replace(/[\s-]/g, "");

        // Run validator if present
        if (piiPattern.validator && !piiPattern.validator(cleaned)) {
          continue;
        }

        raw.push({
          type: piiPattern.type,
          value,
          start: match.index,
          end: match.index + value.length,
          confidence: piiPattern.baseConfidence,
        });
      }
    }

    return this.deduplicateOverlaps(raw);
  }

  /** Remove overlapping detections — keep the more specific (higher confidence) match */
  private deduplicateOverlaps(entities: PIIEntity[]): PIIEntity[] {
    if (entities.length <= 1) return entities;

    // Sort by start position, then by span length descending (longer = more specific)
    const sorted = [...entities].sort((a, b) =>
      a.start !== b.start ? a.start - b.start : (b.end - b.start) - (a.end - a.start),
    );

    const kept: PIIEntity[] = [];
    for (const entity of sorted) {
      // Check if this entity overlaps with any already-kept entity
      const overlaps = kept.some(
        (k) => entity.start < k.end && entity.end > k.start,
      );
      if (!overlaps) {
        kept.push(entity);
      }
      // If it overlaps, the already-kept entity wins (it appeared first in pattern order = more specific)
    }

    return kept;
  }

  /** Mask detected PII in text */
  private applyMasking(text: string, entities: PIIEntity[]): string {
    // Sort by position descending to preserve offsets
    const sorted = [...entities].sort((a, b) => b.start - a.start);
    let masked = text;

    for (const entity of sorted) {
      const replacement = maskValue(entity.type, entity.value);
      masked =
        masked.substring(0, entity.start) +
        replacement +
        masked.substring(entity.end);
    }

    return masked;
  }
}
