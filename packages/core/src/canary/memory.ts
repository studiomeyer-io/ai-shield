import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import type { MemoryCanaryEntry, MemoryCanaryVerification } from "../types.js";

// ============================================================
// Memory Canary — Persistence-Poisoning Detection
//
// Existing canary tokens defend the *system prompt*: inject a sentinel
// + check the response for leakage. That works for prompt-extraction
// attacks but does nothing for the broader class of *persistence
// poisoning*: an attacker mutates a stored memory entry, knowledge-graph
// fact, or RAG document so that the next retrieval steers the model.
//
// MemoryCanary seals each write with:
//   1. A random sentinel token bound to the entry (`canaryToken`).
//   2. A SHA-256 hash over `id || content || canaryToken` so any silent
//      mutation of `content` between write and read is detectable.
//   3. Optional `tenantId` binding so a cross-tenant leak surfaces as
//      an explicit `tenant_mismatch` reason.
//
// Storage of the canary metadata is the caller's responsibility — the
// returned `MemoryCanaryEntry` is JSON-serialisable and meant to be
// persisted alongside the memory entry (separate column / sidecar key).
//
// The library does not store secrets and does not need a key. The
// security property is integrity (mutation detection), not
// confidentiality.
// ============================================================

/** Minimum allowed canary-token length in bytes (= 16 hex chars). */
const MIN_TOKEN_BYTES = 8;
/** Default canary-token length: 16 random bytes -> 32 hex chars. */
const DEFAULT_TOKEN_BYTES = 16;

export interface MintMemoryCanaryOptions {
  /**
   * Override token byte length. Minimum 8 (16 hex chars). Default 16.
   * Longer = stronger guessing resistance, but the hex string lives in
   * sidecar storage so the overhead is negligible.
   */
  tokenBytes?: number;
}

/**
 * Mint a canary for a memory entry. Call at write time, persist the
 * returned `MemoryCanaryEntry` alongside (or in place of) the raw entry.
 *
 * @param id        Stable identifier of the memory entry.
 * @param content   The content being stored.
 * @param tenantId  Optional tenant scope.
 */
export function mintMemoryCanary(
  id: string,
  content: string,
  tenantId?: string,
  options: MintMemoryCanaryOptions = {},
): MemoryCanaryEntry {
  if (typeof id !== "string" || id.length === 0) {
    throw new TypeError("mintMemoryCanary: 'id' must be a non-empty string");
  }
  if (typeof content !== "string") {
    throw new TypeError("mintMemoryCanary: 'content' must be a string");
  }
  const tokenBytes = Math.max(
    MIN_TOKEN_BYTES,
    options.tokenBytes ?? DEFAULT_TOKEN_BYTES,
  );
  const canaryToken = randomBytes(tokenBytes).toString("hex");
  const contentHash = computeHash(id, content, canaryToken, tenantId);

  return {
    id,
    content,
    contentHash,
    canaryToken,
    createdAt: new Date(),
    tenantId,
  };
}

/**
 * Verify a previously minted canary against the content read back from
 * storage. Returns `valid: true` only if both the content matches what
 * was sealed and the tenant binding (if any) matches.
 *
 * Use case 1 — mutation detection:
 * ```ts
 * const entry = mintMemoryCanary("fact:42", "Sky is blue.");
 * await db.write({ ...entry });
 *
 * // ... later ...
 * const stored = await db.read("fact:42");
 * const ver = verifyMemoryCanary(stored, stored.content);
 * if (!ver.valid) {
 *   logger.security("Memory poisoning suspected", { id, reason: ver.reason });
 * }
 * ```
 *
 * Use case 2 — cross-tenant leak detection:
 * ```ts
 * // tenant A reads what should be a tenant-B-only entry
 * const ver = verifyMemoryCanary(entry, entry.content, { tenantId: "tenant-A" });
 * // ver.reason === "tenant_mismatch"
 * ```
 */
export function verifyMemoryCanary(
  entry: MemoryCanaryEntry,
  observedContent: string,
  options: { tenantId?: string } = {},
): MemoryCanaryVerification {
  if (!entry || typeof entry !== "object") {
    return { valid: false, reason: "canary_missing" };
  }
  if (
    typeof entry.canaryToken !== "string" ||
    entry.canaryToken.length < MIN_TOKEN_BYTES * 2
  ) {
    return { valid: false, reason: "canary_missing" };
  }
  if (typeof observedContent !== "string") {
    return { valid: false, reason: "content_mutated" };
  }
  // Tenant binding is fail-closed. If the entry was minted with a
  // tenantId, the caller MUST supply the same tenantId. A caller that
  // omits `options.tenantId` against a tenant-bound entry surfaces as
  // a leak rather than a silent pass (Critic C2 from round 1 review).
  if (entry.tenantId !== undefined) {
    if (options.tenantId === undefined || options.tenantId !== entry.tenantId) {
      return {
        valid: false,
        reason: "tenant_mismatch",
        observed: observedContent,
      };
    }
  } else if (
    options.tenantId !== undefined &&
    entry.tenantId !== options.tenantId
  ) {
    // Caller passed a tenantId but the entry has none — also a mismatch.
    return {
      valid: false,
      reason: "tenant_mismatch",
      observed: observedContent,
    };
  }

  const expectedHash = computeHash(
    entry.id,
    observedContent,
    entry.canaryToken,
    entry.tenantId,
  );
  if (!hashesEqual(expectedHash, entry.contentHash)) {
    return {
      valid: false,
      reason:
        observedContent === entry.content ? "hash_mismatch" : "content_mutated",
      observed: observedContent,
    };
  }
  return { valid: true };
}

/**
 * Re-mint a canary after legitimate content edit. Returns a new
 * sealed entry that supersedes the old one. The old `canaryToken`
 * is rotated so a replay of the previous hash is also invalidated.
 */
export function rotateMemoryCanary(
  prev: MemoryCanaryEntry,
  newContent: string,
): MemoryCanaryEntry {
  return mintMemoryCanary(prev.id, newContent, prev.tenantId);
}

/**
 * Inject a *sentinel* memory entry — a decoy fact whose mutation would
 * indicate the store was tampered with. Pair with `findSentinelMutations()`
 * in a periodic sweep over the memory store.
 *
 * Returns a `MemoryCanaryEntry` with deterministic content that callers
 * can recognise. The content includes the canary token so even content
 * inspection (not just hash compare) catches mutation.
 */
export function buildSentinelEntry(
  scope: string,
  tenantId?: string,
): MemoryCanaryEntry {
  // ID combines timestamp (for ordering) + random suffix (so enumeration
  // by approximate-time guessing is infeasible — Critic M2 round 1).
  const idSuffix = randomBytes(4).toString("hex");
  const id = `ai-shield-sentinel:${scope}:${Date.now().toString(36)}-${idSuffix}`;
  const nonce = randomBytes(8).toString("hex");
  const content = `[AI-Shield sentinel — do not modify] scope=${scope} nonce=${nonce}`;
  return mintMemoryCanary(id, content, tenantId);
}

/**
 * Bulk verify a set of stored entries against their canaries. Returns
 * the IDs that failed verification, with the reason.
 */
export function bulkVerify(
  entries: Array<{
    canary: MemoryCanaryEntry;
    observedContent: string;
    expectedTenantId?: string;
  }>,
): Array<{
  id: string;
  reason: NonNullable<MemoryCanaryVerification["reason"]>;
}> {
  const failures: Array<{
    id: string;
    reason: NonNullable<MemoryCanaryVerification["reason"]>;
  }> = [];
  for (const e of entries) {
    const v = verifyMemoryCanary(e.canary, e.observedContent, {
      tenantId: e.expectedTenantId,
    });
    if (!v.valid && v.reason) {
      failures.push({ id: e.canary.id, reason: v.reason });
    }
  }
  return failures;
}

// --- Internal helpers ---

function computeHash(
  id: string,
  content: string,
  token: string,
  tenantId?: string,
): string {
  return createHash("sha256")
    .update(id)
    .update("\0")
    .update(content)
    .update("\0")
    .update(token)
    .update("\0")
    .update(tenantId ?? "")
    .digest("hex");
}

/**
 * Constant-time hex string compare. Falls back to a non-timing-safe
 * direct compare only when lengths differ (which is itself the leak
 * we want surfaced as a `false`, so this is fine).
 */
function hashesEqual(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  // Safe — both buffers have identical length, both come from
  // hex(SHA-256), no untrusted input.
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
