# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Model pricing table corrected and refreshed (June 2026).** The Anthropic
  rows still carried the pre-4.7 Opus rate of `$15 / $75` per 1M tokens — Opus
  has been `$5 / $25` since the 4.7 generation (with the 1M context window at
  standard pricing, no long-context premium), so `estimateCost()` was
  **over-estimating Opus spend by ~3x**. Corrected Opus 4.6/4.7 to `$5 / $25`,
  added `claude-opus-4-8` and `claude-fable-5` (`$10 / $50`), fixed Haiku 4.5
  to `$1 / $5`, and repointed the `opus` / `sonnet` / `haiku` aliases plus a new
  `fable` alias. `cachedInputPer1M` recomputed at the ~10% cache-read rate
  throughout.

## [0.2.0] — Indirect-Injection + Trust-Tier + Memory Canary + Circuit Breakers (2026-05-20)

The 2026 prompt-injection literature converges on one finding: regex over
user input only addresses the smaller half of the threat. The dominant attack
class is **indirect injection** — payloads arriving through RAG documents,
MCP tool descriptions, stored memory, scraped web content, or another agent's
output. v0.2 closes that gap and adds runtime defense for tool calls.

No breaking changes. All v0.1 APIs continue to work unchanged.

### Added

- **`scanIngested(content, source)` + `IngestionScanner`** — Indirect-injection
  scanner with per-source profiles (`rag` / `tool-desc` / `memory` / `web` /
  `agent-output`). Each source carries a tighter threshold than the user
  channel and a dedicated extra-pattern set: HTML-comment hidden
  instructions, CSS-hidden text, "AI assistant note:" trojan headers,
  "before using this tool you must…", memory-sentinel rewrites,
  markdown-link hijacks, multi-agent contagion patterns. Reuses the
  existing Unicode-evasion normalisation so homoglyph / zero-width /
  full-width attacks land regardless of the channel.
- **`wrapContext()` + `scanWrappedContext()` + `assemblePrompt()`** — Trust-tier
  context streams. Build a `WrappedContext` from typed inputs (`system`,
  `user`, `retrieved`, `tools`, `memory`, `web`, `agentOutput`), scan every
  segment with the source-specific profile, and assemble a final prompt
  where untrusted segments are wrapped in `<UNTRUSTED_CONTENT source="…">`
  fences and blocked segments can be dropped via `strictMode: true`.
  Each segment carries a `contentHash` (SHA-256) for downstream
  poisoning detection.
- **`mintMemoryCanary()` / `verifyMemoryCanary()` / `rotateMemoryCanary()` /
  `buildSentinelEntry()` / `bulkVerify()`** — Persistence-poisoning detection
  for memory stores. Seals each write with a random sentinel + SHA-256 hash
  over `(id, content, token, tenantId)` so silent mutation surfaces as
  `content_mutated` / `tenant_mismatch` / `hash_mismatch`. Constant-time
  hex compare via `crypto.timingSafeEqual`. Sentinel-entry honeypots for
  periodic store sweeps. Cross-tenant leaks surface as `tenant_mismatch`
  rather than ordinary drift.
- **`CircuitBreakerRegistry`** — Runtime tool guard layered on top of the
  static `ToolPolicyScanner`. Per-(tool, scope) rolling-window rate limits,
  blast-radius cap (max destructive calls per window), trip-and-cooldown
  on accumulated failures, plus an `onDestructive` human-in-the-loop hook
  that auto-denies on exception. LRU eviction on `(tool, scope)` cardinality
  so an attacker can't blow up memory by exploding key space. Default cap
  5_000 keys, overridable via `AI_SHIELD_CIRCUIT_MAX_KEYS`. Accepts any
  `ioredis`-shaped `CounterStoreLike` for cross-replica state.
- **`ai-shield-classifier-onnx` (new package, optional)** — ONNX-runtime ML
  classifier as a sibling workspace. Implements the `Scanner` interface so
  it composes cleanly into a `ScannerChain` after the heuristic regex pass.
  Dependency-injected `OnnxInferenceRuntime` + `Tokenizer` keep the package
  hermetic and unit-testable; `loadOnnxClassifier()` dynamically imports
  `onnxruntime-node` only when actually called. Graceful-degrade on
  inference error (returns `allow` + synthetic violation rather than blocking
  traffic). Calibrated default threshold 0.85 for
  `protectai/deberta-v3-base-prompt-injection`-class models. Kept out of
  `ai-shield-core` to preserve the zero-dependency promise.

### Changed

- **`ScanContext` extended** with optional `source: IngestionSource` and
  `trustTier: TrustTier` fields. Default `source: "user"` so existing callers
  see identical behaviour. The ingestion scanner reads these to select the
  source-specific profile.
- **`ViolationType` extended** with five new categories
  (`ingested_injection`, `untrusted_instruction`, `memory_poisoning`,
  `circuit_breaker_open`, `blast_radius_exceeded`). Old callers that
  switch on the type union should add cases — the existing cases still
  match.
- **Public exports** from `ai-shield-core` now include the new APIs above
  plus their associated types (`IngestionSource`, `TrustTier`,
  `ContextSegment`, `WrappedContext`, `MemoryCanaryEntry`,
  `MemoryCanaryVerification`, `CircuitState`, `CircuitBreakerConfig`,
  `CircuitBreakerDecision`, `CounterStoreLike`).

### Tests

- **+242 tests** across new suites: ingestion (48), wrap-context (31),
  memory-canary (44), circuit-breaker (40), onnx-classifier (31, hermetic
  with mock runtime + tokenizer), v0.2 defense-in-depth integration (20).
- **567 / 567 green**, full suite under 1 s. Zero `tsc` errors across all
  six workspaces.

### Migration

No code changes required. To engage v0.2 defenses:

```ts
// Before passing retrieved chunks into the model context:
import { scanIngested } from "ai-shield-core";
const r = await scanIngested(chunk, "rag");
if (!r.safe) drop(chunk);

// For full pipeline:
import { wrapContext, scanWrappedContext, assemblePrompt } from "ai-shield-core";
const ctx = wrapContext({ system, user, retrieved, tools, memory });
await scanWrappedContext(ctx);
const prompt = assemblePrompt(ctx, { strictMode: true });
```

## [0.1.1] — Round-4 OSS-Sweep (2026-04-24)

> Shipped as part of the 0.2.0 npm release (these fixes predate the 0.2.0
> feature work but were never cut as a standalone 0.1.1 tag).

Triple-agent review (Analyst + Critic + Research) surfaced three classes of
pre-release defects.

### Security

- **Unicode-evasion hardening in the heuristic injection scanner.** Added
  `normalizeForInjectionScan()` that applies NFKD decomposition, strips
  zero-width chars (U+200B..U+200D, U+2060, U+FEFF) and combining diacritics
  (U+0300..U+036F), then maps the most common Cyrillic/Greek Latin-lookalikes
  to ASCII. Pattern matching now runs against the normalized form so
  `"ig​nore pre‌vious ins‍tructions"` (zero-width split) and
  `"ignorе prеvious instructions"` (cyrillic `е`) and full-width
  `"ＩＧＮＯＲＥ ＰＲＥＶＩＯＵＳ"` all trip the same rules as the ASCII
  original. Structural signals (newline count, headers, length) still run on
  the raw input so padding attacks aren't masked by normalization.
- **AuditLogger userIdHash widened from 64-bit to 128-bit.** 16 hex chars is
  birthday-bound on ~2^32 entities, not acceptable for long-lived audit
  retention. Truncated SHA-256 is now 32 hex chars (~2^64 collision floor).

### Fixed

- **CostTracker: unbounded `records[]` growth.** A long-running process
  accumulated every `recordCost()` entry in memory until OOM. Introduced a
  ring-buffer with default cap `10_000` (overridable via
  `AI_SHIELD_MAX_RECORDS` env or `{ maxRecords }` constructor option). Set to
  `0` to disable retention entirely for budget-only use cases. Added
  `clearRecords()` for explicit cleanup after export.
- **AuditLogger: `setInterval` blocked clean process exit.** The flush timer
  held the event loop open. Now `unref()`'d so idle processes can exit; call
  `close()` for guaranteed final flush.
- **Shield.scan audit double-logging guard.** Explicit skip-on-cache check so
  subclasses extending `scan()` can't accidentally re-audit cached results.
- **PII IBAN pattern was DE-biased.** The v0.1.0 regex required five 4-digit
  groups, missing NO (15 chars), BE (16), NL (18), FR (27), MT (31) and
  ~40 other IBAN countries. Rewrote to a ReDoS-safe 15-34 char body pattern;
  the existing `validateIBAN()` mod-97 gate filters false positives.
- **PII phone mask overlap on short numbers.** `substring(0,4) + **** +
  substring(length-2)` overlapped when `value.length < 7`. Falls back to the
  generic `[PHONE]` token in that range.
- **PII credit-card mask was index-literal 12.** Now computes from
  `digits.length - 4` and falls back to `[CREDIT_CARD]` when the cleaned
  value is under the Luhn minimum.

### Updated

- **Model pricing table refreshed for April 2026.** Added
  `claude-opus-4-7`, `claude-sonnet-4-5` and `cachedInputPer1M` entries for
  the whole Anthropic family (prompt caching reads land at ~10% of standard
  input rate).

### Added

- **28 new tests** (325 → 353 total, all green):
  - `unicode-evasion.test.ts` — NFKD + ZW-strip + combining-strip + homoglyph
    mapping + ReDoS timing guards (50 KB base64 + 20 KB delimiter inputs
    must scan in <100 ms each).
  - `pii-iban-countries.test.ts` — 7 real IBAN countries (NO, BE, DK, NL,
    DE, FR, MT) + mod-97 rejection + random-alphanum rejection + phone
    minimum-length masking.
  - `cost-records-cap.test.ts` — ring-buffer semantics, `maxRecords: 0`
    disable path, `AI_SHIELD_MAX_RECORDS` env override, `clearRecords()`
    orthogonality against the budget counter.

### Known Limitations

- **Cost checkBudget is still best-effort under concurrency.** `checkBudget`
  reads then decides; `recordCost` increments after the LLM call. Under a
  burst of concurrent requests the budget can overshoot. Use Redis with
  atomic `INCR`-then-decide semantics in your own wrapper if hard caps
  matter.

## [0.1.0] - 2026-03-14

### Added

- **Scanner Chain** — Sequential scanner execution with early-exit on BLOCK (<25ms latency)
- **Prompt Injection Detection** — 40+ regex patterns across 8 categories (instruction override, role manipulation, encoding evasion, delimiter injection, context manipulation, tool abuse, data extraction, structural signals)
- **PII Detection** — German/EU-first with validators: IBAN (Mod-97), credit card (Luhn), email, phone, German tax ID, social security, IP addresses, URLs with credentials
- **PII Actions** — Block, mask (with smart templates like `m***@example.com`), tokenize, allow — per-type overrides
- **Tool Policy Engine** — Wildcard matching (`search_*`, `delete_*`), SHA-256 manifest pinning, drift detection, rate limiting hooks
- **Cost Tracking** — Token counting for 13 models (GPT-5.2, GPT-4o, Claude Opus/Sonnet/Haiku, o3), budget enforcement (soft/hard limits, hourly/daily/monthly), Redis-backed with in-memory fallback, anomaly detection (Z-score)
- **Audit Logging** — Batched PostgreSQL writes, monthly partitions, GDPR-compliant (hashes only, no raw content)
- **Canary Tokens** — Invisible markers to detect prompt extraction from LLM responses
- **LRU Cache** — Scan result caching with TTL (default 5min, max 1000 entries)
- **OpenAI Wrapper** (`ai-shield-openai`) — Drop-in replacement with pre/post scanning, streaming support
- **Anthropic Wrapper** (`ai-shield-anthropic`) — Drop-in replacement with pre/post scanning, streaming support
- **Gemini Wrapper** (`ai-shield-gemini`) — Drop-in replacement for Google Gemini SDK with pre/post scanning, streaming support
- **Middleware** (`ai-shield-middleware`) — Express and Hono route-level protection
- **3 Policy Presets** — `public_website`, `internal_support`, `ops_agent`
- **325 tests** across 23 test files, all passing
