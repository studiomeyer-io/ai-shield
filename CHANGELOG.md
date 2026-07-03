# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`ai-shield-ai-sdk`** — new sibling package: AI Shield middleware for the
  Vercel AI SDK (`ai` >= 7) via `wrapLanguageModel`. `aiShieldMiddleware()`
  returns a `LanguageModelMiddleware` (verified against `ai@7.0.14` /
  `@ai-sdk/provider@4.0.2`, the `LanguageModelV4` middleware spec) that runs
  the input scan chain in `transformParams` BEFORE the provider call — a
  `block` decision throws `ShieldBlockError` without ever invoking the model,
  `warn` fires the `onWarning` callback, and PII masking rewrites the outgoing
  prompt (user messages only, mirroring the OpenAI/Anthropic/Gemini wrappers).
  Optional output scanning (`scanOutput` legacy chain and/or the dedicated
  v0.3 `outputScan` scanner) runs in `wrapGenerate` / `wrapStream`; results
  are surfaced under `providerMetadata.aiShield` on the generate result and on
  the `finish` stream part (output findings are reported, not blocked — same
  semantics as the other streaming wrappers). Ships a `shieldModel(model,
  config)` convenience factory. `ai` is a peer dependency (`>=7.0.0 <8.0.0`),
  runtime deps are `ai-shield-core` only, and core itself is untouched.
  19 new unit tests (`tests/unit/ai-sdk-middleware.test.ts`) drive the real
  `wrapLanguageModel` + `generateText` + `streamText` pipeline against the
  official `ai/test` mock model (block, allow, PII-mask, multi-message mask,
  system-prompt exclusion, callbacks, legacy + dedicated output scan, sinks
  filter, stream passthrough, stream finish-part metadata, stream block,
  tool-name context, contextFactory, convenience factory) — 716 → 735 total.

## [0.5.1] — `ai-shield-classifier-onnx` packaging hotfix (2026-06-22)

Single-package patch — `ai-shield-classifier-onnx` only. The other five
packages are unaffected and stay at 0.5.0.

### Fixed

- **`ai-shield-classifier-onnx` shipped no `dist/`.** The published 0.5.0
  tarball contained only `src/*.ts` + `tsconfig.json` while `main` / `types` /
  `exports` pointed at `./dist/index.js` and `./dist/index.d.ts`, so
  `import('ai-shield-classifier-onnx')` failed with `ERR_MODULE_NOT_FOUND` on a
  clean install. Root cause: the package had no `files` allowlist, so
  `npm pack` fell back to the monorepo `.gitignore` (which excludes `dist/`).
  Added `"files": ["dist"]` — the allowlist takes precedence over `.gitignore`,
  so the compiled output now ships and the raw TS source no longer does
  (tarball: 5 source files → 8 dist files). No code or API change; the package
  was simply uninstallable before. Other packages publish their `dist/`
  correctly and were left untouched.

## [0.5.0] — Typoglycemia Defense + Dual-LLM Privilege Separation (2026-06-22)

Two additions from the v0.3 review research backlog: a fuzzy-matching defense
against scrambled-word evasion, and the OWASP-recommended dual-LLM architecture
for indirect-injection-resistant agentic systems. No breaking changes.

### Added

- **Typoglycemia defense** — `unscrambleForInjectionScan()` as an additional
  lossy view (like `leetDecodeForInjectionScan` / `collapseSpacedLetters`):
  a ≥5-letter word that is an anagram of an injection keyword (same length,
  same first+last letter, same multiset of middle letters) is rewritten to
  the keyword, and the high-value categories re-test against that view. That
  is exactly classic Typoglycemia — a permuted middle — and covers adjacent
  transpositions. "Ignroe all prevoius instrcutions" now blocks. Anagram-only
  folding was a deliberate choice: edit-distance folding was tried and dropped
  because it false-positived real word pairs ("forgot"→"forget",
  "rulers"→"rules"); anagram matching is FP-free on a 116-word benign corpus.
  Ships a standalone `damerauLevenshtein(a, b, cap)` zero-dep utility (optimal
  string alignment + adjacent transposition, early-exit cap) for callers who
  want fuzzy matching with their own FP tolerance.
- **Dual-LLM privilege separation** (`createDualLLM`) — the architecturally
  robust mitigation for indirect injection (OWASP Prompt Injection Cheat Sheet
  2026 / Simon Willison's dual-LLM proposal): the **privileged** model (holds
  the tools) never reads raw untrusted content; the **quarantined** model (no
  tools) processes it and returns data that is scanned (`scanIngested` bridge)
  and fenced (`<QUARANTINED_DATA>`) before the privileged side sees it. A
  flagged quarantined result is **dropped**, not fenced-and-included — it never
  reaches the actor.
- **Action screening** (`createActionScreener`) — a **fail-closed** gate that
  checks a proposed tool call against the user's ORIGINAL intent (never the
  untrusted context that may have steered it, so a steered call can't steer its
  own approval). Any outcome other than an explicit "allow" — deny, unparseable
  judge output, backend error, or timeout — denies the action.

### Tests

- **+22 tests** (688 → **710**): typoglycemia (11 — DL distance/transposition,
  un-scramble, scan integration, FP guards) + dual-llm (11 — privilege routing,
  bridge scan, drop-unsafe assembly, action-screen fail-closed paths). The
  attack-corpus harness reports no new false positives. tsc clean across six
  workspaces; all new paths bounded/ReDoS-safe.

## [0.4.0] — Injection-Detection Hardening: Unicode-Tag / Multilingual / Policy-Puppetry / Leetspeak (2026-06-21)

Closes four prompt-injection bypasses that previously returned `allow` even at
high strictness, plus two correctness bug fixes and three false-positive fixes.
A new attack-corpus harness (24 labelled payloads + 17 benign controls) asserts
the bar: 100% detection / 0% false-positive. No breaking changes.

### Added

- **Unicode TAG smuggling detection** (U+E0000–E007F) — `normalizeForInjectionScan`
  de-tags (maps tag chars to their ASCII payload and re-scans); standalone /
  smuggled invisible tag chars are themselves a violation (Rule TAG-001). New
  `deTagForInjectionScan` / `hasTagChars` helpers; flag-emoji false-positive
  guarded via `stripWellFormedTagSequences`.
- **Multilingual override detection** (DE/ES/FR) — new `localized_override`
  category (INJ-DE-1/2, INJ-ES-1, INJ-FR-1), matched on the NFKD-folded form and
  gated on an override verb before the object noun so benign prose mentioning
  "Anweisungen"/"instrucciones"/"instructions" stays allowed. The French rule is
  scoped to French determiners so it can't double-fire on English.
- **Policy-puppetry / fake-config detection** (HiddenLayer 2025) — DELIM-PP-1..5
  cover interaction-config, allowed-modes, blocked-strings, fake privileged
  `<role>`, and forged `<assistant>`/`<user>` transcript turns (forged-turn
  detection requires an attack co-signal so lone benign transcripts pass).
- **Leetspeak detection** — `leetDecodeForInjectionScan` as an additional lossy
  view (0→o 1→i 3→e 4→a 5→s 7→t @→a $→s), scoped to high-value categories so
  incidental numbers in benign prose ("buy 3 for 5 dollars") don't trip.
- **Attack-corpus harness** (`tests/corpus/`) — runs labelled injection payloads
  + benign controls through the HeuristicScanner at high strictness and asserts
  0 false positives + ≥95% detection (current run: 24/24 caught, 17/17 clean).

### Fixed

- **`shield()` arg-routing** — the fragile `||`/`&&` key-sniff treated any object
  with a string `preset` (and no `agentId`) as a `ShieldConfig`, so a real
  `ScanContext` like `{ preset, source: "rag", userId }` was misread as config
  and its ingestion-routing metadata silently dropped. Replaced with an
  `isShieldConfig()` discriminant (context-only keys win, then config-only keys,
  else default to context — lower blast radius).
- **Secret scrub-on-block** — secret detection ran on the normalized output
  (zero-width stripped) so a split key `sk-ant-…<ZWSP>…` blocked, but redaction
  ran over the RAW output where the anchored pattern didn't match — leaving the
  live key in `sanitized`. Added a scrub-on-block guarantee: if a matched
  pattern still hits the normalized sanitized output, strip the invisible chars
  so the key collapses and redact again. `sanitized` is now free of the live
  secret regardless of the evasion used.
- **Three false positives** closed without reopening bypasses — flag/subdivision
  emoji (TAG-001), negated German ("Vergiss nicht …", INJ-DE-1), lone benign
  transcript pair (DELIM-PP-5).

### Tests

- **+121 tests** (567 → **688**): unicode-evasion 12→25, heuristic-extended
  15→19, +13 policy-puppetry, shield 13→16, output-scanner 14→17, plus the
  corpus harness. All new regex paths ReDoS-safe (<100ms on 50–200KB worst
  case). tsc clean across all six workspaces.

## [0.3.0] — Output Scanning + Tool-Output + Async Judge + Multi-Agent Trust (2026-06-21)

v0.2 closed the *input*-side indirect-injection gap. v0.3 closes the
*output* side and the agentic-loop channels around it. The whole 2026 OSS
LLM-security field is Python-only (LLM Guard, NeMo Guardrails, Guardrails
AI); v0.3 keeps AI Shield the zero-dependency TypeScript answer.

No breaking changes. All v0.1 / v0.2 APIs continue to work unchanged.

### Added

- **`scanOutput()` + `OutputScanner`** — output-side scanning for OWASP
  **LLM05 Improper Output Handling** + **LLM02 Sensitive Information
  Disclosure**. AI Shield previously scanned almost only inputs; this
  answers "is this model *output* safe to act on / show / forward?". Five
  checks: `secret_leak` (API keys, JWT, PEM, DSNs — redacted in
  `sanitized`), `output_injection` (SQL / shell / HTML-JS / template
  payloads, with an optional `sinks` filter), `system_prompt_leak`
  (exact canary-token match + heuristic phrasing fallback),
  `jailbreak_indicator`, and PII (reuses the input-side `PIIScanner`).
  High-confidence checks block; jailbreak/heuristic-leak warn. Length-
  capped (256 KB) and ReDoS-safe.
- **`scanToolOutput(toolName, content)` + `tool-output` ingestion source** —
  scans the runtime *result* a tool returned (MCP tool result, function
  output), distinct from `tool-desc` (the static schema). This is the
  dominant indirect-injection channel in agentic loops — PoisonedRAG
  (USENIX Security 2025) reached a 90% attack-success rate with 5 planted
  documents. Stamps the originating tool name into every violation for
  audit.
- **`propagateTrust(payload, from, to)` — multi-agent contagion tracking** —
  scans an agent-to-agent hand-off as `agent-output`, degrades effective
  trust to `untrusted` on any warn/block, and keeps contamination **sticky**
  across hops (A→B→C): pass the returned `hops` back as `priorChain` so a
  poisoning at A still flags the C-hop. Emits a dedicated `trust_propagation`
  violation distinct from the per-segment `ingested_injection`.
- **`createAsyncJudge()` — async LLM-as-Judge adapter** — semantic injection
  detection off the hot path. BYO-backend (wrap your own Anthropic / OpenAI /
  local-model call — the core stays zero-dependency). Run it in a parallel
  lane alongside the deterministic scan so its latency never hits the
  user-perceived path. Degrades gracefully: a backend error or timeout
  yields an `"error"` verdict, never a throw. With the heuristic chain and
  the optional ONNX classifier, AI Shield now spans all three detection
  layers — pattern + ML + LLM-judge — in one zero-dependency core.
- **Unicode / evasion hardening** — `collapseSpacedLetters()` un-splits
  letter-splitting evasion (`i g n o r e` / `i.g.n.o.r.e` → `ignore`) and the
  high-value override/role/extraction/tool rules are re-tested against the
  collapsed form. Extended the homoglyph map (more Cyrillic / Greek /
  Armenian look-alikes), and added a GCG-style **adversarial-suffix**
  structural signal.
- **`outputScan` flag on the SDK wrappers** — `ShieldedAnthropic`,
  `ShieldedOpenAI` and the Gemini wrapper now accept
  `outputScan: true | OutputScanConfig`, which runs the dedicated
  `OutputScanner` over the model response (non-streaming and streaming) and
  surfaces the result on `response._shield.outputScan` /
  `stream.outputScanResult`. The legacy `scanOutput: boolean` flag (input
  chain over the output) is unchanged — additive, not breaking.

### Changed

- **`ViolationType` extended** with `output_injection`, `secret_leak`,
  `system_prompt_leak`, `jailbreak_indicator`, `trust_propagation`. Existing
  cases still match; callers that exhaustively switch on the union should add
  the new arms.
- **`IngestionSource` extended** with `tool-output`. Additive — existing
  sources unchanged.
- **Public exports** from `ai-shield-core` now include `scanOutput` /
  `OutputScanner`, `scanToolOutput`, `propagateTrust`, `createAsyncJudge`,
  plus `normalizeForInjectionScan`, `collapseSpacedLetters` and
  `tryDecodeObfuscation` (previously internal) and all associated types.

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

### Tests

- **+47 tests** (568 → **615**, all green, full suite ~1s): output-scanner
  (15), tool-output (6), trust-propagation (15), async-judge (11). Zero `tsc`
  errors across all six workspaces.

### Migration

No code changes required. To engage v0.3 defenses:

```ts
import { scanOutput, scanToolOutput, propagateTrust } from "ai-shield-core";

// Before forwarding a model response to a SQL/HTML/shell sink:
const out = await scanOutput(reply, { canaryTokens, sinks: ["sql"] });
if (!out.safe) return fallback();

// Before feeding a tool result back into the model:
const t = await scanToolOutput("web_search", result);
if (!t.safe) return; // drop poisoned tool output

// At each agent-to-agent hand-off:
chain = await propagateTrust(agentOut, "A", "B", { priorChain: chain?.hops });
```

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
