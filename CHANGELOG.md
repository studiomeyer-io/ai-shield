# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Round-4 OSS-Sweep (2026-04-24)

Triple-agent review (Analyst + Critic + Research) surfaced three classes of
pre-release defects. Fixes land here before a tagged release.

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
