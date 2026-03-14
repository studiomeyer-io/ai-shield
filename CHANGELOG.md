# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **OpenAI Wrapper** (`@ai-shield/openai`) — Drop-in replacement with pre/post scanning, streaming support
- **Anthropic Wrapper** (`@ai-shield/anthropic`) — Drop-in replacement with pre/post scanning, streaming support
- **Middleware** (`@ai-shield/middleware`) — Express and Hono route-level protection
- **3 Policy Presets** — `public_website`, `internal_support`, `ops_agent`
- **232 tests** across 15 test files, all passing
