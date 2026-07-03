# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AI Shield, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@studiomeyer.io**

We will:
1. Acknowledge receipt within 48 hours
2. Investigate and provide an initial assessment within 5 business days
3. Work on a fix and coordinate disclosure
4. Credit you in the security advisory (unless you prefer anonymity)

## Scope

The following are in scope:
- Prompt injection detection bypasses
- PII detection false negatives (missed sensitive data)
- Scanner chain logic errors
- Audit logging data leaks (raw content exposure)
- Cache poisoning or collision attacks
- Cost tracking bypass

The following are out of scope:
- Denial of service via large inputs (expected behavior — use input size limits)
- False positives in heuristic detection (open a regular issue)
- Vulnerabilities in peer dependencies (report to those projects)

## Known Limitations

The zero-dependency `ai-shield-core` defaults to **pattern-based detection**
(40+ scored heuristics with Unicode/leetspeak/typoglycemia/letter-splitting
normalisation). Two **optional** semantic layers can be composed on top: the
ONNX DeBERTa classifier (`ai-shield-classifier-onnx`) and the async
LLM-as-judge (`createAsyncJudge`). Even with all three layers, no input filter
is a complete defence. This means:

- **Novel prompt injection attacks** may bypass the heuristic patterns until
  new patterns are added; the optional ML/judge layers narrow but do not close
  that gap.
- **Indirect injection is the larger risk.** Payloads arriving through RAG
  documents, tool descriptions/outputs, stored memory or another agent's output
  are the dominant 2026 attack class. Use `scanIngested` / `wrapContext` /
  `createDualLLM` for that surface — a user-input filter alone does not cover it.
- **Encoding evasion** (e.g., Base64 split across multiple messages) has limited
  detection.
- **Defense in depth** is recommended — AI Shield should be one layer in your
  security stack, not the only one. The only architecturally robust mitigation
  is privilege separation (see "What AI Shield is NOT" in the README).

We are transparent about these limitations because honest security tooling is
better than false confidence.

## Supported Versions

Security fixes land on the latest published minor. Please upgrade to the current
release line before reporting.

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No — please upgrade |
