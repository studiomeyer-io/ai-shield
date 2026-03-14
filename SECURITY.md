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

AI Shield uses **pattern-based detection**, not ML-based analysis. This means:

- **Novel prompt injection attacks** may bypass heuristic patterns until new patterns are added
- **Encoding evasion** (e.g., Base64 split across multiple messages) has limited detection
- **Defense in depth** is recommended — AI Shield should be one layer in your security stack, not the only one

We are transparent about these limitations because honest security tooling is better than false confidence.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
