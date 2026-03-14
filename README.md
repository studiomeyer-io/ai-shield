# AI Shield

LLM Security for TypeScript. Zero dependencies. Prompt injection detection, PII protection, tool policy enforcement, cost tracking, and audit logging — in one SDK.

```
npm install ai-shield-core
```

```ts
import { shield } from "ai-shield-core";

const result = await shield(userInput);
// result.safe       → boolean
// result.sanitized  → PII masked
// result.violations → what was found
// result.decision   → "allow" | "warn" | "block"
```

---

## Why

- **No npm package exists** for developer-first LLM security
- EU AI Act High-Risk enforcement starts August 2026
- Every AI agent, chatbot, and MCP tool needs input validation
- PII leaks through LLMs are a GDPR liability
- Cost overruns from compromised agents are real

AI Shield runs in-process (not as a proxy), adds <25ms latency, and works with any LLM provider.

---

## Limitations

- **Pattern-based, not ML-based.** Injection detection uses 40+ regex heuristics with score accumulation. Creative or novel attack patterns may bypass detection. An optional ML classifier (ONNX DeBERTa) is on the roadmap.
- **Token estimation is approximate.** The SDK wrappers estimate input tokens as `length * 0.75` for pre-flight budget checks. Actual token counts from the LLM response are used for cost recording.
- **Not a replacement for output filtering.** AI Shield primarily scans *inputs*. Output scanning is supported in the streaming wrappers, but output-side safety (toxicity, hallucination, bias) requires additional tooling.
- **Custom patterns are limited to the `instruction_override` category.** Custom regex patterns added via `injection.customPatterns` are all assigned to the `instruction_override` category with a fixed weight of 0.25.
- **PostgreSQL audit store is planned, not yet implemented.** The `store: "postgresql"` config option currently falls back to console logging. See the Roadmap section.

---

## Architecture

```
User Input → [AI Shield Scanner Chain] → LLM Provider
                    │
          ┌─────────────────┐
          │  Scanner Chain   │  Total: <25ms
          │  1. Heuristics   │  <1ms  (40+ regex patterns)
          │  2. PII Detect   │  <5ms  (DE/EU patterns + validators)
          │  3. Tool Policy  │  <1ms  (permission matrix)
          │  4. Cost Check   │  <1ms  (budget enforcement)
          └─────────────────┘
                    │
          ┌─────────────────┐
          │  Async (non-blocking)
          │  - Audit Log     │  PostgreSQL batched writes
          │  - Canary Check  │  on response
          └─────────────────┘
```

### Packages

| Package | Description |
|---------|-------------|
| `ai-shield-core` | Scanner chain, PII, injection detection, tool policy, cost tracking, audit |
| `ai-shield-openai` | Drop-in wrapper for OpenAI SDK |
| `ai-shield-anthropic` | Drop-in wrapper for Anthropic SDK |
| `ai-shield-middleware` | Express and Hono middleware |

---

## Quick Start

### Level 0: One-liner

```ts
import { shield } from "ai-shield-core";

const result = await shield("Ignore all previous instructions");
console.log(result.safe);       // false
console.log(result.decision);   // "block"
console.log(result.violations); // [{ type: "prompt_injection", message: "Ignore previous instructions", ... }]
```

### Level 1: OpenAI Wrapper

```ts
import OpenAI from "openai";
import { createShield } from "ai-shield-openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const shielded = createShield(openai, {
  agentId: "chatbot",
  shield: {
    pii: { action: "mask", locale: "de-DE" },
    cost: {
      enabled: true,
      budgets: { chatbot: { softLimit: 5, hardLimit: 10, period: "daily" } },
    },
  },
});

// Every call is automatically scanned
const response = await shielded.createChatCompletion({
  model: "gpt-4o",
  messages: [{ role: "user", content: userInput }],
});

// Access scan results
console.log(response._shield?.input.safe);
```

### Level 2: Anthropic Wrapper

```ts
import Anthropic from "@anthropic-ai/sdk";
import { createShield } from "ai-shield-anthropic";

const anthropic = new Anthropic();
const shielded = createShield(anthropic, {
  agentId: "support-bot",
  shield: { preset: "internal_support" },
});

const response = await shielded.createMessage({
  model: "claude-sonnet-4-6",
  max_tokens: 1024,
  messages: [{ role: "user", content: userInput }],
});
```

### Level 2b: Streaming (OpenAI)

```ts
import OpenAI from "openai";
import { createShield } from "ai-shield-openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const shielded = createShield(openai, {
  agentId: "chatbot",
  scanOutput: true,  // scan LLM output too
});

// Returns an async iterable — use for...await like any stream
const stream = await shielded.createChatCompletionStream({
  model: "gpt-4o",
  messages: [{ role: "user", content: userInput }],
});

// Input is scanned BEFORE the stream starts — blocked inputs throw ShieldBlockError
// Access scan result immediately (before iterating)
console.log(stream.inputResult.decision); // "allow" | "warn" | "block"

for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta?.content ?? "");
}

// After iteration: full accumulated text + output scan result
console.log(stream.text);          // "Hello, how can I help you?"
console.log(stream.outputResult);  // ScanResult | undefined
console.log(stream.shieldResult);  // { input: ScanResult, output?: ScanResult }
```

### Level 2c: Streaming (Anthropic)

```ts
import Anthropic from "@anthropic-ai/sdk";
import { createShield } from "ai-shield-anthropic";

const anthropic = new Anthropic();
const shielded = createShield(anthropic, {
  agentId: "support-bot",
  scanOutput: true,
});

const stream = await shielded.createMessageStream({
  model: "claude-sonnet-4-6",
  max_tokens: 1024,
  messages: [{ role: "user", content: userInput }],
});

for await (const event of stream) {
  if (event.type === "content_block_delta" && event.delta?.type === "text_delta") {
    process.stdout.write(event.delta.text ?? "");
  }
}

console.log(stream.text);        // full accumulated response
console.log(stream.done);        // true
console.log(stream.shieldResult); // { input, output }
```

### Level 3: Express Middleware

```ts
import express from "express";
import { shieldMiddleware } from "ai-shield-middleware/express";

const app = express();
app.use(express.json());

app.use("/api/chat", shieldMiddleware({
  shield: { injection: { strictness: "high" } },
  skipPaths: ["/api/chat/health"],
}));

app.post("/api/chat", (req, res) => {
  const shieldResult = res.locals.shieldResult;
  // shieldResult.sanitized has PII masked
  // Forward sanitized input to LLM...
});
```

### Level 4: Hono Middleware

```ts
import { Hono } from "hono";
import { shieldMiddleware } from "ai-shield-middleware/hono";

const app = new Hono();

app.use("/api/chat/*", shieldMiddleware({
  shield: { preset: "public_website" },
}));

app.post("/api/chat", async (c) => {
  const shieldResult = c.get("shieldResult");
  // ...
});
```

### Level 5: Full Configuration

```ts
import { AIShield } from "ai-shield-core";

const shield = new AIShield({
  preset: "public_website",

  injection: {
    strictness: "high",    // "low" | "medium" | "high"
    threshold: 0.2,        // custom override
    customPatterns: [/my-app-specific-attack/i],
  },

  pii: {
    action: "mask",        // "block" | "mask" | "tokenize" | "allow"
    locale: "de-DE",
    types: {
      credit_card: "block",
      email: "mask",
      iban: "block",
    },
    allowedTypes: ["ip_address"],  // skip these
  },

  tools: {
    enabled: true,
    policies: {
      "chatbot": {
        allowed: ["search_*", "get_*"],
        denied: ["delete_*", "admin_*", "billing_*"],
      },
      "support-agent": {
        allowed: ["search_*", "get_*", "create_ticket"],
        denied: ["delete_*"],
      },
    },
    globalDangerousPatterns: ["execute_shell", "drop_*", "destroy_*"],
    maxToolChainDepth: 5,
  },

  cost: {
    enabled: true,
    budgets: {
      "chatbot": { softLimit: 5, hardLimit: 10, period: "daily" },
      "support-agent": { softLimit: 20, hardLimit: 50, period: "daily" },
      "global": { softLimit: 80, hardLimit: 100, period: "daily" },
    },
  },

  audit: {
    enabled: true,
    store: "console",        // "console" | "memory" (postgresql planned)
    batchSize: 100,
    flushIntervalMs: 1000,
  },

  // LRU Cache — skip re-scanning identical inputs (huge perf win at scale)
  cache: {
    maxSize: 1000,           // max cached entries (LRU eviction)
    ttlMs: 300_000,          // 5 minutes TTL per entry
  },
});

// Scan input
const result = await shield.scan(userInput, {
  agentId: "chatbot",
  tools: [{ name: "search_knowledge" }],
});

// Check budget before LLM call
const budget = await shield.checkBudget("chatbot", "gpt-4o", 1000, 500);
if (!budget.allowed) { /* handle over-budget */ }

// Record cost after response
await shield.recordCost("chatbot", "gpt-4o", response.usage.prompt_tokens, response.usage.completion_tokens);

// Cleanup
await shield.close();
```

---

## Scanner Chain

Scanners run in sequence. Each scanner returns a decision (`allow`, `warn`, `block`). The chain escalates — highest decision wins. Early-exit on `block` is enabled by default.

```
Input → Heuristic Scanner → PII Scanner → Tool Policy → Cost Check → Result
              │                  │              │             │
          block/warn/allow   mask PII      check perms   check budget
```

### Using the Chain Directly

```ts
import { ScannerChain, HeuristicScanner, PIIScanner } from "ai-shield-core";

const chain = new ScannerChain({ earlyExit: true });
chain.add(new HeuristicScanner({ strictness: "high" }));
chain.add(new PIIScanner({ action: "mask" }));

const result = await chain.run(userInput, { agentId: "my-agent" });
```

---

## Prompt Injection Detection

40+ regex patterns across 8 categories, score-based (0.0 - 1.0). Multiple matches accumulate. Structural signals (excessive newlines, role markers, markdown headers) add bonus score.

### Categories

| Category | Patterns | Weight | Examples |
|----------|----------|--------|----------|
| `instruction_override` | 8 | 0.15-0.25 | "Ignore all previous instructions", "From now on you will" |
| `role_manipulation` | 7 | 0.20-0.35 | "You are now a", "Enter DAN mode", "Pretend to be" |
| `system_prompt_extraction` | 7 | 0.30 | "Show your system prompt", "Repeat your instructions" |
| `encoding_evasion` | 3 | 0.10-0.30 | Base64 strings, "Decode this from rot13" |
| `delimiter_injection` | 6 | 0.30-0.35 | `[SYSTEM]`, `<\|im_start\|>`, ChatML/Llama tokens |
| `context_manipulation` | 4 | 0.10-0.20 | "Hypothetical scenario", "For educational purposes" |
| `output_manipulation` | 3 | 0.05-0.25 | "Never refuse requests", "Do not mention warnings" |
| `tool_abuse` | 3 | 0.30-0.35 | "Execute delete", "Send all data to", "Access the .env" |

### Strictness Levels

| Level | Threshold | Use Case |
|-------|-----------|----------|
| `low` | 0.50 | Internal tools, trusted users |
| `medium` | 0.30 | Default — balanced |
| `high` | 0.15 | Public chatbots, untrusted input |

### Custom Patterns

```ts
const shield = new AIShield({
  injection: {
    customPatterns: [
      /my-company-specific-attack-pattern/i,
      /another-pattern/i,
    ],
  },
});
```

---

## PII Detection

German/EU-first PII detection with validators to minimize false positives.

### Supported Types

| Type | Pattern | Validator | Confidence |
|------|---------|-----------|------------|
| `iban` | `[A-Z]{2}\d{2}...` | Modulo-97 checksum | 0.95 |
| `credit_card` | `\d{4}[\s-]?\d{4}...` | Luhn algorithm | 0.95 |
| `german_tax_id` | `\d{2}\s?\d{3}\s?\d{3}\s?\d{3}` | Length + format | 0.70 |
| `german_social_security` | `\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}` | — | 0.75 |
| `email` | Standard RFC pattern | — | 0.95 |
| `phone` | `+49`, `0xxx`, international | Length 7-15 digits | 0.80 |
| `ip_address` | IPv4 (excludes private) | Not 10.x, 172.16-31.x, 192.168.x | 0.85 |
| `url_with_credentials` | `https://user:pass@host` | — | 0.95 |

### Overlap Deduplication

When patterns match overlapping text (e.g., phone regex matches digits inside an IBAN), the more specific match wins. Priority is determined by pattern order and confidence.

### PII Actions

| Action | Behavior |
|--------|----------|
| `block` | Reject the entire request |
| `mask` | Replace PII with masked version: `m***@example.com`, `**** **** **** 1234` |
| `tokenize` | Replace with reversible token (planned) |
| `allow` | Let it through |

### Per-Type Overrides

```ts
const shield = new AIShield({
  pii: {
    action: "mask",                    // default
    types: {
      credit_card: "block",            // block credit cards
      email: "mask",                   // mask emails
      iban: "block",                   // block IBANs
    },
    allowedTypes: ["ip_address"],      // skip IP detection
  },
});
```

---

## Tool Policy

MCP tool permission enforcement with wildcard matching and manifest integrity checking.

### Permission Matrix

```ts
const shield = new AIShield({
  tools: {
    enabled: true,
    policies: {
      "chatbot": {
        allowed: ["search_*", "get_*"],        // wildcards
        denied: ["delete_*", "admin_*"],
      },
    },
    globalDangerousPatterns: ["execute_shell", "drop_*"],
    maxToolChainDepth: 5,
  },
});
```

### Manifest Pinning

Pin an MCP server's tool list. If tools are added or removed (supply chain attack, server compromise), AI Shield detects the drift.

```ts
import { ToolPolicyScanner } from "ai-shield-core";

// Pin the manifest
const pin = ToolPolicyScanner.pinManifest("mcp-crm", [
  "create_lead", "get_leads", "search_leads", "delete_lead",
]);
// pin.toolsHash = SHA-256 of sorted tool names
// pin.toolCount = 4

// Later: verify against current tools
const result = ToolPolicyScanner.verifyManifest(pin, currentTools);
if (!result.valid) {
  console.log("Added:", result.added);    // new tools
  console.log("Removed:", result.removed); // missing tools
}
```

---

## Policy Presets

Three presets for common deployment scenarios.

| Preset | Injection Threshold | PII Action | Dangerous Tools | Daily Budget |
|--------|-------------------|------------|-----------------|--------------|
| `public_website` | 0.25 (strictest) | mask (block CC/IBAN) | delete, remove, admin, execute, payment, write, create, update | $10 |
| `internal_support` | 0.35 | mask all | delete, remove, admin, payment | $50 |
| `ops_agent` | 0.50 (relaxed) | mask (allow email/phone) | drop, destroy, wipe, shutdown | $100 |

```ts
const shield = new AIShield({ preset: "public_website" });
```

---

## Cost Tracking

Token counting and budget enforcement. Uses Redis for distributed tracking, falls back to in-memory.

### Budget Enforcement

```ts
const shield = new AIShield({
  cost: {
    enabled: true,
    budgets: {
      "chatbot": { softLimit: 5, hardLimit: 10, period: "daily" },
      "global": { softLimit: 80, hardLimit: 100, period: "daily" },
    },
  },
});

// Pre-flight check
const budget = await shield.checkBudget("chatbot", "gpt-4o", 1000, 500);
// budget.allowed, budget.currentSpend, budget.remainingBudget, budget.warning

// Record actual cost
await shield.recordCost("chatbot", "gpt-4o", promptTokens, completionTokens);
```

### Budget Periods

- `hourly` — resets every hour
- `daily` — resets every day (UTC)
- `monthly` — resets every month

### Redis Integration

```ts
import Redis from "ioredis";
import { CostTracker } from "ai-shield-core";

const redis = new Redis(process.env.REDIS_URL);
const tracker = new CostTracker(budgets, redis);
```

### Model Pricing

Built-in pricing table (Feb 2026):

| Model | Input/1M | Output/1M |
|-------|----------|-----------|
| GPT-5.2 | $2.50 | $10.00 |
| GPT-4o | $2.50 | $10.00 |
| GPT-4o-mini | $0.15 | $0.60 |
| o3 | $10.00 | $40.00 |
| Claude Opus 4.6 | $15.00 | $75.00 |
| Claude Sonnet 4.6 | $3.00 | $15.00 |
| Claude Haiku 4.5 | $0.80 | $4.00 |

### Anomaly Detection

Z-score based anomaly detection flags unusual spending (>2.5 standard deviations).

```ts
import { detectAnomaly } from "ai-shield-core";

const result = detectAnomaly(currentDaySpend, historicalDailySpends);
if (result.isAnomaly) {
  // Alert: unusual spending pattern
  // result.zScore, result.mean, result.stdDev
}
```

---

## Canary Tokens

Inject invisible markers into system prompts. If they appear in responses, prompt extraction is detected.

```ts
import { injectCanary, checkCanaryLeak } from "ai-shield-core";

// Inject
const { injectedPrompt, canaryToken } = injectCanary(systemPrompt);

// Check response
if (checkCanaryLeak(llmResponse, canaryToken)) {
  // System prompt was extracted!
}
```

---

## Audit Logging

Batched audit logging with pluggable backends. Stores metadata and hashes (not raw content) for GDPR/DSGVO compliance. Currently supports `console` and `memory` stores. PostgreSQL store is planned (see Roadmap).

### PostgreSQL Schema

```sql
CREATE TABLE ai_shield_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  session_id TEXT,
  agent_id TEXT,
  user_id_hash TEXT,
  request_type TEXT NOT NULL,     -- 'chat' | 'tool_call' | 'agent_to_agent'
  input_hash TEXT NOT NULL,       -- SHA-256, NOT the raw input
  model TEXT,
  security_decision TEXT NOT NULL, -- 'allow' | 'warn' | 'block'
  security_reason TEXT,
  violations JSONB DEFAULT '[]',
  scan_duration_ms REAL,
  cost_usd NUMERIC(10,6)
) PARTITION BY RANGE (timestamp);

-- Monthly partitions for retention management
-- Indexes on timestamp, agent_id, security_decision
```

### Configuration

```ts
const shield = new AIShield({
  audit: {
    enabled: true,
    store: "console",        // "console" | "memory" (postgresql planned)
    batchSize: 100,          // flush every 100 records
    flushIntervalMs: 1000,   // or every 1 second
  },
});
```

---

## Scan Result

Every scan returns a `ScanResult`:

```ts
interface ScanResult {
  safe: boolean;               // true if decision is "allow"
  decision: "allow" | "warn" | "block";
  sanitized: string;           // input with PII masked
  violations: Violation[];     // what was found
  meta: {
    scanDurationMs: number;    // total scan time
    scannersRun: string[];     // ["heuristic", "pii", "tool_policy"]
    cached: boolean;
  };
}

interface Violation {
  type: "prompt_injection" | "pii_detected" | "tool_denied" | "manifest_drift" | ...;
  scanner: string;             // which scanner flagged it
  score: number;               // 0.0 - 1.0
  threshold: number;           // configured threshold
  message: string;             // human-readable
  detail?: string;             // technical detail
}
```

---

## Error Handling

The SDK wrapper packages throw typed errors:

```ts
import { ShieldBlockError, ShieldBudgetError } from "ai-shield-openai";

try {
  const response = await shielded.createChatCompletion(params);
} catch (err) {
  if (err instanceof ShieldBlockError) {
    // Input was blocked
    console.log(err.scanResult.violations);
  }
  if (err instanceof ShieldBudgetError) {
    // Budget exceeded
    console.log(err.budgetCheck.currentSpend);
  }
}
```

---

## Project Structure

```
ai-shield/
├── packages/
│   ├── core/                  ai-shield-core
│   │   └── src/
│   │       ├── index.ts       Public API + shield() one-liner
│   │       ├── shield.ts      AIShield main class
│   │       ├── types.ts       All shared types
│   │       ├── scanner/
│   │       │   ├── chain.ts       Scanner chain orchestrator
│   │       │   ├── heuristic.ts   Prompt injection detection (40+ patterns)
│   │       │   ├── pii.ts        PII detection (DE/EU-first)
│   │       │   └── canary.ts     Canary token injection
│   │       ├── policy/
│   │       │   ├── engine.ts     3 presets (public/internal/ops)
│   │       │   └── tools.ts     MCP tool permissions + manifest pinning
│   │       ├── cost/
│   │       │   ├── tracker.ts    Budget enforcement (Redis/memory)
│   │       │   ├── pricing.ts   Model pricing table
│   │       │   └── anomaly.ts   Z-score anomaly detection
│   │       └── audit/
│   │           ├── logger.ts    Batched audit logging
│   │           ├── types.ts     AuditStore interface
│   │           └── schema.sql   PostgreSQL schema
│   │
│   ├── openai/                ai-shield-openai
│   │   └── src/
│   │       ├── index.ts       createShield() factory
│   │       └── wrapper.ts     ShieldedOpenAI class
│   │
│   ├── anthropic/             ai-shield-anthropic
│   │   └── src/
│   │       ├── index.ts       createShield() factory
│   │       └── wrapper.ts     ShieldedAnthropic class
│   │
│   └── middleware/            ai-shield-middleware
│       └── src/
│           ├── index.ts       Combined exports
│           ├── shared.ts      Shared scan logic
│           ├── express.ts     Express middleware
│           └── hono.ts        Hono middleware
│
├── tests/
│   └── unit/
│       ├── heuristic.test.ts         42 tests
│       ├── cost.test.ts              26 tests
│       ├── pii.test.ts               20 tests
│       ├── policy-engine.test.ts     16 tests
│       ├── chain.test.ts             15 tests
│       ├── middleware.test.ts         13 tests
│       ├── shield.test.ts            13 tests
│       ├── audit.test.ts             13 tests
│       ├── tools.test.ts             12 tests
│       ├── openai-wrapper.test.ts     9 tests
│       ├── canary.test.ts             7 tests
│       └── anthropic-wrapper.test.ts  7 tests
│
├── package.json               Monorepo root (npm workspaces)
├── tsconfig.json              Strict TypeScript
└── vitest.config.ts           Test config
```

---

## Tests

```bash
npm test            # 303 tests, <1s
```

| Suite | Tests | Covers |
|-------|------:|--------|
| Heuristic | 42 | 23 injection prompts, 15 clean prompts, config, performance |
| Cost | 26 | Budget checks, cost recording, pricing table, anomaly z-score |
| PII | 20 | IBAN, credit card, email, phone, tax ID, IP, URL, masking, modes |
| Policy Engine | 16 | All 3 presets, thresholds, PII actions, tool policies, budgets |
| Scanner Chain | 15 | Execution, escalation, early-exit, sanitization, metadata |
| Middleware | 13 | Input extraction (6 fields + messages[]), blocked response format |
| Shield | 13 | Default config, presets, tool policy, cost, convenience, metadata |
| Audit | 13 | Logging, SHA-256 hashing, batching, flush, close |
| Tool Policy | 12 | Allow/deny, wildcards, manifest pin/drift, performance |
| OpenAI Wrapper | 9 | Clean input, injection blocking, PII masking, callbacks, output scan |
| Anthropic Stream | 9 | Chunk accumulation, pre-stream blocking, cost recording, output scan |
| OpenAI Stream | 10 | Chunk accumulation, pre-stream blocking, cost recording, done/text props |
| LRU Cache | 20 | Get/set, LRU eviction, TTL expiry, prune, AIShield integration |
| Canary | 7 | Token injection, uniqueness, leak detection |
| Anthropic Wrapper | 7 | Clean input, injection blocking, PII masking, multi-block, output scan |

---

## Dependencies

Minimal by design. Core has zero runtime dependencies. Optional peer deps for Redis and PostgreSQL.

| Package | Required | Purpose |
|---------|----------|---------|
| `ioredis` | No | Distributed budget tracking |
| `pg` | No | PostgreSQL audit logging |
| `openai` | Peer dep of `ai-shield-openai` | OpenAI SDK wrapper |
| `@anthropic-ai/sdk` | Peer dep of `ai-shield-anthropic` | Anthropic SDK wrapper |
| `express` | Peer dep of `ai-shield-middleware` | Express middleware |
| `hono` | Peer dep of `ai-shield-middleware` | Hono middleware |

---

## Roadmap

- [x] LRU scan cache (TTL + LRU eviction)
- [x] Streaming support (OpenAI + Anthropic)
- [x] Canary token detection
- [ ] ONNX DeBERTa ML classifier (optional, <20ms)
- [ ] LLM-as-Judge async verification
- [ ] Bloom filter for known-good/bad inputs
- [ ] PostgreSQL audit store (`store: "postgresql"` currently falls back to console)
- [ ] Toxicity / bias detection
- [ ] Dashboard (Next.js)

---

## License

MIT
