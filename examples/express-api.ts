/**
 * Express middleware example — protect your AI chat API endpoint.
 *
 * Prerequisites:
 *   npm install express ai-shield-core ai-shield-middleware
 *
 * Run: npx tsx examples/express-api.ts
 * Test: curl -X POST http://localhost:3333/api/chat \
 *         -H "Content-Type: application/json" \
 *         -d '{"message": "Hello!"}'
 */
import express from "express";
import { shieldMiddleware } from "ai-shield-middleware/express";

const app = express();
app.use(express.json());

// Apply AI Shield to all /api/chat routes
app.use(
  "/api/chat",
  shieldMiddleware({
    shield: {
      injection: { strictness: "high" },
      pii: { action: "mask" },
    },
    skipPaths: ["/api/chat/health"],
  }),
);

// Health check (skipped by shield)
app.get("/api/chat/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Chat endpoint — input is already scanned
app.post("/api/chat", (req, res) => {
  const shieldResult = res.locals.shieldResult;

  if (!shieldResult) {
    res.status(500).json({ error: "Shield not applied" });
    return;
  }

  // Use sanitized input (PII masked) for your LLM call
  const sanitizedInput = shieldResult.sanitized;

  res.json({
    message: `You said: ${sanitizedInput}`,
    shield: {
      decision: shieldResult.decision,
      safe: shieldResult.safe,
      scanMs: shieldResult.meta.scanDurationMs,
      violations: shieldResult.violations.length,
    },
  });
});

const PORT = 3333;
app.listen(PORT, () => {
  console.log(`AI Shield Express example running on http://localhost:${PORT}`);
  console.log(`Try: curl -X POST http://localhost:${PORT}/api/chat -H "Content-Type: application/json" -d '{"message": "Hello!"}'`);
});
