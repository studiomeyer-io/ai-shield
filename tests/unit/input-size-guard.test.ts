import { describe, it, expect, afterEach } from "vitest";
import { AIShield } from "../../packages/core/src/index.js";

// ============================================================
// Input-size guard (AIShield.scan)
// ------------------------------------------------------------
// scan() truncates the input to AI_SHIELD_MAX_INPUT_BYTES (default 262_144
// code units) before running the scanner chain, so a multi-MB user-supplied
// prompt can't force every regex over the full buffer. This behaviour was
// shipped but had no direct test — these lock the DoS-bound contract in.
//
// Note: the cap is read from process.env at call time, so tests set/clear the
// override around each scan. The fixtures use a spaced benign sentence (no
// injection tokens, no 50-char alphanumeric run that would look like base64),
// so `sanitized` equals the (possibly truncated) input, the decision stays
// "allow", and the observable effect of the guard is `sanitized.length`.
// ============================================================

/** Benign filler of exactly `n` code units — spaced words, nothing that trips a rule. */
function benign(n: number): string {
  const base = "lorem ipsum dolor sit amet consectetur adipiscing elit ";
  return base.repeat(Math.ceil(n / base.length)).slice(0, n);
}

describe("AIShield input-size guard", () => {
  const instances: AIShield[] = [];
  const make = (): AIShield => {
    const s = new AIShield();
    instances.push(s);
    return s;
  };

  afterEach(async () => {
    delete process.env.AI_SHIELD_MAX_INPUT_BYTES;
    while (instances.length) await instances.pop()!.close();
  });

  it("truncates input beyond the default 262_144-char cap", async () => {
    const shield = make();
    const r = await shield.scan(benign(262_144 + 500));
    // Benign filler → only the guard's slice changes the text.
    expect(r.sanitized.length).toBe(262_144);
    expect(r.decision).toBe("allow");
    expect(r.safe).toBe(true);
  });

  it("leaves input under the cap untouched", async () => {
    const shield = make();
    const r = await shield.scan(benign(500));
    expect(r.sanitized.length).toBe(500);
    expect(r.decision).toBe("allow");
  });

  it("honours the AI_SHIELD_MAX_INPUT_BYTES override", async () => {
    process.env.AI_SHIELD_MAX_INPUT_BYTES = "100";
    const shield = make();
    const r = await shield.scan(benign(500));
    expect(r.sanitized.length).toBe(100);
    expect(r.decision).toBe("allow");
  });

  it("stays bounded on a very large input (no hang / throw)", async () => {
    const shield = make();
    const huge = benign(5_000_000); // ~5 MB
    const start = performance.now();
    const r = await shield.scan(huge);
    const elapsed = performance.now() - start;
    expect(r.sanitized.length).toBeLessThanOrEqual(262_144);
    // Generous ceiling — the point is "bounded", not a micro-benchmark.
    expect(elapsed).toBeLessThan(2000);
  });
});
