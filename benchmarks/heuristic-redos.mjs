import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import console from "node:console";
import { HeuristicScanner } from "../packages/core/dist/scanner/heuristic.js";

// Measure the actual scanner after warmup, using medians rather than a single
// wall-clock deadline. The 3x input must grow by less than 6x: the original
// ROLE-007 grows by about 9x. This guards growth, not a latency promise.
const scanner = new HeuristicScanner();
const samples = [];
for (const bytes of [80_000, 160_000, 240_000]) {
  const input = "DAN ".repeat(bytes / 4);
  await scanner.scan(input, {});
  const timings = [];
  for (let sample = 0; sample < 5; sample++) {
    const start = performance.now();
    const result = await scanner.scan(input, {});
    timings.push(performance.now() - start);
    assert.equal(result.decision, "allow");
  }
  timings.sort((a, b) => a - b);
  samples.push({ bytes, medianMs: timings[2] });
}
const growth = samples[2].medianMs / Math.max(1, samples[0].medianMs);
console.log(JSON.stringify({ samples, growth, maximumGrowth: 6 }, null, 2));
assert.ok(growth < 6, `3x input grew by ${growth.toFixed(2)}x (expected <6x)`);
