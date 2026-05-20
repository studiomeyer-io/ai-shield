import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  CircuitBreakerRegistry,
  makeBreakerScope,
} from "../../packages/core/src/policy/circuit-breaker.js";
import type {
  CircuitBreakerConfig,
  ToolCall,
  ScanContext,
  CounterStoreLike,
} from "../../packages/core/src/types.js";

// ============================================================
// CircuitBreakerRegistry — unit tests
//
// Covers: construction + configure(), happy-path check(),
// state transitions (closed → open → half-open → closed),
// rate-limit cap, blast-radius cap, HITL gate, inspect(),
// violationType(), LRU eviction, window pruning, custom store,
// adversarial scenarios.
// ============================================================

describe("CircuitBreakerRegistry", () => {
  // --- shared fixtures ---

  const ctx = (
    agentId: string | undefined = "agent-a",
    sessionId: string | undefined = "session-1",
  ): ScanContext => ({ agentId, sessionId });

  const callOf = (name: string): ToolCall => ({ name });

  afterEach(() => {
    // Always restore real timers between tests — vi.useFakeTimers in any
    // suite leaks into siblings otherwise.
    vi.useRealTimers();
  });

  // ==========================================================
  // A. Registry construction + configure()
  // ==========================================================

  describe("A. construction + configure()", () => {
    it("works with empty config array — all checks allowed/closed", async () => {
      const reg = new CircuitBreakerRegistry([]);
      const result = await reg.check(callOf("delete_user"), ctx());
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");
    });

    it("accepts a single config via constructor", async () => {
      const reg = new CircuitBreakerRegistry([
        { tool: "fetch_url", maxCallsPerWindow: 1 },
      ]);
      const ctxNoScope: ScanContext = {};
      const first = await reg.check(callOf("fetch_url"), ctxNoScope);
      const second = await reg.check(callOf("fetch_url"), ctxNoScope);
      expect(first.allowed).toBe(true);
      expect(second.allowed).toBe(false);
      expect(second.reason).toBe("rate_limit");
    });

    it("distinguishes configs by tool and scope", async () => {
      const reg = new CircuitBreakerRegistry([
        { tool: "send_email", scope: "agent-x", maxCallsPerWindow: 1 },
        { tool: "send_email", scope: "agent-y", maxCallsPerWindow: 5 },
      ]);
      // agent-x exhausted after one call
      const x1 = await reg.check(callOf("send_email"), { agentId: "agent-x" });
      const x2 = await reg.check(callOf("send_email"), { agentId: "agent-x" });
      expect(x1.allowed).toBe(true);
      expect(x2.allowed).toBe(false);
      expect(x2.reason).toBe("rate_limit");
      // agent-y still has budget
      const y1 = await reg.check(callOf("send_email"), { agentId: "agent-y" });
      expect(y1.allowed).toBe(true);
    });

    it("configure() is idempotent — calling twice with same key still works", async () => {
      const reg = new CircuitBreakerRegistry();
      const cfg: CircuitBreakerConfig = {
        tool: "drop_table",
        maxCallsPerWindow: 2,
      };
      reg.configure(cfg);
      reg.configure(cfg);
      reg.configure({ ...cfg, maxCallsPerWindow: 3 });
      // After third configure (overrides), 3 calls allowed.
      const c1 = await reg.check(callOf("drop_table"), {});
      const c2 = await reg.check(callOf("drop_table"), {});
      const c3 = await reg.check(callOf("drop_table"), {});
      const c4 = await reg.check(callOf("drop_table"), {});
      expect([c1.allowed, c2.allowed, c3.allowed]).toEqual([true, true, true]);
      expect(c4.allowed).toBe(false);
      expect(c4.reason).toBe("rate_limit");
    });

    it("applies defaults when optional fields omitted", async () => {
      // With only `tool` set, failureThreshold defaults to 5, windowMs to
      // 60_000, cooldownMs to 60_000, maxCallsPerWindow/maxWritesPerWindow
      // to Infinity, onDestructive to () => true.
      const reg = new CircuitBreakerRegistry([{ tool: "noop_tool" }]);

      // Default failureThreshold = 5 → 4 failures shouldn't trip.
      for (let i = 0; i < 4; i++) {
        reg.recordFailure("noop_tool");
      }
      const stillClosed = await reg.check(callOf("noop_tool"), {});
      expect(stillClosed.allowed).toBe(true);
      expect(stillClosed.state).toBe("closed");

      // 5th failure → tripped.
      reg.recordFailure("noop_tool");
      const opened = await reg.check(callOf("noop_tool"), {});
      expect(opened.allowed).toBe(false);
      expect(opened.state).toBe("open");
      expect(opened.reason).toBe("circuit_open");
      // retryAfterMs ~ cooldownMs default = 60_000.
      expect(opened.retryAfterMs).toBeGreaterThan(0);
      expect(opened.retryAfterMs!).toBeLessThanOrEqual(60_000);
    });
  });

  // ==========================================================
  // B. check() happy path
  // ==========================================================

  describe("B. check() happy path", () => {
    let reg: CircuitBreakerRegistry;

    beforeEach(() => {
      reg = new CircuitBreakerRegistry();
    });

    it("allows when no config registered for that tool", async () => {
      const result = await reg.check(callOf("unknown_tool"), ctx());
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");
      expect(result.reason).toBeUndefined();
    });

    it("allows when registered and state=closed", async () => {
      reg.configure({ tool: "get_thing" });
      const result = await reg.check(callOf("get_thing"), ctx());
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");
    });

    it("records call timestamp — inspect() shows callsInWindow increased", async () => {
      reg.configure({ tool: "get_thing", scope: makeBreakerScope("agent-a", "session-1") });
      await reg.check(callOf("get_thing"), ctx());
      await reg.check(callOf("get_thing"), ctx());
      const snap = reg.inspect("get_thing", makeBreakerScope("agent-a", "session-1"));
      expect(snap).not.toBeNull();
      expect(snap!.callsInWindow).toBe(2);
    });

    it("records write timestamp for destructive tools — inspect() shows writesInWindow", async () => {
      reg.configure({ tool: "delete_user", scope: makeBreakerScope("agent-a", "session-1") });
      await reg.check(callOf("delete_user"), ctx());
      const snap = reg.inspect("delete_user", makeBreakerScope("agent-a", "session-1"));
      expect(snap).not.toBeNull();
      expect(snap!.callsInWindow).toBe(1);
      expect(snap!.writesInWindow).toBe(1);
    });

    it("isolates different scopes — same tool, different agentId+sessionId", async () => {
      reg.configure({ tool: "do_thing", scope: makeBreakerScope("agent-a", "session-1") });
      reg.configure({ tool: "do_thing", scope: makeBreakerScope("agent-b", "session-2") });
      await reg.check(callOf("do_thing"), {
        agentId: "agent-a",
        sessionId: "session-1",
      });
      await reg.check(callOf("do_thing"), {
        agentId: "agent-a",
        sessionId: "session-1",
      });
      await reg.check(callOf("do_thing"), {
        agentId: "agent-b",
        sessionId: "session-2",
      });

      const aSnap = reg.inspect("do_thing", makeBreakerScope("agent-a", "session-1"));
      const bSnap = reg.inspect("do_thing", makeBreakerScope("agent-b", "session-2"));
      expect(aSnap!.callsInWindow).toBe(2);
      expect(bSnap!.callsInWindow).toBe(1);
    });

    it("scopeFor(): uses agentId+sessionId when both, just one when one, empty when neither", async () => {
      // Three configs with empty scope (the default key).
      reg.configure({ tool: "scoped_tool" });

      // Both set → composite scope makeBreakerScope("agent-a", "session-1")
      await reg.check(callOf("scoped_tool"), {
        agentId: "agent-a",
        sessionId: "session-1",
      });
      // Only agentId
      await reg.check(callOf("scoped_tool"), { agentId: "agent-a" });
      // Only sessionId
      await reg.check(callOf("scoped_tool"), { sessionId: "session-1" });
      // Neither
      await reg.check(callOf("scoped_tool"), {});

      // All four calls hit different scope keys but share the same
      // empty-scope config (fallback lookup). Inspect them via the
      // exact scope strings the impl uses.
      expect(reg.inspect("scoped_tool", makeBreakerScope("agent-a", "session-1"))!.callsInWindow).toBe(1);
      expect(reg.inspect("scoped_tool", "agent-a")!.callsInWindow).toBe(1);
      expect(reg.inspect("scoped_tool", "session-1")!.callsInWindow).toBe(1);
      expect(reg.inspect("scoped_tool", "")!.callsInWindow).toBe(1);
    });
  });

  // ==========================================================
  // C. State transitions
  // ==========================================================

  describe("C. state transitions", () => {
    let reg: CircuitBreakerRegistry;

    beforeEach(() => {
      reg = new CircuitBreakerRegistry([
        {
          tool: "flaky_tool",
          failureThreshold: 3,
          cooldownMs: 5_000,
          windowMs: 60_000,
        },
      ]);
    });

    it("recordFailure() accumulates and trips at threshold", async () => {
      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      // 2 failures — still closed.
      const beforeTrip = await reg.check(callOf("flaky_tool"), {});
      expect(beforeTrip.allowed).toBe(true);
      expect(beforeTrip.state).toBe("closed");

      reg.recordFailure("flaky_tool");
      const afterTrip = await reg.check(callOf("flaky_tool"), {});
      expect(afterTrip.allowed).toBe(false);
      expect(afterTrip.state).toBe("open");
      expect(afterTrip.reason).toBe("circuit_open");
    });

    it("open circuit returns retryAfterMs and refuses calls", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");

      const result = await reg.check(callOf("flaky_tool"), {});
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("circuit_open");
      expect(result.retryAfterMs).toBeGreaterThan(0);
      expect(typeof result.retryAfterMs).toBe("number");
      expect(result.message).toContain("Circuit OPEN");
    });

    it("retryAfterMs decreases as time passes", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");

      const r1 = await reg.check(callOf("flaky_tool"), {});
      vi.advanceTimersByTime(2_000);
      const r2 = await reg.check(callOf("flaky_tool"), {});

      expect(r1.allowed).toBe(false);
      expect(r2.allowed).toBe(false);
      expect(r2.retryAfterMs).toBeLessThan(r1.retryAfterMs!);
      // Roughly 2s shorter.
      expect(r1.retryAfterMs! - r2.retryAfterMs!).toBeGreaterThanOrEqual(1_900);
    });

    it("after cooldown elapses, next check flips to half-open and allows", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");

      // Confirm tripped.
      const opened = await reg.check(callOf("flaky_tool"), {});
      expect(opened.allowed).toBe(false);
      expect(opened.state).toBe("open");

      // Advance past cooldownMs (5_000).
      vi.advanceTimersByTime(5_500);

      const halfOpen = await reg.check(callOf("flaky_tool"), {});
      expect(halfOpen.allowed).toBe(true);
      expect(halfOpen.state).toBe("half-open");
    });

    it("recordSuccess() in half-open → closes circuit and resets failures", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      vi.advanceTimersByTime(5_500);
      // Trigger half-open transition.
      await reg.check(callOf("flaky_tool"), {});

      reg.recordSuccess("flaky_tool");

      const snap = reg.inspect("flaky_tool", "");
      expect(snap!.state).toBe("closed");
      expect(snap!.failuresInWindow).toBe(0);

      // Subsequent calls allowed.
      const ok = await reg.check(callOf("flaky_tool"), {});
      expect(ok.allowed).toBe(true);
      expect(ok.state).toBe("closed");
    });

    it("recordFailure() in half-open re-trips once threshold is hit", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      reg.recordFailure("flaky_tool");
      vi.advanceTimersByTime(5_500);
      // Flip to half-open.
      await reg.check(callOf("flaky_tool"), {});
      // Half-open state still carries previous failure timestamps; one
      // more failure pushes the count over threshold again. (The current
      // impl does NOT reset failures when transitioning open→half-open —
      // it only clears them on recordSuccess in half-open. So even ONE
      // more failure re-opens.)
      reg.recordFailure("flaky_tool");

      const snap = reg.inspect("flaky_tool", "");
      expect(snap!.state).toBe("open");

      const blocked = await reg.check(callOf("flaky_tool"), {});
      expect(blocked.allowed).toBe(false);
      expect(blocked.reason).toBe("circuit_open");
    });

    it("trip() and reset() are manual escape hatches", async () => {
      reg.trip("flaky_tool");
      const blocked = await reg.check(callOf("flaky_tool"), {});
      expect(blocked.allowed).toBe(false);
      expect(blocked.state).toBe("open");

      reg.reset("flaky_tool");
      // After reset, state object is gone → inspect returns null.
      expect(reg.inspect("flaky_tool", "")).toBeNull();
      // Fresh check allowed again.
      const ok = await reg.check(callOf("flaky_tool"), {});
      expect(ok.allowed).toBe(true);
      expect(ok.state).toBe("closed");
    });
  });

  // ==========================================================
  // D. Rate-limit cap (maxCallsPerWindow)
  // ==========================================================

  describe("D. rate-limit cap", () => {
    it("N calls allowed, N+1 denied with reason=rate_limit", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "get_thing",
          maxCallsPerWindow: 3,
          windowMs: 60_000,
        },
      ]);
      const c1 = await reg.check(callOf("get_thing"), {});
      const c2 = await reg.check(callOf("get_thing"), {});
      const c3 = await reg.check(callOf("get_thing"), {});
      const c4 = await reg.check(callOf("get_thing"), {});
      expect([c1.allowed, c2.allowed, c3.allowed]).toEqual([true, true, true]);
      expect(c4.allowed).toBe(false);
      expect(c4.reason).toBe("rate_limit");
      expect(c4.retryAfterMs).toBe(60_000);
    });

    it("after window expires, counter resets", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      const reg = new CircuitBreakerRegistry([
        {
          tool: "get_thing",
          maxCallsPerWindow: 2,
          windowMs: 10_000,
        },
      ]);

      await reg.check(callOf("get_thing"), {});
      await reg.check(callOf("get_thing"), {});
      const blocked = await reg.check(callOf("get_thing"), {});
      expect(blocked.allowed).toBe(false);
      expect(blocked.reason).toBe("rate_limit");

      // Advance past window.
      vi.advanceTimersByTime(11_000);

      const fresh = await reg.check(callOf("get_thing"), {});
      expect(fresh.allowed).toBe(true);
      // Old timestamps pruned — only the new one is in window.
      const snap = reg.inspect("get_thing", "");
      expect(snap!.callsInWindow).toBe(1);
    });

    it("rate-limit is independent per scope", async () => {
      const reg = new CircuitBreakerRegistry([
        { tool: "do_thing", scope: "agent-a", maxCallsPerWindow: 1 },
        { tool: "do_thing", scope: "agent-b", maxCallsPerWindow: 1 },
      ]);

      const a1 = await reg.check(callOf("do_thing"), { agentId: "agent-a" });
      const a2 = await reg.check(callOf("do_thing"), { agentId: "agent-a" });
      const b1 = await reg.check(callOf("do_thing"), { agentId: "agent-b" });

      expect(a1.allowed).toBe(true);
      expect(a2.allowed).toBe(false);
      expect(a2.reason).toBe("rate_limit");
      // Different scope unaffected.
      expect(b1.allowed).toBe(true);
    });

    it("mixed reads + writes count toward the same call budget", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "send_email",
          maxCallsPerWindow: 2,
          // maxWritesPerWindow not set → Infinity (so cap is the call cap).
        },
      ]);
      // send_email is destructive by prefix → all 3 calls count toward
      // the same 2-call call-budget.
      const r1 = await reg.check(callOf("send_email"), {});
      const r2 = await reg.check(callOf("send_email"), {});
      const r3 = await reg.check(callOf("send_email"), {});
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
      expect(r3.allowed).toBe(false);
      expect(r3.reason).toBe("rate_limit");
    });
  });

  // ==========================================================
  // E. Blast-radius cap (maxWritesPerWindow)
  // ==========================================================

  describe("E. blast-radius cap", () => {
    it("only counts tools matching the destructive prefix list", async () => {
      // delete_, remove_, drop_, destroy_, wipe_, shutdown_, purge_,
      // truncate_, send_email, transfer_, payment_.
      const reg = new CircuitBreakerRegistry();
      const prefixes = [
        "delete_user",
        "remove_record",
        "drop_table",
        "destroy_session",
        "wipe_disk",
        "shutdown_service",
        "purge_cache",
        "truncate_logs",
        "send_email",
        "transfer_funds",
        "payment_charge",
      ];
      for (const tool of prefixes) {
        reg.configure({ tool, maxWritesPerWindow: 1 });
      }

      // Each fires twice — 2nd should be blocked by blast-radius.
      for (const tool of prefixes) {
        const first = await reg.check(callOf(tool), {});
        const second = await reg.check(callOf(tool), {});
        expect(first.allowed).toBe(true);
        expect(second.allowed).toBe(false);
        expect(second.reason).toBe("blast_radius_exceeded");
      }
    });

    it("read-only tool calls do not decrement the write budget", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "get_record",
          maxWritesPerWindow: 1,
        },
      ]);
      // get_record is NOT in the destructive prefix list.
      const r1 = await reg.check(callOf("get_record"), {});
      const r2 = await reg.check(callOf("get_record"), {});
      const r3 = await reg.check(callOf("get_record"), {});
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
      expect(r3.allowed).toBe(true);
      const snap = reg.inspect("get_record", "");
      expect(snap!.writesInWindow).toBe(0);
      expect(snap!.callsInWindow).toBe(3);
    });

    it("excess write returns reason=blast_radius_exceeded", async () => {
      const reg = new CircuitBreakerRegistry([
        { tool: "delete_user", maxWritesPerWindow: 2 },
      ]);
      await reg.check(callOf("delete_user"), {});
      await reg.check(callOf("delete_user"), {});
      const blocked = await reg.check(callOf("delete_user"), {});
      expect(blocked.allowed).toBe(false);
      expect(blocked.reason).toBe("blast_radius_exceeded");
      expect(blocked.retryAfterMs).toBe(60_000);
      expect(blocked.message).toContain("Blast-radius cap");
    });

    it("isDestructive: true forces a non-prefix tool to count as destructive", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "innocuous_lookup",
          isDestructive: true,
          maxWritesPerWindow: 1,
        },
      ]);
      const first = await reg.check(callOf("innocuous_lookup"), {});
      const second = await reg.check(callOf("innocuous_lookup"), {});
      expect(first.allowed).toBe(true);
      expect(second.allowed).toBe(false);
      expect(second.reason).toBe("blast_radius_exceeded");
    });
  });

  // ==========================================================
  // F. HITL gate (onDestructive)
  // ==========================================================

  describe("F. HITL gate", () => {
    it("returns false → reason=hitl_denied, allowed=false", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          onDestructive: () => false,
        },
      ]);
      const r = await reg.check(callOf("delete_user"), {});
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("hitl_denied");
      expect(r.message).toContain("Human-in-the-loop denied");
    });

    it("returns true → call proceeds", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          onDestructive: () => true,
        },
      ]);
      const r = await reg.check(callOf("delete_user"), {});
      expect(r.allowed).toBe(true);
      expect(r.state).toBe("closed");
    });

    it("async callback resolving true also works", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          onDestructive: async () => {
            await new Promise((resolve) => setTimeout(resolve, 0));
            return true;
          },
        },
      ]);
      const r = await reg.check(callOf("delete_user"), {});
      expect(r.allowed).toBe(true);
    });

    it("callback that throws is treated as denial", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          onDestructive: () => {
            throw new Error("hook crashed");
          },
        },
      ]);
      const r = await reg.check(callOf("delete_user"), {});
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("hitl_denied");
      expect(r.message).toContain("hook crashed");
    });

    it("hook receives { tool, scope, context }", async () => {
      const spy = vi.fn(() => true);
      // Register with the composite scope built via makeBreakerScope so
      // the config lookup hits the exact scope the runtime derives from
      // (agentId, sessionId) — the separator is implementation detail.
      const scope = makeBreakerScope("agent-x", "session-9");
      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          scope,
          onDestructive: spy,
        },
      ]);
      const context: ScanContext = {
        agentId: "agent-x",
        sessionId: "session-9",
      };
      await reg.check(callOf("delete_user"), context);

      expect(spy).toHaveBeenCalledTimes(1);
      const arg = spy.mock.calls[0]![0] as {
        tool: string;
        scope?: string;
        context: ScanContext;
      };
      expect(arg.tool).toBe("delete_user");
      expect(arg.scope).toBe(scope);
      expect(arg.context).toEqual(context);
    });
  });

  // ==========================================================
  // G. inspect() + violationType()
  // ==========================================================

  describe("G. inspect() + violationType()", () => {
    it("inspect() returns null when no state exists yet", () => {
      const reg = new CircuitBreakerRegistry([{ tool: "get_thing" }]);
      // Configured but never invoked → no state.
      expect(reg.inspect("get_thing", "")).toBeNull();
      // Never configured → also null.
      expect(reg.inspect("unknown_tool", "")).toBeNull();
    });

    it("inspect() returns state + counts after activity", async () => {
      const reg = new CircuitBreakerRegistry([
        { tool: "delete_user", scope: makeBreakerScope("agent-a", "session-1") },
      ]);
      const c: ScanContext = { agentId: "agent-a", sessionId: "session-1" };
      await reg.check(callOf("delete_user"), c);
      await reg.check(callOf("delete_user"), c);
      reg.recordFailure("delete_user", c);

      const snap = reg.inspect("delete_user", makeBreakerScope("agent-a", "session-1"));
      expect(snap).not.toBeNull();
      expect(snap!.state).toBe("closed");
      expect(snap!.callsInWindow).toBe(2);
      expect(snap!.writesInWindow).toBe(2);
      expect(snap!.failuresInWindow).toBe(1);
    });

    it("violationType() maps decisions correctly", () => {
      const T = CircuitBreakerRegistry.violationType;
      expect(
        T({ allowed: false, state: "open", reason: "circuit_open" }),
      ).toBe("circuit_breaker_open");
      expect(
        T({
          allowed: false,
          state: "closed",
          reason: "blast_radius_exceeded",
        }),
      ).toBe("blast_radius_exceeded");
      expect(
        T({ allowed: false, state: "closed", reason: "rate_limit" }),
      ).toBe("tool_rate_limit");
      expect(
        T({ allowed: false, state: "closed", reason: "hitl_denied" }),
      ).toBe("tool_denied");
      // Allowed decision falls through to tool_denied as the default
      // bucket (no other reason).
      expect(T({ allowed: true, state: "closed" })).toBe("tool_denied");
    });
  });

  // ==========================================================
  // H. Resource bounds / memory safety
  // ==========================================================

  describe("H. resource bounds", () => {
    it("LRU eviction kicks in beyond maxKeys", async () => {
      const reg = new CircuitBreakerRegistry(
        [
          { tool: "t1" },
          { tool: "t2" },
          { tool: "t3" },
          { tool: "t4" },
          { tool: "t5" },
        ],
        { maxKeys: 3 },
      );
      // Fire 5 distinct (tool, "") keys in order.
      await reg.check(callOf("t1"), {});
      await reg.check(callOf("t2"), {});
      await reg.check(callOf("t3"), {});
      // At this point states.size = 3 (cap). Adding a 4th evicts t1.
      await reg.check(callOf("t4"), {});
      await reg.check(callOf("t5"), {});

      // t1 evicted → inspect returns null (state gone, config still there).
      expect(reg.inspect("t1", "")).toBeNull();
      // The two oldest remaining keys are also at risk. The impl evicts
      // the OLDEST on each new insertion past the cap, so after inserting
      // t4 and t5, t1 and t2 are both gone.
      expect(reg.inspect("t2", "")).toBeNull();
      // t3, t4, t5 should be the surviving three.
      expect(reg.inspect("t3", "")).not.toBeNull();
      expect(reg.inspect("t4", "")).not.toBeNull();
      expect(reg.inspect("t5", "")).not.toBeNull();
    });

    it("window pruning drops timestamps older than windowMs", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          windowMs: 10_000,
          failureThreshold: 100, // high so failures don't trip.
        },
      ]);
      // Three calls + three failures at t=0.
      await reg.check(callOf("delete_user"), {});
      await reg.check(callOf("delete_user"), {});
      await reg.check(callOf("delete_user"), {});
      reg.recordFailure("delete_user");
      reg.recordFailure("delete_user");
      reg.recordFailure("delete_user");

      let snap = reg.inspect("delete_user", "");
      expect(snap!.callsInWindow).toBe(3);
      expect(snap!.writesInWindow).toBe(3);
      expect(snap!.failuresInWindow).toBe(3);

      // Advance past the window — pruning happens during inspect().
      vi.advanceTimersByTime(11_000);

      snap = reg.inspect("delete_user", "");
      expect(snap!.callsInWindow).toBe(0);
      expect(snap!.writesInWindow).toBe(0);
      expect(snap!.failuresInWindow).toBe(0);
    });
  });

  // ==========================================================
  // I. Custom CounterStoreLike
  // ==========================================================

  describe("I. custom CounterStoreLike", () => {
    it("uses the supplied mock store for the store field", () => {
      const mockStore: CounterStoreLike = {
        get: vi.fn(async () => null),
        incrbyfloat: vi.fn(async () => "1"),
        expire: vi.fn(async () => 1),
      };
      const reg = new CircuitBreakerRegistry([], { counterStore: mockStore });

      // The store is a private field, but its presence is observable:
      // we instantiate the registry with it and assert the mock object
      // is the same identity via a runtime probe.
      // We use Reflect-style access here because there's no public
      // accessor on the class.
      const internalStore = (reg as unknown as { store: CounterStoreLike })
        .store;
      expect(internalStore).toBe(mockStore);
    });

    it("falls back to in-memory store when none supplied", () => {
      const reg = new CircuitBreakerRegistry();
      const internalStore = (reg as unknown as { store: CounterStoreLike })
        .store;
      expect(internalStore).toBeDefined();
      // The default is an InMemoryCounter instance — has get/incrbyfloat/expire.
      expect(typeof internalStore.get).toBe("function");
      expect(typeof internalStore.incrbyfloat).toBe("function");
      expect(typeof internalStore.expire).toBe("function");
    });
  });

  // ==========================================================
  // J. Adversarial scenarios
  // ==========================================================

  describe("J. adversarial scenarios", () => {
    it("attacker spamming delete_user is cut off after small N", async () => {
      const reg = new CircuitBreakerRegistry([
        {
          tool: "delete_user",
          maxWritesPerWindow: 2,
          windowMs: 60_000,
        },
      ]);
      const attacker: ScanContext = {
        agentId: "compromised-agent",
        sessionId: "evil-session",
      };

      const attempts = [];
      for (let i = 0; i < 10; i++) {
        attempts.push(await reg.check(callOf("delete_user"), attacker));
      }

      // First two get through; the rest blocked.
      expect(attempts[0]!.allowed).toBe(true);
      expect(attempts[1]!.allowed).toBe(true);
      for (let i = 2; i < 10; i++) {
        expect(attempts[i]!.allowed).toBe(false);
        expect(attempts[i]!.reason).toBe("blast_radius_exceeded");
      }
    });

    it("long-running slow-drip attack still trips because failures accumulate within rolling window", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-05-20T10:00:00Z"));

      const reg = new CircuitBreakerRegistry([
        {
          tool: "exploit_tool",
          failureThreshold: 5,
          windowMs: 15 * 60_000, // 15-minute window
          cooldownMs: 60 * 60_000, // 1h cooldown — long enough that
          // the trip sticks while we observe.
        },
      ]);

      // Drip a failure every 2 minutes. After 5 failures within the
      // 15-min rolling window the breaker trips. Deliberately DO NOT
      // advance time after the last failure — we want to observe the
      // open state at the moment of the trip, before any cooldown can
      // leak in and flip back to half-open.
      for (let i = 0; i < 5; i++) {
        reg.recordFailure("exploit_tool");
        if (i < 4) {
          vi.advanceTimersByTime(2 * 60_000);
        }
      }

      const blocked = await reg.check(callOf("exploit_tool"), {});
      expect(blocked.allowed).toBe(false);
      expect(blocked.reason).toBe("circuit_open");
    });
  });
});
