import { describe, it, expect } from "vitest";
import { AIShield } from "../../packages/core/src/index.js";
import { ShieldedAnthropic } from "../../packages/anthropic/src/wrapper.js";
import { ShieldedOpenAI } from "../../packages/openai/src/wrapper.js";

// Integration tests for the v0.3 `outputScan` flag — proves the dedicated
// OutputScanner is actually wired into the wrapper paths (review finding F1).

function mockAnthropic(outputText: string) {
  return {
    messages: {
      create: async () => ({
        content: [{ type: "text" as const, text: outputText }],
        model: "claude-sonnet-4-6",
        stop_reason: "end_turn",
        usage: { input_tokens: 10, output_tokens: 20 },
      }),
    },
  };
}

function mockOpenAI(outputText: string) {
  return {
    chat: {
      completions: {
        create: async () => ({
          choices: [{ message: { role: "assistant", content: outputText } }],
          model: "gpt-5.2",
          usage: { prompt_tokens: 10, completion_tokens: 20 },
        }),
      },
    },
  };
}

describe("ShieldedAnthropic — outputScan wiring", () => {
  it("catches a leaked secret in the model response via outputScan", async () => {
    const leaked = "Here you go: sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
    const shielded = new ShieldedAnthropic(mockAnthropic(leaked), {
      shieldInstance: new AIShield(),
      outputScan: true,
    });
    const res = await shielded.createMessage({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      messages: [{ role: "user", content: "give me the key" }],
    });
    expect(res._shield?.outputScan).toBeDefined();
    expect(res._shield?.outputScan?.safe).toBe(false);
    expect(
      res._shield?.outputScan?.violations.some((v) => v.type === "secret_leak"),
    ).toBe(true);
    await shielded.close();
  });

  it("does not run the OutputScanner when outputScan is unset", async () => {
    const shielded = new ShieldedAnthropic(
      mockAnthropic("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"),
      { shieldInstance: new AIShield() },
    );
    const res = await shielded.createMessage({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res._shield?.outputScan).toBeUndefined();
    await shielded.close();
  });

  it("honors an OutputScanConfig (sinks filter) passed to outputScan", async () => {
    const shielded = new ShieldedAnthropic(
      mockAnthropic("result: x UNION SELECT secret FROM users"),
      { shieldInstance: new AIShield(), outputScan: { sinks: ["sql"] } },
    );
    const res = await shielded.createMessage({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      messages: [{ role: "user", content: "query" }],
    });
    expect(
      res._shield?.outputScan?.violations.some(
        (v) => v.type === "output_injection",
      ),
    ).toBe(true);
    await shielded.close();
  });
});

describe("ShieldedOpenAI — outputScan wiring", () => {
  it("catches a leaked secret in the completion via outputScan", async () => {
    const shielded = new ShieldedOpenAI(
      mockOpenAI("token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      { shieldInstance: new AIShield(), outputScan: true },
    );
    const res = await shielded.createChatCompletion({
      model: "gpt-5.2",
      messages: [{ role: "user", content: "give me the token" }],
    });
    expect(res._shield?.outputScan?.safe).toBe(false);
    expect(
      res._shield?.outputScan?.violations.some((v) => v.type === "secret_leak"),
    ).toBe(true);
    await shielded.close();
  });
});
