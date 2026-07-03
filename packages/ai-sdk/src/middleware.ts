import type {
  AIShield,
  ShieldConfig,
  ScanContext,
  ScanResult,
  OutputScanConfig,
  OutputScanResult,
} from "ai-shield-core";
import type { LanguageModelMiddleware } from "ai";

// ============================================================
// AI Shield middleware for the Vercel AI SDK (`ai` >= 7)
// Runs the input scan chain in `transformParams` (block / warn /
// PII-mask BEFORE the model call) and optional output scanning in
// `wrapGenerate` / `wrapStream`. Scan results are surfaced under
// `providerMetadata.aiShield` — the AI SDK forwards provider
// metadata to `generateText` / `streamText` results.
//
// API verified against ai@7.0.14 / @ai-sdk/provider@4.0.2:
// `wrapLanguageModel` accepts `LanguageModelMiddleware` (the
// version-relaxed alias of `LanguageModelV4Middleware`) with the
// hooks `transformParams`, `wrapGenerate`, `wrapStream`.
// ============================================================

// --- Types derived from the middleware surface itself ---
// Single source of truth is the `ai` peer dependency; no direct
// dependency on `@ai-sdk/provider` needed.

type TransformParamsHook = NonNullable<LanguageModelMiddleware["transformParams"]>;
type WrapGenerateHook = NonNullable<LanguageModelMiddleware["wrapGenerate"]>;
type WrapStreamHook = NonNullable<LanguageModelMiddleware["wrapStream"]>;

/** `LanguageModelV4CallOptions` — the spec-level params object. */
export type ShieldCallOptions = Awaited<ReturnType<TransformParamsHook>>;
/** `LanguageModelV4Prompt` — the spec-level prompt (array of messages). */
export type ShieldPrompt = ShieldCallOptions["prompt"];
/** `LanguageModelV4GenerateResult` */
type ShieldGenerateResult = Awaited<ReturnType<WrapGenerateHook>>;
/** `LanguageModelV4StreamResult` */
type ShieldStreamResult = Awaited<ReturnType<WrapStreamHook>>;
/** `LanguageModelV4StreamPart` */
type ShieldStreamPart =
  ShieldStreamResult["stream"] extends ReadableStream<infer TPart> ? TPart : never;
/** `SharedV4ProviderMetadata` value slot (`JSONObject`). */
type ShieldMetadataValue = NonNullable<ShieldGenerateResult["providerMetadata"]>[string];

export interface AiSdkMiddlewareConfig {
  /** AI Shield config (or pass an existing AIShield instance) */
  shield?: ShieldConfig;
  /** Pre-created AIShield instance (takes precedence over `shield` config) */
  shieldInstance?: AIShield;
  /** Agent ID for tool policy / cost tracking context */
  agentId?: string;
  /** Custom scan context factory (receives the spec-level prompt) */
  contextFactory?: (prompt: ShieldPrompt) => ScanContext;
  /**
   * Legacy: run the INPUT scan chain (heuristic + PII) over the output too.
   * Default false. For real output-side defense (secret leak, SQL/XSS/shell
   * injection, system-prompt leak) use `outputScan` below (OWASP LLM05).
   */
  scanOutput?: boolean;
  /**
   * Run the dedicated output scanner over the response (OWASP LLM05 / LLM02):
   * secret leak, output injection, system-prompt leak, jailbreak, output-side
   * PII. Pass `true` for defaults or an `OutputScanConfig`. Result lands in
   * `providerMetadata.aiShield.outputScan` (on the generate result, and on
   * the `finish` stream part for streams).
   */
  outputScan?: boolean | OutputScanConfig;
  /** Callback when input is blocked */
  onBlocked?: (result: ScanResult, prompt: ShieldPrompt) => void;
  /** Callback when input has warnings */
  onWarning?: (result: ScanResult, prompt: ShieldPrompt) => void;
}

/**
 * Create an AI Shield middleware for `wrapLanguageModel` from the
 * Vercel AI SDK (`ai` package, v7).
 *
 * - `transformParams` scans the user prompt BEFORE the model call:
 *   `block` throws {@link ShieldBlockError} (the provider is never
 *   called), `warn` fires `onWarning`, and PII masking rewrites the
 *   outgoing prompt.
 * - `wrapGenerate` / `wrapStream` optionally scan the generated text
 *   (`scanOutput` legacy chain and/or the dedicated `outputScan`
 *   scanner) and attach all results under `providerMetadata.aiShield`.
 *   Mirroring the other ai-shield wrappers, output findings are
 *   REPORTED, not blocked — gate on `aiShield.outputScan.safe`
 *   before forwarding output to a downstream sink.
 *
 * @example
 * ```ts
 * import { openai } from "@ai-sdk/openai";
 * import { generateText, wrapLanguageModel } from "ai";
 * import { aiShieldMiddleware } from "ai-shield-ai-sdk";
 *
 * const model = wrapLanguageModel({
 *   model: openai("gpt-4o"),
 *   middleware: aiShieldMiddleware({
 *     shield: { pii: { action: "mask", locale: "de-DE" } },
 *     outputScan: true,
 *   }),
 * });
 *
 * const { text, providerMetadata } = await generateText({ model, prompt: userInput });
 * console.log(providerMetadata?.aiShield);
 * ```
 */
export function aiShieldMiddleware(
  config: AiSdkMiddlewareConfig = {},
): LanguageModelMiddleware {
  let shield: AIShield | null = config.shieldInstance ?? null;
  let shieldReady: Promise<AIShield> | null = null;

  /** Lazy-init shield (avoid import at construction time) */
  function getShield(): Promise<AIShield> {
    if (shield) return Promise.resolve(shield);
    if (!shieldReady) {
      shieldReady = import("ai-shield-core").then((mod) => {
        shield = new mod.AIShield(config.shield ?? {});
        return shield;
      });
    }
    return shieldReady;
  }

  /** Build scan context from the spec-level params */
  function buildContext(params: ShieldCallOptions): ScanContext {
    if (config.contextFactory) {
      return config.contextFactory(params.prompt);
    }

    const context: ScanContext = {};
    if (config.agentId) {
      context.agentId = config.agentId;
    }

    // Include tool names if tools are being passed to the model
    if (params.tools && params.tools.length > 0) {
      context.tools = params.tools.map((t) => ({ name: t.name }));
    }

    return context;
  }

  /**
   * Input scan results, keyed by the (possibly rewritten) params object
   * returned from `transformParams`. `wrapLanguageModel` threads that
   * exact object through to `wrapGenerate` / `wrapStream`, which lets
   * the input result travel without shared mutable state (concurrency-
   * safe: one entry per in-flight call).
   */
  const inputResults = new WeakMap<ShieldCallOptions, ScanResult>();

  /** Run the configured output scans over generated text. */
  async function runOutputScans(
    text: string,
    context: ScanContext,
  ): Promise<{ output?: ScanResult; outputScan?: OutputScanResult }> {
    const results: { output?: ScanResult; outputScan?: OutputScanResult } = {};
    if (config.scanOutput && text) {
      const shieldInstance = await getShield();
      results.output = await shieldInstance.scan(text, context);
    }
    if (config.outputScan && text) {
      const cfg = config.outputScan === true ? {} : config.outputScan;
      const mod = await import("ai-shield-core");
      results.outputScan = await mod.scanOutput(text, cfg, context);
    }
    return results;
  }

  /** Assemble the `providerMetadata.aiShield` payload. */
  function buildShieldMetadata(parts: {
    input?: ScanResult;
    output?: ScanResult;
    outputScan?: OutputScanResult;
  }): ShieldMetadataValue {
    // JSON round-trip guarantees the payload is a plain JSONObject
    // (drops undefined keys) as required by SharedV4ProviderMetadata.
    return JSON.parse(JSON.stringify(parts)) as ShieldMetadataValue;
  }

  return {
    transformParams: async ({ params }) => {
      const shieldInstance = await getShield();
      const context = buildContext(params);
      const userText = extractUserText(params.prompt);

      const inputResult = await shieldInstance.scan(userText, context);

      if (inputResult.decision === "block") {
        config.onBlocked?.(inputResult, params.prompt);
        throw new ShieldBlockError("Input blocked by AI Shield", inputResult);
      }

      if (inputResult.decision === "warn") {
        config.onWarning?.(inputResult, params.prompt);
      }

      // Replace sanitized content if PII was masked
      let finalParams = params;
      if (inputResult.sanitized !== userText) {
        finalParams = {
          ...params,
          prompt: replaceUserText(params.prompt, inputResult.sanitized),
        };
      }

      inputResults.set(finalParams, inputResult);
      return finalParams;
    },

    wrapGenerate: async ({ doGenerate, params }) => {
      const result = await doGenerate();

      const inputResult = inputResults.get(params);
      const outputText = extractOutputText(result.content);
      const scans = await runOutputScans(outputText, buildContext(params));

      return {
        ...result,
        providerMetadata: {
          ...result.providerMetadata,
          aiShield: buildShieldMetadata({ input: inputResult, ...scans }),
        },
      };
    },

    wrapStream: async ({ doStream, params }) => {
      const { stream, ...rest } = await doStream();

      const inputResult = inputResults.get(params);
      const context = buildContext(params);
      let fullText = "";

      const transform = new TransformStream<ShieldStreamPart, ShieldStreamPart>({
        transform: async (part, controller) => {
          if (part.type === "text-delta") {
            fullText += part.delta;
            controller.enqueue(part);
            return;
          }

          if (part.type === "finish") {
            // Post-stream output scan (the text has already been
            // emitted — findings are reported, not blocked, exactly
            // like the other ai-shield streaming wrappers).
            const scans = await runOutputScans(fullText, context);
            controller.enqueue({
              ...part,
              providerMetadata: {
                ...part.providerMetadata,
                aiShield: buildShieldMetadata({ input: inputResult, ...scans }),
              },
            });
            return;
          }

          controller.enqueue(part);
        },
      });

      return { ...rest, stream: stream.pipeThrough(transform) };
    },
  };
}

// --- Prompt / content text extraction ---

/** Extract text content from user messages for scanning */
function extractUserText(prompt: ShieldPrompt): string {
  const parts: string[] = [];

  for (const msg of prompt) {
    // Only scan user messages (not system/assistant/tool)
    if (msg.role !== "user") continue;

    for (const part of msg.content) {
      if (part.type === "text" && part.text) {
        parts.push(part.text);
      }
    }
  }

  return parts.join("\n");
}

/** Replace user message text with the sanitized version */
function replaceUserText(prompt: ShieldPrompt, sanitized: string): ShieldPrompt {
  let remaining = sanitized;

  return prompt.map((msg) => {
    if (msg.role !== "user") return msg;

    const content = msg.content.map((part) => {
      if (part.type === "text" && part.text) {
        const replacement = remaining.substring(0, part.text.length);
        remaining = remaining.substring(part.text.length + 1); // +1 for "\n" joiner
        return { ...part, text: replacement };
      }
      return part;
    });

    return { ...msg, content };
  });
}

/** Extract generated text segments from the result content */
function extractOutputText(content: ShieldGenerateResult["content"]): string {
  const parts: string[] = [];
  for (const item of content) {
    if (item.type === "text" && item.text) {
      parts.push(item.text);
    }
  }
  return parts.join("");
}

// --- Error types ---

export class ShieldBlockError extends Error {
  constructor(
    message: string,
    public readonly scanResult: ScanResult,
  ) {
    super(message);
    this.name = "ShieldBlockError";
  }
}
