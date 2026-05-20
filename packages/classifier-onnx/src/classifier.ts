import type {
  Scanner,
  ScannerResult,
  ScanContext,
  Violation,
} from "ai-shield-core";

// ============================================================
// OnnxInjectionScanner — ML-backed prompt-injection detection
//
// Implements the `Scanner` interface from ai-shield-core. Designed to
// be added to a `ScannerChain` after the heuristic scanner so that
// known patterns short-circuit on cheap regex AND novel paraphrases
// still get a second-pass ML check.
//
// The runtime is abstracted via `OnnxInferenceRuntime` so this file
// has zero hard dependency on `onnxruntime-node` at type-check time.
// At runtime you pass in either:
//   1. An already-constructed `ort.InferenceSession`
//      (`new OnnxInjectionScanner({ session, tokenizer })`)
//   2. A path to a `.onnx` model file + a path to a `tokenizer.json`
//      (`await loadOnnxClassifier({ modelPath, tokenizerPath })`)
//
// Both paths keep the dep injection clean and unit-testable.
// ============================================================

/**
 * Minimal subset of `onnxruntime-node`'s `InferenceSession` we use.
 * Declaring it locally means this package type-checks even when
 * `onnxruntime-node` is not installed (which is the entire point —
 * it's an optional peer dep).
 */
export interface OnnxInferenceRuntime {
  run(
    feeds: Record<string, OnnxTensorLike>,
  ): Promise<Record<string, OnnxTensorLike>>;
  readonly inputNames?: readonly string[];
  readonly outputNames?: readonly string[];
}

/** Tensor descriptor compatible with `onnxruntime-common`'s Tensor. */
export interface OnnxTensorLike {
  readonly data: ArrayLike<number> | BigInt64Array;
  readonly dims: readonly number[];
  readonly type?: string;
}

/**
 * Tokenizer abstraction. Same trick as the runtime — we don't bind to
 * any specific HF tokenizer package so the user can wire up
 * `@huggingface/transformers`, `tokenizers`, or a hand-written one.
 */
export interface Tokenizer {
  encode(text: string): {
    input_ids: number[];
    attention_mask: number[];
    token_type_ids?: number[];
  };
  /** Optional max sequence length the tokenizer was trained for. */
  modelMaxLength?: number;
}

export interface OnnxClassifierConfig {
  /** A pre-constructed inference session. */
  session: OnnxInferenceRuntime;
  /** Tokenizer matching the model. */
  tokenizer: Tokenizer;
  /**
   * Probability threshold above which the input is flagged as
   * injection. Default 0.85 (calibrated for protectai/deberta-v3-base-
   * prompt-injection — adjust per model).
   */
  threshold?: number;
  /**
   * Name of the output node that carries logits/probabilities.
   * Default: first key in the runtime's result map.
   */
  outputName?: string;
  /**
   * Index of the "injection" class in the model output.
   * Default: 1 (binary classifier convention: 0 = SAFE, 1 = INJECTION).
   */
  injectionClassIndex?: number;
  /**
   * Maximum sequence length to feed. Default: 512.
   * Larger inputs are truncated head-only (start kept) which matches
   * the standard DeBERTa fine-tune recipe.
   */
  maxLength?: number;
}

export class OnnxInjectionScanner implements Scanner {
  readonly name = "onnx-classifier";
  private readonly cfg: Required<
    Omit<OnnxClassifierConfig, "outputName">
  > & { outputName?: string };

  constructor(config: OnnxClassifierConfig) {
    if (!config.session) {
      throw new TypeError("OnnxInjectionScanner: 'session' is required");
    }
    if (!config.tokenizer) {
      throw new TypeError("OnnxInjectionScanner: 'tokenizer' is required");
    }
    this.cfg = {
      session: config.session,
      tokenizer: config.tokenizer,
      threshold: config.threshold ?? 0.85,
      outputName: config.outputName,
      injectionClassIndex: config.injectionClassIndex ?? 1,
      maxLength:
        config.maxLength ?? config.tokenizer.modelMaxLength ?? 512,
    };
  }

  async scan(input: string, _context: ScanContext): Promise<ScannerResult> {
    const start = performance.now();
    try {
      const probability = await this.predict(input);
      const violations: Violation[] = [];
      let decision: ScannerResult["decision"] = "allow";

      if (probability >= this.cfg.threshold) {
        decision = "block";
        violations.push({
          type: "prompt_injection",
          scanner: this.name,
          score: probability,
          threshold: this.cfg.threshold,
          message: "ML classifier flagged prompt-injection",
          detail: `p(injection)=${probability.toFixed(4)} threshold=${this.cfg.threshold}`,
        });
      } else if (probability >= this.cfg.threshold * 0.6) {
        decision = "warn";
        violations.push({
          type: "prompt_injection",
          scanner: this.name,
          score: probability,
          threshold: this.cfg.threshold,
          message: "ML classifier flagged borderline content",
          detail: `p(injection)=${probability.toFixed(4)} threshold=${this.cfg.threshold}`,
        });
      }

      return {
        decision,
        violations,
        durationMs: performance.now() - start,
      };
    } catch (err) {
      // ML errors must not take down the entire chain — degrade gracefully
      // to "allow" with a synthetic violation so the audit log shows
      // something went wrong without blocking traffic.
      //
      // Critic H4 round 1 — the raw error message can contain file
      // paths (model location), native library symbols, or deployment-
      // internal strings. Strip absolute paths before they hit the audit
      // log. In dev mode we keep more detail to aid debugging.
      const rawMessage = (err as Error)?.message ?? "unknown error";
      const isDev =
        process.env.NODE_ENV === "development" ||
        process.env.AI_SHIELD_DEBUG === "1";
      const safeDetail = isDev
        ? rawMessage
        : sanitizeOnnxErrorMessage(rawMessage);
      return {
        decision: "allow",
        violations: [
          {
            type: "content_policy",
            scanner: this.name,
            score: 0,
            threshold: this.cfg.threshold,
            message: "ML classifier failed — degraded to allow",
            detail: safeDetail,
          },
        ],
        durationMs: performance.now() - start,
      };
    }
  }

  /** Direct probability access — useful for tests + custom flows. */
  async predict(input: string): Promise<number> {
    const tokens = this.cfg.tokenizer.encode(input);
    const trunc = truncate(tokens, this.cfg.maxLength);

    const inputIds = BigInt64Array.from(trunc.input_ids.map((n) => BigInt(n)));
    const attentionMask = BigInt64Array.from(
      trunc.attention_mask.map((n) => BigInt(n)),
    );
    const dims = [1, trunc.input_ids.length];

    const feeds: Record<string, OnnxTensorLike> = {
      input_ids: { data: inputIds, dims, type: "int64" },
      attention_mask: { data: attentionMask, dims, type: "int64" },
    };
    if (trunc.token_type_ids) {
      feeds.token_type_ids = {
        data: BigInt64Array.from(trunc.token_type_ids.map((n) => BigInt(n))),
        dims,
        type: "int64",
      };
    }

    const result = await this.cfg.session.run(feeds);
    const outputName =
      this.cfg.outputName ??
      this.cfg.session.outputNames?.[0] ??
      Object.keys(result)[0];
    if (!outputName) {
      throw new Error("OnnxInjectionScanner: no output node available");
    }
    const tensor = result[outputName];
    if (!tensor) {
      throw new Error(
        `OnnxInjectionScanner: output '${outputName}' not in result`,
      );
    }

    // Model emits logits of shape [1, num_classes]. Softmax + pick class.
    const logits = Array.from(tensor.data as ArrayLike<number>).map((n) =>
      Number(n),
    );
    const probs = softmax(logits);
    const idx = this.cfg.injectionClassIndex;
    if (idx < 0 || idx >= probs.length) {
      throw new Error(
        `OnnxInjectionScanner: injectionClassIndex ${idx} out of range (len=${probs.length})`,
      );
    }
    return probs[idx] ?? 0;
  }
}

/**
 * Convenience loader. Imports `onnxruntime-node` *at runtime* so
 * consumers who never call this function don't pay the install cost.
 *
 * Tokenizer loading is left to the caller because tokenizer
 * implementations vary widely between models — we don't want to
 * pin a specific HF tokenizer package.
 */
export async function loadOnnxClassifier(opts: {
  modelPath: string;
  tokenizer: Tokenizer;
  threshold?: number;
  outputName?: string;
  injectionClassIndex?: number;
  maxLength?: number;
}): Promise<OnnxInjectionScanner> {
  // Dynamic import keeps the dep optional — TypeScript can't see it
  // at compile time, which is the whole point.
  let ort: unknown;
  try {
    ort = await import("onnxruntime-node" as string);
  } catch (err) {
    throw new Error(
      "ai-shield-classifier-onnx: 'onnxruntime-node' is required " +
        "to call loadOnnxClassifier(). Install it as a peer dependency.\n" +
        `Underlying error: ${(err as Error).message}`,
    );
  }
  const ortModule = (ort as { InferenceSession?: { create?: (path: string) => Promise<OnnxInferenceRuntime> } });
  const create = ortModule.InferenceSession?.create;
  if (typeof create !== "function") {
    throw new Error(
      "ai-shield-classifier-onnx: 'onnxruntime-node' did not expose InferenceSession.create",
    );
  }
  const session = await create(opts.modelPath);
  return new OnnxInjectionScanner({
    session,
    tokenizer: opts.tokenizer,
    threshold: opts.threshold,
    outputName: opts.outputName,
    injectionClassIndex: opts.injectionClassIndex,
    maxLength: opts.maxLength,
  });
}

// --- helpers ---

/**
 * Strip absolute paths and other deployment-internal strings from an
 * ONNX-runtime error message before it lands in the audit log. Keeps
 * the short error class / cause hint that helps diagnose the failure.
 */
function sanitizeOnnxErrorMessage(message: string): string {
  if (typeof message !== "string" || message.length === 0) {
    return "classifier_runtime_error";
  }
  // Truncate before sanitizing — bounded work on adversarial input.
  const truncated = message.length > 500 ? message.slice(0, 500) : message;
  return truncated
    // POSIX absolute paths
    .replace(/(?:^|[\s(])(\/[\w./@-]+)/g, " [path]")
    // Windows drive paths
    .replace(/[A-Za-z]:\\[\\\w./@-]+/g, "[path]")
    // file:// URLs
    .replace(/file:\/\/\S+/g, "[file-url]")
    // Memory addresses (0x...)
    .replace(/0x[0-9a-fA-F]{6,}/g, "[addr]")
    .trim();
}

function softmax(logits: number[]): number[] {
  if (logits.length === 0) return [];
  const max = Math.max(...logits);
  const exps = logits.map((l) => Math.exp(l - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  if (sum === 0) return logits.map(() => 0);
  return exps.map((e) => e / sum);
}

function truncate(
  tokens: ReturnType<Tokenizer["encode"]>,
  maxLength: number,
): ReturnType<Tokenizer["encode"]> {
  if (tokens.input_ids.length <= maxLength) return tokens;
  return {
    input_ids: tokens.input_ids.slice(0, maxLength),
    attention_mask: tokens.attention_mask.slice(0, maxLength),
    token_type_ids: tokens.token_type_ids?.slice(0, maxLength),
  };
}
