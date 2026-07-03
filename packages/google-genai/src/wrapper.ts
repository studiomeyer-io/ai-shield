import type {
  AIShield,
  ShieldConfig,
  ScanContext,
  ScanResult,
  OutputScanConfig,
  OutputScanResult,
} from "ai-shield-core";

// ============================================================
// Google Gen AI Shield Wrapper — Drop-in replacement
// Wraps the NEW unified Google Gen AI SDK (`@google/genai`,
// verified against 2.10.0) — NOT the deprecated
// `@google/generative-ai` (that one is `ai-shield-gemini`).
//
// New-SDK surface (differs from the old SDK):
//   const ai = new GoogleGenAI({ apiKey });
//   await ai.models.generateContent({ model, contents, config })
//     → GenerateContentResponse (`.text` is an accessor property,
//       `string | undefined` — not the old `.response.text()` method)
//   await ai.models.generateContentStream({ ... })
//     → AsyncGenerator<GenerateContentResponse> (no aggregated
//       `response` promise like the old SDK)
//
// Scans input before & output after the LLM call.
// Supports both non-streaming and streaming modes.
// ============================================================

export interface ShieldedGoogleGenAIConfig {
  /** AI Shield config (or pass existing AIShield instance) */
  shield?: ShieldConfig;
  /** Pre-created AIShield instance (takes precedence over shield config) */
  shieldInstance?: AIShield;
  /** Agent ID for tool policy / cost tracking */
  agentId?: string;
  /** Custom scan context factory (receives the normalized contents) */
  contextFactory?: (contents: GenAIContent[]) => ScanContext;
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
   * `result._shield.outputScan`.
   */
  outputScan?: boolean | OutputScanConfig;
  /** Callback when input is blocked */
  onBlocked?: (result: ScanResult, contents: GenAIContent[]) => void;
  /** Callback when input has warnings */
  onWarning?: (result: ScanResult, contents: GenAIContent[]) => void;
}

// --- Google Gen AI SDK types (minimal, duck-typed to avoid a hard
// dependency; `src/compat-check.ts` proves compatibility with the real
// `@google/genai` types at compile time) ---

/** Request-side part (`Part`). Extra SDK fields pass through untouched. */
export interface GenAIPart {
  text?: string;
  /** Model reasoning marker — thought parts are model output, never scanned input. */
  thought?: boolean;
  [key: string]: unknown;
}

/** Request-side content (`Content`) — role + parts, both optional in the new SDK. */
export interface GenAIContent {
  role?: string;
  parts?: GenAIPart[];
}

/** `ContentListUnion` — everything `contents` accepts in the new SDK. */
export type GenAIContents =
  | string
  | GenAIPart
  | GenAIContent
  | Array<string | GenAIPart>
  | GenAIContent[];

interface GenAIFunctionDeclarationLike {
  name?: string;
  description?: string;
  [key: string]: unknown;
}

interface GenAIToolLike {
  functionDeclarations?: GenAIFunctionDeclarationLike[];
  [key: string]: unknown;
}

/** `GenerateContentConfig` — only the fields the wrapper reads are typed. */
export interface GenAIGenerateContentConfig {
  systemInstruction?: string | GenAIContent;
  tools?: GenAIToolLike[];
  [key: string]: unknown;
}

/** `GenerateContentParameters` — the new SDK takes the model per call. */
export interface GenAIGenerateContentParams {
  model: string;
  contents: GenAIContents;
  config?: GenAIGenerateContentConfig;
}

interface GenAIUsageMetadata {
  promptTokenCount?: number;
  candidatesTokenCount?: number;
  totalTokenCount?: number;
}

// Response-side duck types are kept index-signature-free so the real
// `GenerateContentResponse` class (with its `text` accessor) satisfies them.
interface GenAIResponsePartLike {
  text?: string;
  thought?: boolean;
}

interface GenAIResponseContentLike {
  role?: string;
  parts?: GenAIResponsePartLike[];
}

interface GenAICandidateLike {
  content?: GenAIResponseContentLike;
  finishReason?: string;
}

/**
 * `GenerateContentResponse` (duck-typed). In the new SDK `text` is an
 * accessor property returning `string | undefined` — NOT the old SDK's
 * `text()` method.
 */
export interface GenAIResponse {
  text?: string;
  candidates?: GenAICandidateLike[];
  usageMetadata?: GenAIUsageMetadata;
}

/** Shield scan results attached to wrapped responses. */
export interface GenAIShieldMeta {
  input: ScanResult;
  output?: ScanResult;
  outputScan?: OutputScanResult;
}

/** Duck-typed `ai.models` sub-client of the new SDK. */
export interface GenAIModelsLike {
  generateContent(params: GenAIGenerateContentParams): Promise<GenAIResponse>;
  generateContentStream(
    params: GenAIGenerateContentParams,
  ): Promise<AsyncIterable<GenAIResponse>>;
}

/** Duck-typed `GoogleGenAI` client (only `models` is required). */
export interface GoogleGenAIClientLike {
  models: GenAIModelsLike;
}

export class ShieldedGoogleGenAI {
  /**
   * Drop-in `ai.models` replacement — call
   * `shielded.models.generateContent({ model, contents, config })` exactly
   * like the raw `GoogleGenAI` client.
   */
  readonly models: {
    generateContent: (
      params: GenAIGenerateContentParams,
    ) => Promise<GenAIResponse & { _shield?: GenAIShieldMeta }>;
    generateContentStream: (
      params: GenAIGenerateContentParams,
    ) => Promise<ShieldedGoogleGenAIStream>;
  };

  private client: GoogleGenAIClientLike;
  private shield: AIShield | null = null;
  private shieldConfig: ShieldConfig;
  private config: ShieldedGoogleGenAIConfig;
  private _shieldReady: Promise<AIShield> | null = null;

  constructor(
    client: GoogleGenAIClientLike,
    config: ShieldedGoogleGenAIConfig = {},
  ) {
    this.client = client;
    this.config = config;
    this.shieldConfig = config.shield ?? {};

    if (config.shieldInstance) {
      this.shield = config.shieldInstance;
    }

    this.models = {
      generateContent: (params) => this.generateContent(params),
      generateContentStream: (params) => this.generateContentStream(params),
    };
  }

  /** Lazy-init shield (avoid import at construction time) */
  private async getShield(): Promise<AIShield> {
    if (this.shield) return this.shield;
    if (this._shieldReady) return this._shieldReady;

    this._shieldReady = import("ai-shield-core").then((mod) => {
      this.shield = new mod.AIShield(this.shieldConfig);
      return this.shield;
    });

    return this._shieldReady;
  }

  /**
   * Normalize `contents` to `Content[]` — mirrors the SDK's own `tContents`
   * transformer: a bare string / part becomes a single user content, a
   * part array is accumulated into ONE user content, a content array
   * passes through unchanged.
   */
  private normalizeContents(contents: GenAIContents): GenAIContent[] {
    if (typeof contents === "string") {
      return [{ role: "user", parts: [{ text: contents }] }];
    }
    if (!Array.isArray(contents)) {
      return isContentLike(contents)
        ? [contents]
        : [{ role: "user", parts: [contents] }];
    }
    if (contents.length === 0) {
      return [];
    }
    // Mirror the SDK: the first element decides Content[] vs PartUnion[].
    if (isContentLike(contents[0])) {
      if (!contents.every((item) => isContentLike(item))) {
        throw new Error(
          "Mixing Content and Parts is not supported — group parts into Content objects with explicit roles",
        );
      }
      return contents as GenAIContent[];
    }
    if (contents.some((item) => isContentLike(item))) {
      throw new Error(
        "Mixing Content and Parts is not supported — group parts into Content objects with explicit roles",
      );
    }
    const parts = (contents as Array<string | GenAIPart>).map((item) =>
      typeof item === "string" ? { text: item } : item,
    );
    return [{ role: "user", parts }];
  }

  /** Build scan context from the request */
  private buildContext(
    params: GenAIGenerateContentParams,
    contents: GenAIContent[],
  ): ScanContext {
    if (this.config.contextFactory) {
      return this.config.contextFactory(contents);
    }

    const context: ScanContext = {};
    if (this.config.agentId) {
      context.agentId = this.config.agentId;
    }

    // Include tool names if tools are being passed (new SDK: config.tools)
    const tools = params.config?.tools;
    if (tools) {
      const toolNames: Array<{ name: string }> = [];
      for (const tool of tools) {
        for (const fn of tool.functionDeclarations ?? []) {
          if (typeof fn.name === "string" && fn.name.length > 0) {
            toolNames.push({ name: fn.name });
          }
        }
      }
      if (toolNames.length > 0) {
        context.tools = toolNames;
      }
    }

    return context;
  }

  /** Extract text content from normalized contents for scanning */
  private extractUserContent(contents: GenAIContent[]): string {
    const parts: string[] = [];

    for (const content of contents) {
      // Only scan user messages (not model responses)
      if (content.role && content.role !== "user") continue;

      for (const part of content.parts ?? []) {
        if (typeof part.text === "string" && part.text) {
          parts.push(part.text);
        }
      }
    }

    return parts.join("\n");
  }

  /** Scan input and validate budget — shared between streaming and non-streaming */
  private async scanInput(params: GenAIGenerateContentParams): Promise<{
    shieldInstance: AIShield;
    context: ScanContext;
    inputResult: ScanResult;
    finalParams: GenAIGenerateContentParams;
  }> {
    const shieldInstance = await this.getShield();
    const contents = this.normalizeContents(params.contents);
    const context = this.buildContext(params, contents);
    const userContent = this.extractUserContent(contents);

    // --- Scan input ---
    const inputResult = await shieldInstance.scan(userContent, context);

    if (inputResult.decision === "block") {
      this.config.onBlocked?.(inputResult, contents);
      throw new ShieldBlockError("Input blocked by AI Shield", inputResult);
    }

    if (inputResult.decision === "warn") {
      this.config.onWarning?.(inputResult, contents);
    }

    // --- Replace sanitized content if PII was masked ---
    let finalContents = contents;
    if (inputResult.sanitized !== userContent) {
      finalContents = this.replaceUserContent(contents, inputResult.sanitized);
    }

    // --- Cost pre-check (new SDK exposes the model per call) ---
    if (this.config.agentId) {
      const estimate = await shieldInstance.checkBudget(
        this.config.agentId,
        params.model,
        userContent.length * 0.75, // rough token estimate
      );
      if (!estimate.allowed) {
        throw new ShieldBudgetError(
          `Budget exceeded: $${estimate.currentSpend.toFixed(4)} / $${(estimate.currentSpend + estimate.remainingBudget).toFixed(4)}`,
          estimate,
        );
      }
    }

    return {
      shieldInstance,
      context,
      inputResult,
      finalParams: { ...params, contents: finalContents },
    };
  }

  /** Run the dedicated OutputScanner if `outputScan` is configured. */
  private async runOutputScan(
    text: string,
    context: ScanContext,
  ): Promise<OutputScanResult | undefined> {
    if (!this.config.outputScan || !text) return undefined;
    const cfg = this.config.outputScan === true ? {} : this.config.outputScan;
    const mod = await import("ai-shield-core");
    return mod.scanOutput(text, cfg, context);
  }

  /** Generate content with Shield protection (non-streaming) */
  async generateContent(
    params: GenAIGenerateContentParams,
  ): Promise<GenAIResponse & { _shield?: GenAIShieldMeta }> {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(params);

    // --- Make the actual API call ---
    const response = await this.client.models.generateContent(finalParams);

    // --- Record cost ---
    if (this.config.agentId && response.usageMetadata) {
      const usage = response.usageMetadata;
      await shieldInstance.recordCost(
        this.config.agentId,
        params.model,
        usage.promptTokenCount ?? 0,
        usage.candidatesTokenCount ?? 0,
      );
    }

    // --- Scan output ---
    // `.text` is an accessor in the new SDK (may be undefined when the
    // response has no text candidate — e.g. blocked or pure function call).
    const outputText = typeof response.text === "string" ? response.text : "";
    let outputResult: ScanResult | undefined;
    if (this.config.scanOutput && outputText) {
      outputResult = await shieldInstance.scan(outputText, context);
    }
    const outputScan = await this.runOutputScan(outputText, context);

    // Attach `_shield` to the response instance instead of spreading:
    // `GenerateContentResponse` is a class whose `text` / `data` accessors
    // live on the prototype — a spread would silently drop them.
    const shielded = response as GenAIResponse & { _shield?: GenAIShieldMeta };
    shielded._shield = { input: inputResult, output: outputResult, outputScan };
    return shielded;
  }

  /** Generate content stream with Shield protection */
  async generateContentStream(
    params: GenAIGenerateContentParams,
  ): Promise<ShieldedGoogleGenAIStream> {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(params);

    // --- Make streaming API call ---
    const stream = await this.client.models.generateContentStream(finalParams);

    return new ShieldedGoogleGenAIStream({
      stream,
      inputResult,
      shieldInstance,
      context,
      scanOutput: this.config.scanOutput ?? false,
      outputScan: this.config.outputScan,
      agentId: this.config.agentId,
      model: params.model,
    });
  }

  /** Replace user content with sanitized version */
  private replaceUserContent(
    contents: GenAIContent[],
    sanitized: string,
  ): GenAIContent[] {
    let remaining = sanitized;

    return contents.map((content) => {
      if (content.role && content.role !== "user") return content;

      const newParts = (content.parts ?? []).map((part) => {
        if (typeof part.text === "string" && part.text) {
          const replacement = remaining.substring(0, part.text.length);
          remaining = remaining.substring(part.text.length + 1); // +1 for \n
          return { ...part, text: replacement };
        }
        return part;
      });

      return { ...content, parts: newParts };
    });
  }

  /** Access the underlying GoogleGenAI client */
  get raw(): GoogleGenAIClientLike {
    return this.client;
  }

  /** Graceful shutdown */
  async close(): Promise<void> {
    if (this._shieldReady) {
      const shield = await this._shieldReady;
      await shield.close();
    } else if (this.shield) {
      await this.shield.close();
    }
  }
}

/** Mirror of the SDK's `_isContent` discriminator. */
function isContentLike(value: unknown): value is GenAIContent {
  return (
    typeof value === "object" &&
    value !== null &&
    "parts" in value &&
    Array.isArray((value as { parts?: unknown }).parts)
  );
}

interface ShieldedStreamOptions {
  stream: AsyncIterable<GenAIResponse>;
  inputResult: ScanResult;
  shieldInstance: AIShield;
  context: ScanContext;
  scanOutput: boolean;
  outputScan: boolean | OutputScanConfig | undefined;
  agentId: string | undefined;
  model: string;
}

// ============================================================
// ShieldedGoogleGenAIStream — Async iterable wrapper for streaming
// Scans input before stream, accumulates output, scans after.
// The new SDK yields GenerateContentResponse chunks directly (no
// aggregated `response` promise) — usage metadata is captured from
// the chunks themselves (the final chunk carries the totals).
// ============================================================

export class ShieldedGoogleGenAIStream implements AsyncIterable<GenAIResponse> {
  private _inputResult: ScanResult;
  private _outputResult: ScanResult | undefined;
  private _outputScanResult: OutputScanResult | undefined;
  private _done = false;
  private _fullText = "";
  private _usageMetadata: GenAIUsageMetadata | undefined;
  private _stream: AsyncIterable<GenAIResponse>;
  private _shieldInstance: AIShield;
  private _context: ScanContext;
  private _scanOutput: boolean;
  private _outputScan: boolean | OutputScanConfig | undefined;
  private _agentId: string | undefined;
  private _model: string;

  constructor(options: ShieldedStreamOptions) {
    this._stream = options.stream;
    this._inputResult = options.inputResult;
    this._shieldInstance = options.shieldInstance;
    this._context = options.context;
    this._scanOutput = options.scanOutput;
    this._outputScan = options.outputScan;
    this._agentId = options.agentId;
    this._model = options.model;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<GenAIResponse> {
    for await (const chunk of this._stream) {
      // Accumulate text content (`.text` is a property in the new SDK)
      if (typeof chunk.text === "string" && chunk.text) {
        this._fullText += chunk.text;
      }
      // Capture usage metadata (the last chunk carrying it wins)
      if (chunk.usageMetadata) {
        this._usageMetadata = chunk.usageMetadata;
      }

      yield chunk;
    }

    // --- Post-stream: record cost from captured usage metadata ---
    if (this._agentId && this._usageMetadata) {
      await this._shieldInstance.recordCost(
        this._agentId,
        this._model,
        this._usageMetadata.promptTokenCount ?? 0,
        this._usageMetadata.candidatesTokenCount ?? 0,
      );
    }

    // --- Post-stream: scan output ---
    if (this._scanOutput && this._fullText) {
      this._outputResult = await this._shieldInstance.scan(
        this._fullText,
        this._context,
      );
    }
    if (this._outputScan && this._fullText) {
      const cfg = this._outputScan === true ? {} : this._outputScan;
      const mod = await import("ai-shield-core");
      this._outputScanResult = await mod.scanOutput(
        this._fullText,
        cfg,
        this._context,
      );
    }

    this._done = true;
  }

  /** Input scan result (available immediately) */
  get inputResult(): ScanResult {
    return this._inputResult;
  }

  /** Output scan result (legacy input-chain over output; after stream completes) */
  get outputResult(): ScanResult | undefined {
    return this._outputResult;
  }

  /** Dedicated OutputScanner result (after stream completes, if `outputScan` set) */
  get outputScanResult(): OutputScanResult | undefined {
    return this._outputScanResult;
  }

  /** Combined shield results */
  get shieldResult(): GenAIShieldMeta {
    return {
      input: this._inputResult,
      output: this._outputResult,
      outputScan: this._outputScanResult,
    };
  }

  /** Whether the stream has completed */
  get done(): boolean {
    return this._done;
  }

  /** Full accumulated text from the stream */
  get text(): string {
    return this._fullText;
  }

  /** Usage metadata captured from the final stream chunk (after completion) */
  get usageMetadata(): GenAIUsageMetadata | undefined {
    return this._usageMetadata;
  }
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

export class ShieldBudgetError extends Error {
  constructor(
    message: string,
    public readonly budgetCheck: {
      allowed: boolean;
      currentSpend: number;
      remainingBudget: number;
    },
  ) {
    super(message);
    this.name = "ShieldBudgetError";
  }
}
