import type { AIShield, ShieldConfig, ScanContext, ScanResult } from "ai-shield-core";

// ============================================================
// Google Gemini Shield Wrapper — Drop-in replacement
// Wraps Gemini SDK, scans input before & output after LLM call
// Supports both non-streaming and streaming modes
// ============================================================

export interface ShieldedGeminiConfig {
  /** AI Shield config (or pass existing AIShield instance) */
  shield?: ShieldConfig;
  /** Pre-created AIShield instance (takes precedence over shield config) */
  shieldInstance?: AIShield;
  /** Agent ID for tool policy / cost tracking */
  agentId?: string;
  /** Custom scan context factory */
  contextFactory?: (content: GeminiContent[]) => ScanContext;
  /** Whether to scan output (response) too — default: false */
  scanOutput?: boolean;
  /** Callback when input is blocked */
  onBlocked?: (result: ScanResult, content: GeminiContent[]) => void;
  /** Callback when input has warnings */
  onWarning?: (result: ScanResult, content: GeminiContent[]) => void;
  /** Model name for cost tracking (default: "gemini-pro"). Set this to match your model, e.g. "gemini-1.5-pro", "gemini-2.0-flash" */
  modelName?: string;
}

// --- Gemini SDK types (minimal, duck-typed to avoid hard dependency) ---

interface GeminiPart {
  text?: string;
  inlineData?: { mimeType: string; data: string };
  functionCall?: { name: string; args: Record<string, unknown> };
  functionResponse?: { name: string; response: Record<string, unknown> };
  [key: string]: unknown;
}

export interface GeminiContent {
  role?: string;
  parts: GeminiPart[];
}

interface GeminiUsageMetadata {
  promptTokenCount?: number;
  candidatesTokenCount?: number;
  totalTokenCount?: number;
}

interface GeminiResponse {
  text: () => string;
  usageMetadata?: GeminiUsageMetadata;
  candidates?: Array<{
    content: GeminiContent;
    finishReason?: string;
  }>;
}

interface GeminiResult {
  response: GeminiResponse;
}

interface GeminiStreamResult {
  stream: AsyncGenerator<GeminiResponse>;
  response: Promise<GeminiResponse>;
}

interface GeminiTool {
  functionDeclarations?: Array<{ name: string; description?: string }>;
}

export interface GenerateContentParams {
  contents: GeminiContent[];
  tools?: GeminiTool[];
  [key: string]: unknown;
}

/** Duck-typed Gemini GenerativeModel interface */
interface GeminiModelLike {
  generateContent(
    request: GenerateContentParams | string | Array<string | GeminiPart>,
  ): Promise<GeminiResult>;
  generateContentStream(
    request: GenerateContentParams | string | Array<string | GeminiPart>,
  ): Promise<GeminiStreamResult>;
}

export class ShieldedGemini {
  private client: GeminiModelLike;
  private shield: AIShield | null = null;
  private shieldConfig: ShieldConfig;
  private config: ShieldedGeminiConfig;
  private _shieldReady: Promise<AIShield> | null = null;

  constructor(client: GeminiModelLike, config: ShieldedGeminiConfig = {}) {
    this.client = client;
    this.config = config;
    this.shieldConfig = config.shield ?? {};

    if (config.shieldInstance) {
      this.shield = config.shieldInstance;
    }
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

  /** Normalize request to GenerateContentParams */
  private normalizeRequest(
    request: GenerateContentParams | string | Array<string | GeminiPart>,
  ): GenerateContentParams {
    if (typeof request === "string") {
      return { contents: [{ role: "user", parts: [{ text: request }] }] };
    }
    if (Array.isArray(request)) {
      const parts = request.map((item) =>
        typeof item === "string" ? { text: item } : item,
      );
      return { contents: [{ role: "user", parts }] };
    }
    return request;
  }

  /** Build scan context from contents */
  private buildContext(params: GenerateContentParams): ScanContext {
    if (this.config.contextFactory) {
      return this.config.contextFactory(params.contents);
    }

    const context: ScanContext = {};
    if (this.config.agentId) {
      context.agentId = this.config.agentId;
    }

    // Include tool names if tools are being called
    if (params.tools) {
      const toolNames = params.tools.flatMap(
        (t) => t.functionDeclarations?.map((f) => ({ name: f.name })) ?? [],
      );
      if (toolNames.length > 0) {
        context.tools = toolNames;
      }
    }

    return context;
  }

  /** Extract text content from Gemini contents for scanning */
  private extractUserContent(contents: GeminiContent[]): string {
    const parts: string[] = [];

    for (const content of contents) {
      // Only scan user messages (not model responses)
      if (content.role && content.role !== "user") continue;

      for (const part of content.parts) {
        if (part.text) {
          parts.push(part.text);
        }
      }
    }

    return parts.join("\n");
  }

  /** Scan input and validate budget — shared between streaming and non-streaming */
  private async scanInput(
    request: GenerateContentParams | string | Array<string | GeminiPart>,
  ): Promise<{
    shieldInstance: AIShield;
    context: ScanContext;
    userContent: string;
    inputResult: ScanResult;
    finalParams: GenerateContentParams;
  }> {
    const shieldInstance = await this.getShield();
    const params = this.normalizeRequest(request);
    const context = this.buildContext(params);
    const userContent = this.extractUserContent(params.contents);

    // --- Scan input ---
    const inputResult = await shieldInstance.scan(userContent, context);

    if (inputResult.decision === "block") {
      this.config.onBlocked?.(inputResult, params.contents);
      throw new ShieldBlockError("Input blocked by AI Shield", inputResult);
    }

    if (inputResult.decision === "warn") {
      this.config.onWarning?.(inputResult, params.contents);
    }

    // --- Replace sanitized content if PII was masked ---
    let finalParams = params;
    if (inputResult.sanitized !== userContent) {
      finalParams = this.replaceUserContent(params, inputResult.sanitized);
    }

    // --- Cost pre-check ---
    if (this.config.agentId) {
      const estimate = await shieldInstance.checkBudget(
        this.config.agentId,
        this.config.modelName ?? "gemini-pro", // Gemini SDK doesn't expose model name in params
        userContent.length * 0.75, // rough token estimate
      );
      if (!estimate.allowed) {
        throw new ShieldBudgetError(
          `Budget exceeded: $${estimate.currentSpend.toFixed(4)} / $${(estimate.currentSpend + estimate.remainingBudget).toFixed(4)}`,
          estimate,
        );
      }
    }

    return { shieldInstance, context, userContent, inputResult, finalParams };
  }

  /** Generate content with Shield protection (non-streaming) */
  async generateContent(
    request: GenerateContentParams | string | Array<string | GeminiPart>,
  ): Promise<GeminiResult & { _shield?: { input: ScanResult; output?: ScanResult } }> {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(request);

    // --- Make the actual API call ---
    const result = await this.client.generateContent(finalParams);

    // --- Record cost ---
    if (this.config.agentId && result.response.usageMetadata) {
      const usage = result.response.usageMetadata;
      await shieldInstance.recordCost(
        this.config.agentId,
        this.config.modelName ?? "gemini-pro",
        usage.promptTokenCount ?? 0,
        usage.candidatesTokenCount ?? 0,
      );
    }

    // --- Scan output ---
    let outputResult: ScanResult | undefined;
    if (this.config.scanOutput) {
      try {
        const outputText = result.response.text();
        if (outputText) {
          outputResult = await shieldInstance.scan(outputText, context);
        }
      } catch {
        // text() throws if response was blocked — ignore
      }
    }

    return {
      ...result,
      _shield: { input: inputResult, output: outputResult },
    };
  }

  /** Generate content stream with Shield protection */
  async generateContentStream(
    request: GenerateContentParams | string | Array<string | GeminiPart>,
  ): Promise<ShieldedGeminiStream> {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(request);

    // --- Make streaming API call ---
    const streamResult = await this.client.generateContentStream(finalParams);

    return new ShieldedGeminiStream(
      streamResult.stream,
      streamResult.response,
      inputResult,
      shieldInstance,
      context,
      this.config.scanOutput ?? false,
      this.config.agentId,
      this.config.modelName ?? "gemini-pro",
    );
  }

  /** Replace user content with sanitized version */
  private replaceUserContent(
    params: GenerateContentParams,
    sanitized: string,
  ): GenerateContentParams {
    const contents = params.contents.map((content) => {
      if (content.role && content.role !== "user") return content;

      let remaining = sanitized;
      const newParts = content.parts.map((part) => {
        if (part.text) {
          const replacement = remaining.substring(0, part.text.length);
          remaining = remaining.substring(part.text.length + 1); // +1 for \n
          return { ...part, text: replacement };
        }
        return part;
      });

      return { ...content, parts: newParts };
    });

    return { ...params, contents };
  }

  /** Access the underlying Gemini model */
  get raw(): GeminiModelLike {
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

// ============================================================
// ShieldedGeminiStream — Async iterable wrapper for streaming
// Scans input before stream, accumulates output, scans after
// ============================================================

export class ShieldedGeminiStream implements AsyncIterable<GeminiResponse> {
  private _inputResult: ScanResult;
  private _outputResult: ScanResult | undefined;
  private _done = false;
  private _fullText = "";
  private _stream: AsyncGenerator<GeminiResponse>;
  private _responsePromise: Promise<GeminiResponse>;
  private _shieldInstance: AIShield;
  private _context: ScanContext;
  private _scanOutput: boolean;
  private _agentId: string | undefined;
  private _modelName: string;

  constructor(
    stream: AsyncGenerator<GeminiResponse>,
    responsePromise: Promise<GeminiResponse>,
    inputResult: ScanResult,
    shieldInstance: AIShield,
    context: ScanContext,
    scanOutput: boolean,
    agentId: string | undefined,
    modelName: string,
  ) {
    this._stream = stream;
    this._responsePromise = responsePromise;
    this._inputResult = inputResult;
    this._shieldInstance = shieldInstance;
    this._context = context;
    this._scanOutput = scanOutput;
    this._agentId = agentId;
    this._modelName = modelName;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<GeminiResponse> {
    for await (const chunk of this._stream) {
      // Accumulate text content
      try {
        const text = chunk.text();
        if (text) {
          this._fullText += text;
        }
      } catch {
        // text() can throw if chunk has no text candidates
      }

      yield chunk;
    }

    // --- Post-stream: record cost from aggregated response ---
    try {
      const finalResponse = await this._responsePromise;
      if (this._agentId && finalResponse.usageMetadata) {
        const usage = finalResponse.usageMetadata;
        await this._shieldInstance.recordCost(
          this._agentId,
          this._modelName,
          usage.promptTokenCount ?? 0,
          usage.candidatesTokenCount ?? 0,
        );
      }
    } catch {
      // aggregated response may fail — ignore for cost tracking
    }

    // --- Post-stream: scan output ---
    if (this._scanOutput && this._fullText) {
      this._outputResult = await this._shieldInstance.scan(
        this._fullText,
        this._context,
      );
    }

    this._done = true;
  }

  /** Input scan result (available immediately) */
  get inputResult(): ScanResult {
    return this._inputResult;
  }

  /** Output scan result (available after stream completes) */
  get outputResult(): ScanResult | undefined {
    return this._outputResult;
  }

  /** Combined shield results */
  get shieldResult(): { input: ScanResult; output?: ScanResult } {
    return { input: this._inputResult, output: this._outputResult };
  }

  /** Whether the stream has completed */
  get done(): boolean {
    return this._done;
  }

  /** Full accumulated text from the stream */
  get text(): string {
    return this._fullText;
  }

  /** Get the aggregated response promise */
  get response(): Promise<GeminiResponse> {
    return this._responsePromise;
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
    public readonly budgetCheck: { allowed: boolean; currentSpend: number; remainingBudget: number },
  ) {
    super(message);
    this.name = "ShieldBudgetError";
  }
}
