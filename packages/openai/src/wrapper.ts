import type {
  AIShield,
  ShieldConfig,
  ScanContext,
  ScanResult,
  OutputScanConfig,
  OutputScanResult,
} from "ai-shield-core";

// ============================================================
// OpenAI Shield Wrapper — Drop-in replacement
// Wraps OpenAI SDK, scans input before & output after LLM call
// Supports both non-streaming and streaming modes
// ============================================================

export interface ShieldedOpenAIConfig {
  /** AI Shield config (or pass existing AIShield instance) */
  shield?: ShieldConfig;
  /** Pre-created AIShield instance (takes precedence over shield config) */
  shieldInstance?: AIShield;
  /** Agent ID for tool policy / cost tracking */
  agentId?: string;
  /** Custom scan context factory */
  contextFactory?: (messages: ChatMessage[]) => ScanContext;
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
   * `response._shield.outputScan`.
   */
  outputScan?: boolean | OutputScanConfig;
  /** Callback when input is blocked */
  onBlocked?: (result: ScanResult, messages: ChatMessage[]) => void;
  /** Callback when input has warnings */
  onWarning?: (result: ScanResult, messages: ChatMessage[]) => void;
}

interface ChatMessage {
  role: string;
  content: string | null | Array<{ type: string; text?: string }>;
  tool_calls?: Array<{ function: { name: string; arguments: string } }>;
}

interface ChatCompletionParams {
  model: string;
  messages: ChatMessage[];
  tools?: Array<{ function: { name: string } }>;
  stream?: boolean;
  [key: string]: unknown;
}

interface ChatCompletion {
  choices: Array<{
    message: {
      content: string | null;
      tool_calls?: Array<{ function: { name: string; arguments: string } }>;
    };
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface ChatCompletionChunk {
  choices: Array<{
    delta: {
      content?: string | null;
      role?: string;
      tool_calls?: Array<{ function: { name: string; arguments: string } }>;
    };
    index: number;
    finish_reason: string | null;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

interface OpenAILike {
  chat: {
    completions: {
      create(params: ChatCompletionParams): Promise<ChatCompletion | AsyncIterable<ChatCompletionChunk>>;
    };
  };
}

export class ShieldedOpenAI {
  private client: OpenAILike;
  private shield: AIShield | null = null;
  private shieldConfig: ShieldConfig;
  private config: ShieldedOpenAIConfig;
  private _shieldReady: Promise<AIShield> | null = null;

  constructor(client: OpenAILike, config: ShieldedOpenAIConfig = {}) {
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

  /** Build scan context from messages */
  private buildContext(params: ChatCompletionParams): ScanContext {
    if (this.config.contextFactory) {
      return this.config.contextFactory(params.messages);
    }

    const context: ScanContext = {};
    if (this.config.agentId) {
      context.agentId = this.config.agentId;
    }

    // Include tool names if tools are being called
    if (params.tools) {
      context.tools = params.tools.map((t) => ({ name: t.function.name }));
    }

    return context;
  }

  /** Extract text content from messages for scanning */
  private extractUserContent(messages: ChatMessage[]): string {
    const parts: string[] = [];

    for (const msg of messages) {
      // Only scan user messages (not system/assistant)
      if (msg.role !== "user") continue;

      if (typeof msg.content === "string") {
        parts.push(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === "text" && block.text) {
            parts.push(block.text);
          }
        }
      }
    }

    return parts.join("\n");
  }

  /** Scan input and validate budget — shared between streaming and non-streaming */
  private async scanInput(params: ChatCompletionParams): Promise<{
    shieldInstance: AIShield;
    context: ScanContext;
    userContent: string;
    inputResult: ScanResult;
    finalParams: ChatCompletionParams;
  }> {
    const shieldInstance = await this.getShield();
    const context = this.buildContext(params);
    const userContent = this.extractUserContent(params.messages);

    // --- Scan input ---
    const inputResult = await shieldInstance.scan(userContent, context);

    if (inputResult.decision === "block") {
      this.config.onBlocked?.(inputResult, params.messages);
      throw new ShieldBlockError("Input blocked by AI Shield", inputResult);
    }

    if (inputResult.decision === "warn") {
      this.config.onWarning?.(inputResult, params.messages);
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

    return { shieldInstance, context, userContent, inputResult, finalParams };
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

  /** Create chat completion with Shield protection (non-streaming) */
  async createChatCompletion(
    params: ChatCompletionParams,
  ): Promise<
    ChatCompletion & {
      _shield?: {
        input: ScanResult;
        output?: ScanResult;
        outputScan?: OutputScanResult;
      };
    }
  > {
    const { shieldInstance, context, inputResult, finalParams } = await this.scanInput(params);

    // --- Make the actual API call ---
    const response = await this.client.chat.completions.create({ ...finalParams, stream: false }) as ChatCompletion;

    // --- Record cost ---
    if (this.config.agentId && response.usage) {
      await shieldInstance.recordCost(
        this.config.agentId,
        params.model,
        response.usage.prompt_tokens,
        response.usage.completion_tokens,
      );
    }

    // --- Scan output ---
    const outputText = response.choices[0]?.message?.content ?? "";
    let outputResult: ScanResult | undefined;
    if (this.config.scanOutput && outputText) {
      outputResult = await shieldInstance.scan(outputText, context);
    }
    const outputScan = await this.runOutputScan(outputText, context);

    return {
      ...response,
      _shield: { input: inputResult, output: outputResult, outputScan },
    };
  }

  /** Create streaming chat completion with Shield protection */
  async createChatCompletionStream(
    params: Omit<ChatCompletionParams, "stream">,
  ): Promise<ShieldedChatStream> {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(params as ChatCompletionParams);

    // --- Make streaming API call ---
    const stream = await this.client.chat.completions.create({
      ...finalParams,
      stream: true,
    }) as AsyncIterable<ChatCompletionChunk>;

    return new ShieldedChatStream(
      stream,
      inputResult,
      shieldInstance,
      context,
      this.config.scanOutput ?? false,
      this.config.agentId,
      finalParams.model,
      this.config.outputScan,
    );
  }

  /** Replace user message content with sanitized version */
  private replaceUserContent(
    params: ChatCompletionParams,
    sanitized: string,
  ): ChatCompletionParams {
    const messages = params.messages.map((msg) => {
      if (msg.role !== "user") return msg;

      if (typeof msg.content === "string") {
        return { ...msg, content: sanitized };
      }
      // For multi-part content, replace text blocks
      if (Array.isArray(msg.content)) {
        let remaining = sanitized;
        const newContent = msg.content.map((block) => {
          if (block.type === "text" && block.text) {
            const replacement = remaining.substring(0, block.text.length);
            remaining = remaining.substring(block.text.length + 1); // +1 for \n
            return { ...block, text: replacement };
          }
          return block;
        });
        return { ...msg, content: newContent };
      }

      return msg;
    });

    return { ...params, messages };
  }

  /** Access the underlying OpenAI client */
  get raw(): OpenAILike {
    return this.client;
  }

  /** Graceful shutdown */
  async close(): Promise<void> {
    if (this.shield) {
      await this.shield.close();
    }
  }
}

// ============================================================
// ShieldedChatStream — Async iterable wrapper for streaming
// Scans input before stream, accumulates output, scans after
// ============================================================

export class ShieldedChatStream implements AsyncIterable<ChatCompletionChunk> {
  private _inputResult: ScanResult;
  private _outputResult: ScanResult | undefined;
  private _outputScanResult: OutputScanResult | undefined;
  private _done = false;
  private _fullText = "";
  private _stream: AsyncIterable<ChatCompletionChunk>;
  private _shieldInstance: AIShield;
  private _context: ScanContext;
  private _scanOutput: boolean;
  private _outputScan: boolean | OutputScanConfig | undefined;
  private _agentId: string | undefined;
  private _model: string;
  private _usage: { prompt_tokens: number; completion_tokens: number } | undefined;

  constructor(
    stream: AsyncIterable<ChatCompletionChunk>,
    inputResult: ScanResult,
    shieldInstance: AIShield,
    context: ScanContext,
    scanOutput: boolean,
    agentId: string | undefined,
    model: string,
    outputScan?: boolean | OutputScanConfig,
  ) {
    this._stream = stream;
    this._inputResult = inputResult;
    this._shieldInstance = shieldInstance;
    this._context = context;
    this._scanOutput = scanOutput;
    this._outputScan = outputScan;
    this._agentId = agentId;
    this._model = model;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<ChatCompletionChunk> {
    for await (const chunk of this._stream) {
      // Accumulate text content
      const content = chunk.choices[0]?.delta?.content;
      if (content) {
        this._fullText += content;
      }

      // Capture usage if present (typically in the last chunk)
      if (chunk.usage) {
        this._usage = {
          prompt_tokens: chunk.usage.prompt_tokens,
          completion_tokens: chunk.usage.completion_tokens,
        };
      }

      yield chunk;
    }

    // --- Post-stream: record cost ---
    if (this._agentId && this._usage) {
      await this._shieldInstance.recordCost(
        this._agentId,
        this._model,
        this._usage.prompt_tokens,
        this._usage.completion_tokens,
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
  get shieldResult(): {
    input: ScanResult;
    output?: ScanResult;
    outputScan?: OutputScanResult;
  } {
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
