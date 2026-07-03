import type {
  AIShield,
  ShieldConfig,
  ScanContext,
  ScanResult,
  OutputScanConfig,
  OutputScanResult,
} from "ai-shield-core";

// ============================================================
// Anthropic Shield Wrapper — Drop-in replacement
// Wraps Anthropic SDK, scans input before & output after
// Supports both non-streaming and streaming modes
// ============================================================

export interface ShieldedAnthropicConfig {
  /** AI Shield config */
  shield?: ShieldConfig;
  /** Pre-created AIShield instance */
  shieldInstance?: AIShield;
  /** Agent ID for tool policy / cost tracking */
  agentId?: string;
  /** Custom scan context factory */
  contextFactory?: (messages: AnthropicMessage[]) => ScanContext;
  /**
   * Legacy: run the INPUT scan chain (heuristic + PII) over the output too.
   * Default false. Kept for backwards compatibility — for real output-side
   * defense (secret leak, SQL/XSS/shell injection, system-prompt leak) use
   * `outputScan` below, which runs the dedicated OutputScanner (OWASP LLM05).
   */
  scanOutput?: boolean;
  /**
   * Run the dedicated output scanner over the model response (OWASP LLM05 /
   * LLM02): secret leak, output injection, system-prompt leak, jailbreak,
   * output-side PII. Pass `true` for defaults or an `OutputScanConfig`
   * (e.g. `{ sinks: ["sql"], canaryTokens }`). Result lands in
   * `response._shield.outputScan`.
   */
  outputScan?: boolean | OutputScanConfig;
  /** Callback when input is blocked */
  onBlocked?: (result: ScanResult, messages: AnthropicMessage[]) => void;
  /** Callback when input has warnings */
  onWarning?: (result: ScanResult, messages: AnthropicMessage[]) => void;
}

// --- Anthropic SDK types (minimal, avoids hard dependency) ---

interface ContentBlockText {
  type: "text";
  text: string;
}

interface ContentBlockToolUse {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

type ContentBlock =
  | ContentBlockText
  | ContentBlockToolUse
  | { type: string; [key: string]: unknown };

export interface AnthropicMessage {
  role: "user" | "assistant";
  content: string | ContentBlock[];
}

interface AnthropicTool {
  name: string;
  description?: string;
  input_schema: Record<string, unknown>;
}

export interface AnthropicCreateParams {
  model: string;
  messages: AnthropicMessage[];
  system?: string | Array<{ type: "text"; text: string }>;
  max_tokens: number;
  tools?: AnthropicTool[];
  stream?: boolean;
  [key: string]: unknown;
}

interface AnthropicResponse {
  content: ContentBlock[];
  model: string;
  stop_reason: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

// --- Streaming event types ---

export interface AnthropicStreamEvent {
  type: string;
  message?: AnthropicResponse;
  index?: number;
  content_block?: ContentBlock;
  delta?: { type: string; text?: string; stop_reason?: string };
  usage?: { output_tokens: number };
}

interface AnthropicLike {
  messages: {
    create(
      params: AnthropicCreateParams,
    ): Promise<AnthropicResponse | AsyncIterable<AnthropicStreamEvent>>;
  };
}

export class ShieldedAnthropic {
  private client: AnthropicLike;
  private shield: AIShield | null = null;
  private shieldConfig: ShieldConfig;
  private config: ShieldedAnthropicConfig;
  private _shieldReady: Promise<AIShield> | null = null;

  constructor(client: AnthropicLike, config: ShieldedAnthropicConfig = {}) {
    this.client = client;
    this.config = config;
    this.shieldConfig = config.shield ?? {};

    if (config.shieldInstance) {
      this.shield = config.shieldInstance;
    }
  }

  /** Lazy-init shield */
  private async getShield(): Promise<AIShield> {
    if (this.shield) return this.shield;
    if (this._shieldReady) return this._shieldReady;

    this._shieldReady = import("ai-shield-core").then((mod) => {
      this.shield = new mod.AIShield(this.shieldConfig);
      return this.shield;
    });

    return this._shieldReady;
  }

  /** Build scan context from params */
  private buildContext(params: AnthropicCreateParams): ScanContext {
    if (this.config.contextFactory) {
      return this.config.contextFactory(params.messages);
    }

    const context: ScanContext = {};
    if (this.config.agentId) {
      context.agentId = this.config.agentId;
    }

    // Include tool names if tools are declared
    if (params.tools) {
      context.tools = params.tools.map((t) => ({ name: t.name }));
    }

    return context;
  }

  /** Extract text content from user messages */
  private extractUserContent(messages: AnthropicMessage[]): string {
    const parts: string[] = [];

    for (const msg of messages) {
      if (msg.role !== "user") continue;

      if (typeof msg.content === "string") {
        parts.push(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === "text" && "text" in block) {
            parts.push((block as ContentBlockText).text);
          }
        }
      }
    }

    return parts.join("\n");
  }

  /** Extract text from response content blocks */
  private extractResponseText(content: ContentBlock[]): string {
    return content
      .filter((b): b is ContentBlockText => b.type === "text")
      .map((b) => b.text)
      .join("\n");
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

  /** Scan input and validate budget — shared between streaming and non-streaming */
  private async scanInput(params: AnthropicCreateParams): Promise<{
    shieldInstance: AIShield;
    context: ScanContext;
    userContent: string;
    inputResult: ScanResult;
    finalParams: AnthropicCreateParams;
  }> {
    const shieldInstance = await this.getShield();
    const context = this.buildContext(params);
    const userContent = this.extractUserContent(params.messages);

    // --- Scan user input ---
    const inputResult = await shieldInstance.scan(userContent, context);

    if (inputResult.decision === "block") {
      this.config.onBlocked?.(inputResult, params.messages);
      throw new ShieldBlockError("Input blocked by AI Shield", inputResult);
    }

    if (inputResult.decision === "warn") {
      this.config.onWarning?.(inputResult, params.messages);
    }

    // --- Also scan system prompt if present ---
    if (params.system) {
      const systemText =
        typeof params.system === "string"
          ? params.system
          : params.system.map((b) => b.text).join("\n");

      // System prompt scan is informational only
      await shieldInstance.scan(systemText, {
        ...context,
        preset: "ops_agent",
      });
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
        userContent.length * 0.75,
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

  /** Create message with Shield protection (non-streaming) */
  async createMessage(params: AnthropicCreateParams): Promise<
    AnthropicResponse & {
      _shield?: {
        input: ScanResult;
        output?: ScanResult;
        outputScan?: OutputScanResult;
      };
    }
  > {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(params);

    // --- Make the actual API call ---
    const response = (await this.client.messages.create({
      ...finalParams,
      stream: false,
    })) as AnthropicResponse;

    // --- Record actual cost ---
    if (this.config.agentId && response.usage) {
      await shieldInstance.recordCost(
        this.config.agentId,
        params.model,
        response.usage.input_tokens,
        response.usage.output_tokens,
      );
    }

    // --- Scan output ---
    const outputText = this.extractResponseText(response.content);
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

  /** Create streaming message with Shield protection */
  async createMessageStream(
    params: Omit<AnthropicCreateParams, "stream">,
  ): Promise<ShieldedAnthropicStream> {
    const { shieldInstance, context, inputResult, finalParams } =
      await this.scanInput(params as AnthropicCreateParams);

    // --- Make streaming API call ---
    const stream = (await this.client.messages.create({
      ...finalParams,
      stream: true,
    })) as AsyncIterable<AnthropicStreamEvent>;

    return new ShieldedAnthropicStream(
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

  /** Replace user content with sanitized version */
  private replaceUserContent(
    params: AnthropicCreateParams,
    sanitized: string,
  ): AnthropicCreateParams {
    const messages = params.messages.map((msg) => {
      if (msg.role !== "user") return msg;

      if (typeof msg.content === "string") {
        return { ...msg, content: sanitized };
      }

      // Multi-block: replace text blocks
      if (Array.isArray(msg.content)) {
        let remaining = sanitized;
        const newContent = msg.content.map((block) => {
          if (block.type === "text" && "text" in block) {
            const original = (block as ContentBlockText).text;
            const replacement = remaining.substring(0, original.length);
            remaining = remaining.substring(original.length + 1);
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

  /** Access underlying Anthropic client */
  get raw(): AnthropicLike {
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
// ShieldedAnthropicStream — Async iterable wrapper for streaming
// Accumulates text from content_block_delta events, scans after
// ============================================================

export class ShieldedAnthropicStream implements AsyncIterable<AnthropicStreamEvent> {
  private _inputResult: ScanResult;
  private _outputResult: ScanResult | undefined;
  private _outputScanResult: OutputScanResult | undefined;
  private _done = false;
  private _fullText = "";
  private _stream: AsyncIterable<AnthropicStreamEvent>;
  private _shieldInstance: AIShield;
  private _context: ScanContext;
  private _scanOutput: boolean;
  private _outputScan: boolean | OutputScanConfig | undefined;
  private _agentId: string | undefined;
  private _model: string;
  private _inputTokens = 0;
  private _outputTokens = 0;

  constructor(
    stream: AsyncIterable<AnthropicStreamEvent>,
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

  async *[Symbol.asyncIterator](): AsyncGenerator<AnthropicStreamEvent> {
    for await (const event of this._stream) {
      // Accumulate text from content_block_delta events
      if (
        event.type === "content_block_delta" &&
        event.delta?.type === "text_delta" &&
        event.delta.text
      ) {
        this._fullText += event.delta.text;
      }

      // Capture usage from message_start
      if (event.type === "message_start" && event.message?.usage) {
        this._inputTokens = event.message.usage.input_tokens;
      }

      // Capture output tokens from message_delta
      if (event.type === "message_delta" && event.usage) {
        this._outputTokens = event.usage.output_tokens;
      }

      yield event;
    }

    // --- Post-stream: record cost ---
    if (this._agentId && (this._inputTokens > 0 || this._outputTokens > 0)) {
      await this._shieldInstance.recordCost(
        this._agentId,
        this._model,
        this._inputTokens,
        this._outputTokens,
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
