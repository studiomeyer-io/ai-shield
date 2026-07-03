# ai-shield-google-genai

[AI Shield](https://github.com/studiomeyer-io/ai-shield) wrapper for the
**new unified Google Gen AI SDK**
([`@google/genai`](https://www.npmjs.com/package/@google/genai)) —
prompt-injection detection, PII masking and output scanning for
`ai.models.generateContent` / `generateContentStream` (Gemini Developer API
and Vertex AI).

> Using the deprecated `@google/generative-ai` SDK
> (`GoogleGenerativeAI` + `getGenerativeModel()`)? That one is covered by
> [`ai-shield-gemini`](https://www.npmjs.com/package/ai-shield-gemini).
> This package targets the new SDK surface
> (`new GoogleGenAI()` + `ai.models.generateContent({ model, contents, config })`).

- **Input scan before the model call** — a `block` decision throws
  `ShieldBlockError` and the model is never invoked, `warn` fires the
  `onWarning` callback, PII masking rewrites the outgoing `contents`
  (user contents only).
- **Optional output scanning** — the legacy input chain (`scanOutput`) and/or
  the dedicated OWASP-LLM05 output scanner (`outputScan`: secret leak,
  SQL/XSS/shell payloads, system-prompt leak, output-side PII). Findings land
  in `response._shield` (non-streaming) or the stream's `shieldResult`
  (after completion). Output findings are reported, not blocked — gate on
  `_shield.outputScan.safe` before forwarding output to a downstream sink.
- **Cost tracking with the per-call model** — the new SDK passes `model` in
  every request, so budget checks and cost records use it directly (no
  `modelName` config needed).

## Install

```bash
npm install ai-shield-google-genai @google/genai
```

`@google/genai` (>= 2.0.0 < 3) is a peer dependency
(wrapper verified against `@google/genai@2.10.0`).

## Usage

```ts
import { GoogleGenAI } from "@google/genai";
import { createShield, ShieldBlockError } from "ai-shield-google-genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });

const shielded = createShield(ai, {
  agentId: "chatbot",
  shield: { pii: { action: "mask", locale: "de-DE" } },
  outputScan: true,
});

try {
  // Drop-in: same call shape as the raw client
  const response = await shielded.models.generateContent({
    model: "gemini-2.5-flash",
    contents: userInput,
  });
  console.log(response.text);           // the SDK's accessor still works
  console.log(response._shield);        // { input, outputScan }
} catch (err) {
  if (err instanceof ShieldBlockError) {
    console.warn("blocked:", err.scanResult.violations);
  }
}
```

Streaming:

```ts
const stream = await shielded.models.generateContentStream({
  model: "gemini-2.5-flash",
  contents: userInput,
});

for await (const chunk of stream) {
  process.stdout.write(chunk.text ?? "");
}

console.log(stream.text);         // full accumulated response
console.log(stream.shieldResult); // { input, output?, outputScan? } after completion
```

Full documentation, scanner configuration and the threat-model write-up live
in the [monorepo README](https://github.com/studiomeyer-io/ai-shield#readme).

## License

MIT — [StudioMeyer](https://studiomeyer.io)
