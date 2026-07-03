# ai-shield-ai-sdk

[AI Shield](https://github.com/studiomeyer-io/ai-shield) middleware for the
[Vercel AI SDK](https://ai-sdk.dev) (`ai` >= 7) — prompt-injection detection,
PII masking and output scanning for any AI SDK provider via
`wrapLanguageModel`.

- **Input scan before the provider call** — runs in `transformParams`: a
  `block` decision throws `ShieldBlockError` and the model is never invoked,
  `warn` fires the `onWarning` callback, PII masking rewrites the outgoing
  prompt (user messages only).
- **Optional output scanning** — the legacy input chain (`scanOutput`) and/or
  the dedicated OWASP-LLM05 output scanner (`outputScan`: secret leak,
  SQL/XSS/shell payloads, system-prompt leak, output-side PII). Findings are
  attached under `providerMetadata.aiShield` — on the generate result, and on
  the `finish` stream part for `streamText`. Output findings are reported,
  not blocked; gate on `aiShield.outputScan.safe` before forwarding output to
  a downstream sink.

## Install

```bash
npm install ai-shield-ai-sdk ai
```

`ai` (>= 7.0.0 < 8) is a peer dependency. The middleware targets the
`LanguageModelV4` middleware specification (`ai@7` / `@ai-sdk/provider@4`).

## Usage

```ts
import { openai } from "@ai-sdk/openai";
import { generateText, wrapLanguageModel } from "ai";
import { aiShieldMiddleware, ShieldBlockError } from "ai-shield-ai-sdk";

const model = wrapLanguageModel({
  model: openai("gpt-4o"),
  middleware: aiShieldMiddleware({
    agentId: "chatbot",
    shield: { pii: { action: "mask", locale: "de-DE" } },
    outputScan: true,
  }),
});

try {
  const { text, providerMetadata } = await generateText({ model, prompt: userInput });
  console.log(providerMetadata?.aiShield); // { input, outputScan }
} catch (err) {
  if (err instanceof ShieldBlockError) {
    console.warn("blocked:", err.scanResult.violations);
  }
}
```

One-line convenience factory:

```ts
import { shieldModel } from "ai-shield-ai-sdk";

const model = shieldModel(openai("gpt-4o"), { outputScan: true });
```

Streaming (`streamText`) works the same way — the input scan still blocks
before the stream starts; output scan results land on the `finish` stream
part's `providerMetadata.aiShield`.

Full documentation, scanner configuration and the threat-model write-up live
in the [monorepo README](https://github.com/studiomeyer-io/ai-shield#readme).

## License

MIT — [StudioMeyer](https://studiomeyer.io)
