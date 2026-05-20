# ai-shield-classifier-onnx

Optional ONNX-runtime ML classifier for [ai-shield](https://github.com/studiomeyer-io/ai-shield).
Pairs with `ai-shield-core` to add a DeBERTa-style prompt-injection classifier
alongside the heuristic patterns.

## Why a separate package?

`ai-shield-core` is zero-dependency by design. ONNX inference requires
`onnxruntime-node`, which ships native binaries. Install this package only
when you actively want ML-augmented detection on top of the regex layer.

## Install

```bash
npm install ai-shield-core ai-shield-classifier-onnx onnxruntime-node
```

## Usage

```ts
import { ScannerChain, HeuristicScanner } from "ai-shield-core";
import { loadOnnxClassifier } from "ai-shield-classifier-onnx";

// Bring your own tokenizer. Example: protectai/deberta-v3-base-prompt-injection
const tokenizer = await yourTokenizerFor("protectai/deberta-v3-base-prompt-injection");

const ml = await loadOnnxClassifier({
  modelPath: "./models/deberta-injection.onnx",
  tokenizer,
  threshold: 0.85, // tune per model
});

const chain = new ScannerChain({ earlyExit: true });
chain.add(new HeuristicScanner({ strictness: "high" })); // cheap regex first
chain.add(ml);                                            // ML fallback

const result = await chain.run("Ignore previous instructions...");
console.log(result.decision); // "block"
```

Or manually with an already-constructed `InferenceSession`:

```ts
import * as ort from "onnxruntime-node";
import { OnnxInjectionScanner } from "ai-shield-classifier-onnx";

const session = await ort.InferenceSession.create("./models/deberta.onnx");
const scanner = new OnnxInjectionScanner({ session, tokenizer, threshold: 0.85 });
```

## Recommended models

- [`protectai/deberta-v3-base-prompt-injection`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection) (Apache-2.0)
- [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)
- Any HF model exported to ONNX via `optimum-cli export onnx`

## Notes

- The scanner degrades **gracefully** on inference errors — failure is logged
  as a `content_policy` violation but does not block traffic. This avoids
  taking down the whole chain when the model file is missing or the runtime
  hits a hardware-specific edge case.
- Use after the heuristic scanner. Most known attacks short-circuit on
  cheap regex; the ML pass catches paraphrases and obfuscations that slip
  through.
- The probability threshold is **calibrated per model**. Start at 0.85 and
  tune against your false-positive budget.

## License

MIT — see [LICENSE](../../LICENSE).
