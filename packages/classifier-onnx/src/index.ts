// ============================================================
// ai-shield-classifier-onnx — Optional ML classifier package
//
// Pairs with ai-shield-core. Adds an ONNX-runtime-backed
// prompt-injection classifier (DeBERTa-style by default) that can
// be added to a ScannerChain alongside the built-in heuristics.
//
// Why a separate package?
//   The core package keeps a zero-dependency promise (Node stdlib only).
//   ONNX inference requires `onnxruntime-node`, which ships native
//   binaries and is too heavy to force on every consumer. Install this
//   package only when you actively want ML-augmented detection.
//
// Recommended models:
//   - protectai/deberta-v3-base-prompt-injection (Apache-2.0)
//   - protectai/deberta-v3-base-prompt-injection-v2
//   - hf models exported to ONNX via `optimum-cli`
//
// The classifier is intentionally pluggable — you bring the model file
// + tokenizer JSON, the wrapper handles inference + thresholding +
// integration with the Scanner interface.
// ============================================================

export {
  OnnxInjectionScanner,
  loadOnnxClassifier,
  type OnnxClassifierConfig,
  type OnnxInferenceRuntime,
  type Tokenizer,
} from "./classifier.js";
