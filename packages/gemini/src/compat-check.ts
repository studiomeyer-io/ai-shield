import type {
  GenerativeModel,
  GenerateContentRequest,
  Part,
} from "@google/generative-ai";
import type { ShieldedGemini } from "./wrapper.js";

type Assert<T extends true> = T;
type Extends<A, B> = A extends B ? true : false;

export type ClientCompat = Assert<
  Extends<GenerativeModel, ConstructorParameters<typeof ShieldedGemini>[0]>
>;
export type RequestCompat = Assert<
  Extends<
    GenerateContentRequest,
    Parameters<ShieldedGemini["generateContent"]>[0]
  >
>;
export type PartsCompat = Assert<
  Extends<Part[], Parameters<ShieldedGemini["generateContentStream"]>[0]>
>;
