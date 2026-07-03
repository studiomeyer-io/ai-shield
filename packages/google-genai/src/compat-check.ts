// ============================================================
// Compile-time compatibility proof against the REAL `@google/genai`
// type declarations (devDependency; verified against 2.10.0).
//
// The wrapper duck-types the SDK to avoid a hard runtime dependency —
// this file guarantees at `tsc -b` time that the duck types stay
// structurally compatible with the actual SDK surface:
//
//   1. A real `GoogleGenAI` client is accepted by the wrapper.
//   2. The wrapper's request params are valid input for the real SDK
//      (they form a strict subtype of `GenerateContentParameters`).
//   3. The real `GenerateContentResponse` (a class — `.text` is a
//      prototype accessor) satisfies the wrapper's response type.
//   4. The real stream (`AsyncGenerator<GenerateContentResponse>`)
//      satisfies the wrapper's `AsyncIterable` expectation.
//
// Not exported from the package entry point — types only, no runtime.
// ============================================================

import type {
  GoogleGenAI,
  GenerateContentParameters,
  GenerateContentResponse,
} from "@google/genai";
import type {
  GoogleGenAIClientLike,
  GenAIGenerateContentParams,
  GenAIResponse,
} from "./wrapper.js";

type Extends<A, B> = A extends B ? true : false;
type Assert<T extends true> = T;

/** 1. Real client satisfies the duck-typed client interface. */
export type ClientCompat = Assert<Extends<GoogleGenAI, GoogleGenAIClientLike>>;

/** 2. Duck params are valid real-SDK params (safe to pass through). */
export type ParamsCompat = Assert<
  Extends<GenAIGenerateContentParams, GenerateContentParameters>
>;

/** 3. Real response satisfies the duck-typed response. */
export type ResponseCompat = Assert<
  Extends<GenerateContentResponse, GenAIResponse>
>;

/** 4. Real stream satisfies the duck-typed stream. */
export type StreamCompat = Assert<
  Extends<AsyncGenerator<GenerateContentResponse>, AsyncIterable<GenAIResponse>>
>;
