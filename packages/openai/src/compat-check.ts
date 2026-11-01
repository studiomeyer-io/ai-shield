import type OpenAI from "openai";
import type { ShieldedOpenAI } from "./wrapper.js";
type Assert<T extends true> = T;
/** The actual SDK must satisfy the public constructor without a cast. */
export type OpenAIClientCompatibility = Assert<
  OpenAI extends ConstructorParameters<typeof ShieldedOpenAI>[0] ? true : false
>;
