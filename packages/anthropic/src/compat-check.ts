import type Anthropic from "@anthropic-ai/sdk";
import type { ShieldedAnthropic } from "./wrapper.js";

type Assert<T extends true> = T;
type Extends<A, B> = A extends B ? true : false;

export type ClientCompat = Assert<
  Extends<Anthropic, ConstructorParameters<typeof ShieldedAnthropic>[0]>
>;
export type RequestCompat = Assert<
  Extends<
    Parameters<Anthropic["messages"]["create"]>[0],
    Parameters<ShieldedAnthropic["createMessage"]>[0]
  >
>;
export type StreamRequestCompat = Assert<
  Extends<
    Parameters<Anthropic["messages"]["create"]>[0],
    Parameters<ShieldedAnthropic["createMessageStream"]>[0]
  >
>;
