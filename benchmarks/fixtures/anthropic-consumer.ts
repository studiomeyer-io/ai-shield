import Anthropic from "@anthropic-ai/sdk";
import {
  ShieldedAnthropic,
  type AnthropicCreateParams,
} from "ai-shield-anthropic";

const client = new Anthropic({ apiKey: "local-test-key" });
const wrapper = new ShieldedAnthropic(client);
type SDKRequest = Parameters<Anthropic["messages"]["create"]>[0];
const createOpts: SDKRequest = {
  model: "local-test-model",
  max_tokens: 16,
  messages: [{ role: "user", content: [{ type: "text", text: "Hello" }] }],
  system: [{ type: "text", text: "Be helpful" }],
  tools: [
    {
      name: "lookup",
      description: "Find a fact",
      input_schema: {
        type: "object",
        properties: { term: { type: "string" } },
        required: ["term"],
      },
    },
  ],
  metadata: { user_id: "local-test-user" },
  temperature: 0.2,
};
const plain: SDKRequest & { stream: false } = { ...createOpts, stream: false };
const streaming: SDKRequest & { stream: true } = {
  ...createOpts,
  stream: true,
};
const variable: SDKRequest = { ...createOpts, stream: Math.random() > 0.5 };
void wrapper.createMessage(createOpts);
void wrapper.createMessage(plain);
void wrapper.createMessage(streaming);
void wrapper.createMessage(variable);
void wrapper.createMessageStream(createOpts);
void wrapper.createMessageStream(plain);
void wrapper.createMessageStream(streaming);
void wrapper.createMessageStream(variable);
void wrapper.createMessage({ ...createOpts, temperature: 0.5 });
const legacy: AnthropicCreateParams = {
  ...createOpts,
  temperature: 0.3,
  metadata: { user_id: "legacy-request" },
};
void wrapper.createMessage(legacy);
void wrapper.createMessageStream(legacy);
// @ts-expect-error The structural request still requires a numeric token limit.
void wrapper.createMessage({ ...plain, max_tokens: "16" });
