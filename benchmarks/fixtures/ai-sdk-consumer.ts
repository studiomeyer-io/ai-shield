import {
  generateText,
  streamText,
  wrapLanguageModel,
  type LanguageModelMiddleware,
} from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { aiShieldMiddleware } from "ai-shield-ai-sdk";
const middleware: LanguageModelMiddleware = aiShieldMiddleware({});
const model = wrapLanguageModel({
  model: new MockLanguageModelV4(),
  middleware,
});
const params: Parameters<typeof model.doGenerate>[0] = {
  prompt: [{ role: "user", content: [{ type: "text", text: "Hello" }] }],
};
void model.doGenerate(params);
void model.doStream(params);
void generateText({ model, prompt: "Hello", maxRetries: 0 });
void streamText({ model, prompt: "Hello", maxRetries: 0 });
