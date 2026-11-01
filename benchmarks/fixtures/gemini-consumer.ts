import {
  GoogleGenerativeAI,
  type GenerativeModel,
  type GenerateContentRequest,
  type Part,
} from "@google/generative-ai";
import {
  ShieldedGemini,
  createShield,
  type GenerateContentParams,
} from "ai-shield-gemini";
const sdk = new GoogleGenerativeAI("local-test-key");
const model: GenerativeModel = sdk.getGenerativeModel(
  { model: "local-test-model" },
  { baseUrl: "http://127.0.0.1:1" },
);
const wrapped = new ShieldedGemini(model);
const factory = createShield(model);
const request: GenerateContentRequest = {
  contents: [{ role: "user", parts: [{ text: "Hello" }] }],
  generationConfig: { temperature: 0.2 },
};
const parts: Part[] = [
  { text: "What is in this picture?" },
  { inlineData: { mimeType: "image/png", data: "AAAA" } },
  { functionResponse: { name: "lookup", response: { message: "Sunny" } } },
];
void wrapped.generateContent(request);
void wrapped.generateContentStream(request);
void wrapped.generateContent(parts);
void wrapped.generateContentStream(parts);
void wrapped.generateContent("Hello");
void wrapped.generateContentStream("Hello");
void factory.generateContent(request);
void factory.generateContentStream(parts);
void wrapped.generateContent({
  ...request,
  generationConfig: { temperature: 0.5 },
});
const legacy: GenerateContentParams = { ...request, customMetadata: "local" };
void wrapped.generateContent(legacy);
void wrapped.generateContentStream(legacy);
// @ts-expect-error Requests still require a content array.
void wrapped.generateContent({ contents: "Hello" });
