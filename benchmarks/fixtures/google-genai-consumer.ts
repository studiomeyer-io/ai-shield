import { GoogleGenAI, type GenerateContentParameters } from "@google/genai";
import { ShieldedGoogleGenAI } from "ai-shield-google-genai";
const client = new GoogleGenAI({
  apiKey: "local-test-key",
  httpOptions: { baseUrl: "http://127.0.0.1:1" },
});
const wrapped = new ShieldedGoogleGenAI(client);
const params: GenerateContentParameters = {
  model: "test-model",
  contents: [{ role: "user", parts: [{ text: "Hello" }] }],
};
void wrapped.generateContent(params);
void wrapped.generateContentStream(params);
void wrapped.models.generateContent(params);
void wrapped.models.generateContentStream(params);
