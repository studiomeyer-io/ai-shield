import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import console from "node:console";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL, URL } from "node:url";

// Exercise declarations from real packed artifacts at the exact peer floor,
// the previously tested v4, and the development major. Legacy SDKs live only
// in this disposable consumer tree, outside the repository dependency graph.
const root = fileURLToPath(new URL("../", import.meta.url));
const destination = mkdtempSync(join(tmpdir(), "ai-shield-openai-peers-"));
const supported = ["4.0.0", "4.104.0", "6.49.0"];
const versions = process.argv.length > 2 ? process.argv.slice(2) : supported;
for (const version of versions)
  assert.ok(supported.includes(version), `Unknown fixture ${version}`);
const run = (command, args, cwd) =>
  execFileSync(command, args, { cwd, encoding: "utf8" });
try {
  const packs = JSON.parse(
    run(
      "npm",
      [
        "pack",
        "--workspace",
        "ai-shield-core",
        "--workspace",
        "ai-shield-openai",
        "--pack-destination",
        destination,
        "--json",
      ],
      root,
    ),
  );
  const tarball = (name) => {
    const pack = packs.find((item) => item.name === name);
    assert.ok(pack, `Missing pack ${name}`);
    return `file:${join(destination, pack.filename)}`;
  };
  const results = [];
  for (const version of versions) {
    const consumer = join(destination, version);
    mkdirSync(consumer);
    const prefix =
      version === "4.0.0"
        ? "CompletionCreateParams"
        : "ChatCompletionCreateParams";
    writeFileSync(
      join(consumer, "package.json"),
      JSON.stringify(
        {
          name: "ai-shield-openai-peer-probe",
          private: true,
          type: "module",
          dependencies: {
            openai: version,
            "ai-shield-core": tarball("ai-shield-core"),
            "ai-shield-openai": tarball("ai-shield-openai"),
            zod: version.startsWith("6.") ? "4.6.7" : "3.25.76",
          },
        },
        null,
        2,
      ),
    );
    run(
      "npm",
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
      ],
      consumer,
    );
    writeFileSync(
      join(consumer, "tsconfig.json"),
      JSON.stringify(
        {
          compilerOptions: {
            target: "ES2022",
            module: "NodeNext",
            moduleResolution: "NodeNext",
            strict: true,
            skipLibCheck: false,
            noEmit: true,
          },
          include: ["consumer.ts"],
        },
        null,
        2,
      ),
    );
    writeFileSync(
      join(consumer, "consumer.ts"),
      `
import OpenAI from "openai";
import { ShieldedOpenAI } from "ai-shield-openai";
const client = new OpenAI({ apiKey: "local-test-key" });
const wrapper = new ShieldedOpenAI(client);
const plain: OpenAI.Chat.Completions.${prefix}NonStreaming = {
  model: "test-model", messages: [{ role: "user", content: "Hello" }], stream: false,
};
const streaming: OpenAI.Chat.Completions.${prefix}Streaming = { ...plain, stream: true };
const either: OpenAI.Chat.Completions.${prefix} = Math.random() < 0.5 ? plain : streaming;
void wrapper.createChatCompletion(plain);
void wrapper.createChatCompletionStream(streaming);
void wrapper.createChatCompletion(either);
void wrapper.createChatCompletionStream(either);
void wrapper.createChatCompletion({ model: "test-model", messages: [{ role: "user", content: "Hello" }], temperature: 0.2 });
`,
    );
    run(
      process.execPath,
      [
        join(root, "node_modules/typescript/bin/tsc"),
        "-p",
        join(consumer, "tsconfig.json"),
      ],
      consumer,
    );
    const runtime = run(
      process.execPath,
      [
        join(root, "benchmarks/openai-compat.mjs"),
        pathToFileURL(join(consumer, "node_modules/openai/index.mjs")).href,
        version,
        pathToFileURL(
          join(consumer, "node_modules/ai-shield-openai/dist/index.js"),
        ).href,
      ],
      consumer,
    );
    const manifest = JSON.parse(
      readFileSync(
        join(consumer, "node_modules/ai-shield-openai/package.json"),
        "utf8",
      ),
    );
    assert.equal(manifest.peerDependencies.openai, ">=4.0.0");
    results.push({
      version,
      strict: true,
      skipLibCheck: false,
      types: "PASS",
      runtime: JSON.parse(runtime.trim()),
    });
  }
  console.log(JSON.stringify(results, null, 2));
} finally {
  rmSync(destination, { recursive: true, force: true });
}
