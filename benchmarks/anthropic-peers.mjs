import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import console from "node:console";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const destination = mkdtempSync(join(tmpdir(), "ai-shield-anthropic-peers-"));
const supported = ["0.30.0", "0.135.0", "0.137.0"];
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
        "ai-shield-anthropic",
        "--pack-destination",
        destination,
        "--json",
      ],
      root,
    ),
  );
  const tarball = (name) => {
    const pack = packs.find((item) => item.name === name);
    assert.ok(pack, `Missing ${name}`);
    return `file:${join(destination, pack.filename)}`;
  };
  const results = [];
  for (const version of versions) {
    const consumer = join(destination, version);
    mkdirSync(consumer);
    writeFileSync(
      join(consumer, "package.json"),
      JSON.stringify(
        {
          name: "ai-shield-anthropic-peer-probe",
          private: true,
          type: "module",
          dependencies: {
            "@anthropic-ai/sdk": version,
            "ai-shield-core": tarball("ai-shield-core"),
            "ai-shield-anthropic": tarball("ai-shield-anthropic"),
          },
          devDependencies: { "@types/node": "22.20.5" },
        },
        null,
        2,
      ),
    );
    run(
      "npm",
      ["install", "--ignore-scripts", "--no-audit", "--no-fund"],
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
    for (const extension of ["ts", "mjs"])
      copyFileSync(
        join(root, "benchmarks/fixtures", `anthropic-consumer.${extension}`),
        join(consumer, `consumer.${extension}`),
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
    const runtime = JSON.parse(
      run(process.execPath, [join(consumer, "consumer.mjs")], consumer).trim(),
    );
    const manifest = JSON.parse(
      readFileSync(
        join(consumer, "node_modules/ai-shield-anthropic/package.json"),
        "utf8",
      ),
    );
    assert.equal(manifest.peerDependencies["@anthropic-ai/sdk"], ">=0.30.0");
    const installed = JSON.parse(
      readFileSync(
        join(consumer, "node_modules/@anthropic-ai/sdk/package.json"),
        "utf8",
      ),
    );
    assert.equal(installed.version, version);
    results.push({
      version,
      strict: true,
      skipLibCheck: false,
      types: "PASS",
      runtime,
    });
  }
  console.log(JSON.stringify(results, null, 2));
} finally {
  rmSync(destination, { recursive: true, force: true });
}
