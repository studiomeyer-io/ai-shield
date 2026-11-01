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
const destination = mkdtempSync(join(tmpdir(), "ai-shield-new-sdk-"));
const groups = [
  {
    name: "ai-sdk",
    peer: "ai",
    versions: ["7.0.0", "7.0.159"],
    minimumNode: 22,
  },
  {
    name: "google-genai",
    peer: "@google/genai",
    versions: ["2.0.0", "2.32.0"],
    minimumNode: 20,
  },
].filter(
  (group) =>
    process.argv.length === 2 || process.argv.slice(2).includes(group.name),
);
assert.ok(groups.length > 0);
const run = (command, args, cwd) =>
  execFileSync(command, args, { cwd, encoding: "utf8" });
try {
  const packs = JSON.parse(
    run(
      "npm",
      ["pack", "--workspaces", "--pack-destination", destination, "--json"],
      root,
    ),
  );
  const tarball = (name) => {
    const pack = packs.find((item) => item.name === name);
    assert.ok(pack, `Missing ${name}`);
    return `file:${join(destination, pack.filename)}`;
  };
  const results = [];
  for (const group of groups) {
    assert.ok(
      Number(process.versions.node.split(".")[0]) >= group.minimumNode,
      `${group.name} requires Node${group.minimumNode}+`,
    );
    for (const version of group.versions) {
      const consumer = join(destination, `${group.name}-${version}`);
      mkdirSync(consumer);
      const dependencies = {
        [group.peer]: version,
        "ai-shield-core": tarball("ai-shield-core"),
        [`ai-shield-${group.name}`]: tarball(`ai-shield-${group.name}`),
      };
      if (group.name === "ai-sdk") dependencies.zod = "4.6.7";
      writeFileSync(
        join(consumer, "package.json"),
        JSON.stringify(
          {
            name: `shield-${group.name}-consumer`,
            private: true,
            type: "module",
            dependencies,
            devDependencies: { "@types/node": "22.20.5" },
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
      for (const extension of ["ts", "mjs"])
        copyFileSync(
          join(
            root,
            "benchmarks/fixtures",
            `${group.name}-consumer.${extension}`,
          ),
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
        run(
          process.execPath,
          [join(consumer, "consumer.mjs")],
          consumer,
        ).trim(),
      );
      const installed = JSON.parse(
        readFileSync(
          join(consumer, "node_modules", group.peer, "package.json"),
          "utf8",
        ),
      );
      assert.equal(installed.version, version);
      results.push({
        package: `ai-shield-${group.name}`,
        sdk: group.peer,
        version,
        strict: true,
        skipLibCheck: false,
        types: "PASS",
        runtime,
      });
    }
  }
  console.log(JSON.stringify(results, null, 2));
} finally {
  rmSync(destination, { recursive: true, force: true });
}
