import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import console from "node:console";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const destination = mkdtempSync(join(tmpdir(), "ai-shield-pack-"));
function targets(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(targets);
  if (value && typeof value === "object")
    return Object.values(value).flatMap(targets);
  return [];
}
try {
  const packages = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--workspaces", "--pack-destination", destination, "--json"],
      { cwd: root, encoding: "utf8" },
    ),
  );
  const workspaces = JSON.parse(
    readFileSync(join(root, "package.json"), "utf8"),
  ).workspaces;
  const checks = workspaces.map((workspace) => {
    const manifest = JSON.parse(
      readFileSync(join(root, workspace, "package.json"), "utf8"),
    );
    const pack = packages.find((item) => item.name === manifest.name);
    assert.ok(pack, `Missing packed workspace ${manifest.name}`);
    const files = new Set(pack.files.map((item) => item.path));
    const entrypoints = [
      ...new Set(
        [
          ...targets(manifest.exports),
          ...targets(manifest.main),
          ...targets(manifest.types),
        ].map((path) => path.replace(/^\.\//, "")),
      ),
    ];
    for (const entrypoint of entrypoints)
      assert.ok(files.has(entrypoint), `${manifest.name} omits ${entrypoint}`);
    return { package: manifest.name, entrypoints, status: "PASS" };
  });
  console.log(JSON.stringify(checks, null, 2));
} finally {
  rmSync(destination, { recursive: true, force: true });
}
