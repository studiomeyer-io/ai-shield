// @ts-check
// ESLint flat config (ESLint 10 + typescript-eslint 8).
//
// Layering:
//   1. Global ignores (build output, deps, coverage).
//   2. All .ts files: recommended (syntax-level, no type info required).
//   3. Package sources only: type-aware layer via projectService — surfaces
//      @typescript-eslint/no-floating-promises as WARNINGS for human review.
//      Do NOT autofix floating promises in this codebase: inserting `void` /
//      `await` changes control flow in a security library.
import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig([
  globalIgnores([
    "**/dist/**",
    "**/node_modules/**",
    "coverage/**",
    "**/*.tsbuildinfo",
  ]),

  // Lint the config files themselves (this file, future *.mjs scripts).
  {
    files: ["**/*.{js,mjs,cjs}"],
    extends: [js.configs.recommended],
  },

  // All TypeScript: syntax-level rules, no type information needed.
  // Applies to packages/*/src, tests/, examples/, vitest.config.ts.
  {
    files: ["**/*.ts"],
    // NOTE: tseslint.configs.stylistic was evaluated and deliberately NOT
    // adopted: it reports 64 findings (54x array-type, 6x no-empty-function,
    // ...) whose autofixes would rewrite tokens inside the scanner/policy
    // sources. Revisit as a separate, reviewed change if wanted.
    extends: [js.configs.recommended, tseslint.configs.recommended],
    rules: {
      // The codebase deliberately avoids `any` — keep it that way.
      "@typescript-eslint/no-explicit-any": "error",
      // Honor the codebase's existing `_`-prefix convention for intentionally
      // unused bindings (mirrors tsc's noUnusedParameters behavior).
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      // The heuristic scanner's regexes deliberately contain zero-width /
      // invisible characters — they ARE the detection payload (zero-width
      // smuggling, Unicode TAG-block evasion). Strings are skipped by the
      // rule's default; regexes need the explicit opt-out.
      "no-irregular-whitespace": ["error", { skipRegExps: true }],
      // New in ESLint 10 recommended. The two current hits are real findings
      // (optional-dependency import errors that inline the message instead of
      // attaching `cause`), but the fix changes thrown-error shape — a runtime
      // behavior change. Surface as warnings for human review; do not autofix.
      "preserve-caught-error": "warn",
    },
  },

  // Test-only relaxations.
  {
    files: ["tests/**/*.ts"],
    rules: {
      // Tests cast partial mocks with `as any` (audit.test.ts). Keep the
      // hard error for published package sources, surface in tests.
      "@typescript-eslint/no-explicit-any": "warn",
      // The corpus test prints a readable detection-rate report behind an
      // explicit eslint-disable directive the authors already wrote —
      // enabling the rule here makes that directive meaningful and catches
      // stray debug logging in new tests.
      "no-console": "warn",
    },
  },

  // Type-aware layer for published package sources only. Each package has its
  // own tsconfig.json (composite, include: ["src"]), which projectService
  // resolves per-file. tests/ and examples/ are not part of any tsconfig
  // project and stay on the syntax-level layer above.
  {
    files: ["packages/*/src/**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Surface unawaited promises for review — warn, never autofix.
      "@typescript-eslint/no-floating-promises": "warn",
    },
  },
]);
