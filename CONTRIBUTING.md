# Contributing to AI Shield

Thanks for your interest in contributing! AI Shield is an open-source LLM security middleware, and we welcome contributions.

## Getting Started

```bash
git clone https://github.com/studiomeyer-io/ai-shield.git
cd ai-shield
npm install
npm run build
npm test
```

## Development

### Project Structure

```
packages/
  core/        — Scanner chain, heuristics, PII, cost, audit (zero deps)
  openai/      — OpenAI SDK wrapper
  anthropic/   — Anthropic SDK wrapper
  middleware/  — Express + Hono middleware
tests/         — All test files (vitest)
```

### Commands

```bash
npm test                    # Run all 232 tests
npm run build               # Build all packages
npm run typecheck            # TypeScript strict check
npx vitest run tests/unit/heuristic.test.ts  # Single test file
```

### Code Standards

- **TypeScript strict** — `noUncheckedIndexedAccess`, `noUnusedLocals`, `noUnusedParameters`
- **No `any`** — ever
- **Zero runtime dependencies** in `@ai-shield/core` — everything optional via peer deps
- **All scanners** implement the `Scanner` interface from `types.ts`
- **Tests must pass** before any PR

## Adding a Scanner

1. Create your scanner in `packages/core/src/scanner/`
2. Implement the `Scanner` interface (see `types.ts`)
3. Register it in the scanner chain (`shield.ts`)
4. Add tests in `tests/unit/`
5. Update the README

## Adding Injection Patterns

Edit `packages/core/src/scanner/heuristic.ts`:

```typescript
{
  pattern: /your-regex-here/i,
  weight: 0.3,          // 0.0-1.0, higher = more suspicious
  category: 'instruction_override',
  description: 'What this pattern catches'
}
```

Then add test cases in `tests/unit/heuristic.test.ts` for both detection and false-positive prevention.

## Pull Requests

1. Fork the repo and create a feature branch
2. Make your changes
3. Run `npm test` and `npm run typecheck`
4. Submit a PR with a clear description

## Reporting Security Issues

If you find a security vulnerability, please email security@studiomeyer.io instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
