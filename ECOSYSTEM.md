# StudioMeyer Ecosystem

AI Shield is part of the StudioMeyer open source toolkit. Here is everything we build and maintain.

## MCP Server Products (Hosted)

| Product | Tools | What it does | Link |
|---------|-------|-------------|------|
| **StudioMeyer Memory** | 53 | Persistent AI memory with knowledge graph, semantic search, multi-agent support | [memory.studiomeyer.io](https://memory.studiomeyer.io) |
| **StudioMeyer CRM** | 33 | Headless CRM — contacts, companies, deals, pipeline, health scores, Stripe sync | [crm.studiomeyer.io](https://crm.studiomeyer.io) |
| **StudioMeyer GEO** | 24 | AI visibility monitoring across 8 LLM platforms (ChatGPT, Gemini, Perplexity, Claude, Grok, DeepSeek, Meta AI, Copilot) | [geo.studiomeyer.io](https://geo.studiomeyer.io) |
| **MCP Crew** | 10 | 8 expert personas (CEO, CFO, CMO, CTO, PM, Analyst, Support, Creative) with domain frameworks | [crew.studiomeyer.io](https://crew.studiomeyer.io) |

All MCP products use OAuth 2.1 + Magic Link authentication. Free tiers available. EU Frankfurt hosting.

Connect any of them in Claude Desktop, Claude Code, Cursor, or any MCP client:

```
https://memory.studiomeyer.io/mcp
https://crm.studiomeyer.io/mcp
https://geo.studiomeyer.io/mcp
https://crew.studiomeyer.io/mcp
```

## Open Source Tools

| Project | Description | Install |
|---------|-------------|---------|
| **[AI Shield](https://github.com/studiomeyer-io/ai-shield)** | LLM security — prompt injection, PII, cost tracking, tool policies | `npm install ai-shield-core` |
| **[Darwin Agents](https://github.com/studiomeyer-io/darwin-agents)** | Self-evolving AI agents with A/B testing and safety gates | `npm install darwin-agents` |
| **[Agent Fleet](https://github.com/studiomeyer-io/agent-fleet)** | Multi-agent orchestration for Claude Code CLI | `git clone` + `npm install` |
| **[MCP Video](https://github.com/studiomeyer-io/mcp-video)** | Cinema-grade video production via MCP (FFmpeg + Playwright) | `npx mcp-video` |

## Claude Code Plugin Suite

Install all 4 MCP products as Claude Code plugins with one command:

```bash
/plugin marketplace add studiomeyer-io/studiomeyer-marketplace
```

[Marketplace repo](https://github.com/studiomeyer-io/studiomeyer-marketplace) — 119 tools, 21 slash commands, 5 skills, 3 subagents.

## How AI Shield fits in

AI Shield secures the input layer for any AI application — including the MCP servers above. Use it as middleware in your own agents, or as a standalone scanner for user-facing chatbots.

Typical integration: User input → **AI Shield scan** → MCP tool call → LLM response.

## License

All open source projects are MIT licensed. MCP server implementations are proprietary StudioMeyer software with free tiers.

---

Built by [StudioMeyer](https://studiomeyer.io) — AI agency from Mallorca, Spain.
