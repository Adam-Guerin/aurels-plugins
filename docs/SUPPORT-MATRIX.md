# Support matrix

| Package | Version | Runtime | Status | Security boundary |
| --- | --- | --- | --- | --- |
| Aurels OpenClaw | 0.2.5 | Node 20+, OpenClaw 2026.3.2+ | Supported | `before_tool_call` / `after_tool_call` only |
| Aurels Hermes | 0.2.5 | Python 3.11+, native hook host | Supported | `pre_tool_call` / `post_tool_call` only |
| Aurels Ollama | 0.2.5 | Ollama with `qwen3-coder:q3` | Supported | Local analysis only; not an execution hook |

Codex, CrewAI, LangGraph, OpenAI Agents, Claude Code, and MCP references are not packaged in this marketplace release. They must not be represented as supported marketplace plugins until they ship with the same release contract, tests, and documentation.
