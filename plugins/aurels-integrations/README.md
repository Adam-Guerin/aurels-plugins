# Aurels framework integrations

Use your own Jev key or local Laya/Ollama model with the [self-hosted evaluator](../aurels-evaluator/README.md). The guide generates the local URL/token configuration; this adapter retains its existing enforcement and approval contract.

This package contains the framework adapters that were previously embedded in the Aurels web application. Their source of truth now lives in this repository.

## Experimental adapters

These adapters are available for review and controlled evaluation. They are not marketplace releases and do not have the same host-version matrix or release evidence as the supported OpenClaw and Hermes packages.

- Claude Code native hook plugin: `integrations/claude-code` (downloadable archive)
- Codex native hook plugin and optional MCP bridge: `integrations/codex` (downloadable archive)
- CrewAI: `integrations/crewai`
- LangGraph: `integrations/langgraph`
- MCP stdio proxy: `integrations/mcp`
- OpenAI Agents SDK: `integrations/openai-agents`

Independent npm release archives are built for LangGraph (`@aurels/langgraph-guard`), OpenAI Agents (`@aurels/openai-agents-guard`), and MCP (`@aurels/mcp-proxy`). Install from a GitHub release artifact URL using the adapter-specific instructions. The first two include the shared Aurels client; their host SDKs remain peer dependencies. The MCP archive provides an executable proxy command.

Build Claude Code and Codex native archives with `npm run package:claude-code` and `npm run package:codex`. Build the CrewAI wheel with `npm run package:crewai`; install CrewAI separately in the host application. The npm archives are built by `npm run package:langgraph`, `npm run package:openai-agents`, and `npm run package:mcp`. The Codex plugin is also listed as `aurels-codex-guard` in this repository marketplace, but remains manually installed and experimental. Downloadable packages do not automatically activate host plugins; follow each adapter's setup guide.

The former application adapters for OpenClaw, Hermes, and Ollama are retained under `legacy/` as migration snapshots. Use `plugins/aurels-openclaw`, `plugins/aurels-hermes`, and `plugins/aurels-ollama` for the maintained packages.

Shared helper code is under `integrations/shared`, and the local mock service is under `integrations/dev-harness`.

Validation includes compiled LangGraph graphs (@langchain/langgraph 1.4.18, @langchain/core 1.2.13), real OpenAI Agents Runner execution (@openai/agents 0.18.0), the official MCP SDK stdio client/server (1.32.0), and CrewAI 1.15.23 synchronous/asynchronous BaseTool dispatch. Model responses, tools, and Aurels policy responses are synthetic; no live model or account is needed. The npm host scenarios are repeated with independently installed archives, and CI tests CrewAI with an installed wheel. Claude Code and Codex tests execute native hook-format scripts against a fake local API and verify their archives; full Claude Code/Codex agent sessions remain unverified. See the [validation matrix](../../docs/SUPPORT-MATRIX.md) and [hardening report](../../docs/PLUGIN-HARDENING-2026-10.md). The general downloadable tarball remains a source bundle, not an installable package for every listed framework.

Before using an experimental adapter for consequential actions, review its host-specific README and limitations. These adapters must not be advertised as supported until each has focused host-level tests, a documented runtime matrix, and release packaging.
