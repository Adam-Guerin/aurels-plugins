# Documentation

This repository is the public source of truth for the supported Aurels plugin packages.

## Start here

- [Repository overview](../README.md)
- [Support matrix and runtime boundaries](SUPPORT-MATRIX.md)
- [October 2026 hardening and regression evidence](PLUGIN-HARDENING-2026-10.md)
- [Your own Jev key or local model](../plugins/aurels-evaluator/README.md)
- [Release verification](RELEASE-TRUST.md)
- [Security reporting and key hygiene](../SECURITY.md)
- [Contributing](../CONTRIBUTING.md)

## OpenClaw

- [Install, configure, and verify](../plugins/aurels-openclaw/README.md)
- [Operational rollout, rotation, and rollback](../plugins/aurels-openclaw/docs/OPERATIONS.md)
- [Data handling](../plugins/aurels-openclaw/docs/DATA-HANDLING.md)
- [Release history](../plugins/aurels-openclaw/CHANGELOG.md)

## Hermes

- [Install, configure, and verify](../plugins/aurels-hermes/README.md)
- [Operational rollout, rotation, and rollback](../plugins/aurels-hermes/docs/OPERATIONS.md)
- [Data handling](../plugins/aurels-hermes/docs/DATA-HANDLING.md)
- [Release history](../plugins/aurels-hermes/CHANGELOG.md)

## Experimental framework integrations

- [Adapters and support boundary](../plugins/aurels-integrations/README.md)
- [Claude Code](../plugins/aurels-integrations/integrations/claude-code/README.md)
- [Codex native hook plugin and MCP bridge](../plugins/aurels-integrations/integrations/codex/aurel-codex-plugin/README.md)
- [CrewAI](../plugins/aurels-integrations/integrations/crewai/README.md)
- [LangGraph](../plugins/aurels-integrations/integrations/langgraph/README.md)
- [MCP proxy](../plugins/aurels-integrations/integrations/mcp/README.md)
- [OpenAI Agents SDK](../plugins/aurels-integrations/integrations/openai-agents/README.md)

## Support boundary

Only OpenClaw, Hermes, and Ollama are supported marketplace packages. The framework adapters are experimental and are not covered by that support contract. Never copy an API key into an issue, pull request, or example configuration.
