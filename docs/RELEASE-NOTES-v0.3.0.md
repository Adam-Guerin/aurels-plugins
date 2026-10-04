# Aurels Plugins v0.3.0

This release fixes the production-readiness audit and adds independent evaluation with Jev, Laya, Ollama or an OpenAI-compatible model server.

- **OpenClaw:** authenticated redirects are refused, real tool failures are reported correctly, approval freezes evaluated parameters and flagged actions no longer generate duplicate blocked events. Compatibility is limited to tested hosts **2026.3.28 and 2026.9.6**; other versions are refused at registration.
- **Hermes:** the native `ok` outcome is classified as success, failures stay failures and action/trace correlation is preserved. Tests run the pinned Hermes dispatcher and inspect telemetry. Application-owned `run_protected` binds decisions to dispatched arguments; native allows require explicit trust in hook ordering.
- **Ollama:** replaces the invalid base tag with `qwen2.5:7b-instruct-q4_K_M`. The packaged Node installer verifies a locked manifest and creates from immutable model bytes, with pinned template and license. The installed preset is checked with real inference on Ollama 0.24.0.
- **Catalogues and supply chain:** both marketplace entry points expose the same four plugins, with an equality check in CI. The SPDX inventory includes the Ollama preset, model manifest, weight digest and dependency relationships. Release archives have checksums, signed checksum evidence and build attestations; CI actions are pinned by commit.
- **Self-hosted evaluation:** use your own provider credentials or local models, without an Aurels cloud account. Includes model readiness checks, bounded responses and concurrency, separate client/provider credentials and conservative action handling.
- **Experimental adapters:** downloadable packages for Claude Code, Codex, CrewAI, LangGraph, MCP and OpenAI Agents. Codex and CrewAI include actual host dispatch checks. These adapters remain experimental, with boundaries documented in the support matrix.

Install supported plugins from this release's archives and follow their package README. For Ollama, extract `aurels-ollama-plugin.zip` and run `node install.mjs` with a local Ollama server. The model weights (4.7 GB) are fetched separately.

An OpenClaw plugin load error must stop agent startup; it does not protect an agent that continues without the guard. Ollama analysis and Hermes retrospective mode are advisory. No live Jev/Laya credentials or production Aurels policies were available for verification; provider protocols are covered by fixtures.

See [support boundaries](https://github.com/Adam-Guerin/aurels-plugins/blob/v0.3.0/docs/SUPPORT-MATRIX.md) and [release verification](https://github.com/Adam-Guerin/aurels-plugins/blob/v0.3.0/docs/RELEASE-TRUST.md).
