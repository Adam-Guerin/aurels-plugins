# Aurels Plugins

Open-source, downloadable integrations maintained by Aurels.

## Available plugins

- **Aurels for OpenClaw** — integration package for OpenClaw.
- **Aurels for Hermes** — integration package for Hermes.
- **Aurels for Ollama** — local security-analysis model preset, installable through the Codex marketplace or release archive.
- **Framework integrations** — experimental adapters for Claude Code, Codex, CrewAI, LangGraph, MCP, and OpenAI Agents, maintained in `plugins/aurels-integrations`. Aurels Codex Guard is also listed as an experimental, manually installable plugin in this repository's Codex marketplace.

The build generates downloadable experimental installers for Claude Code, Codex, CrewAI, LangGraph, OpenAI Agents, and MCP. The release workflow attaches them to GitHub releases; [published releases](https://github.com/Adam-Guerin/aurels-plugins/releases) may not yet contain the newest packages. They remain experimental, not production-supported marketplace releases. See [the integrations guide](plugins/aurels-integrations/README.md) for installation steps and enforcement boundaries.

Each plugin is self-contained in `plugins/`, with its executable source, tests, configuration example, release notes, and operating documentation. No code from the Aurels web application is required to run either package.

## Repository layout

```text
plugins/
  aurels-openclaw/
  aurels-hermes/
  aurels-ollama/
  aurels-integrations/
```

Start with the documentation inside the package you want to install:

- [Complete documentation index](docs/INDEX.md)
- [OpenClaw installation and security contract](plugins/aurels-openclaw/README.md)
- [Hermes installation and security contract](plugins/aurels-hermes/README.md)
- [Supported runtimes and coverage boundaries](docs/SUPPORT-MATRIX.md)
- [October 2026 hardening and regression evidence](docs/PLUGIN-HARDENING-2026-10.md)
- [Experimental framework integrations and limitations](plugins/aurels-integrations/README.md)
- [Release verification and supply-chain evidence](docs/RELEASE-TRUST.md)
- [Security reporting and least-privilege keys](SECURITY.md)

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), open an issue for larger changes, and submit plugins through pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
