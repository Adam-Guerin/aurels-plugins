# Aurels Plugins

Open-source, downloadable integrations maintained by Aurels.

## Available plugins

- **Aurels for OpenClaw** — integration package for OpenClaw.
- **Aurels for Hermes** — integration package for Hermes.
- **Aurels for Ollama** — local security-analysis model preset, installable through the Codex marketplace or release archive.

Each plugin is self-contained in `plugins/`, with its executable source, tests, configuration example, release notes, and operating documentation. No code from the Aurels web application is required to run either package.

## Repository layout

```text
plugins/
  aurels-openclaw/
  aurels-hermes/
  aurels-ollama/
```

Start with the documentation inside the package you want to install:

- [Complete documentation index](docs/INDEX.md)
- [OpenClaw installation and security contract](plugins/aurels-openclaw/README.md)
- [Hermes installation and security contract](plugins/aurels-hermes/README.md)
- [Supported runtimes and coverage boundaries](docs/SUPPORT-MATRIX.md)
- [Release verification and supply-chain evidence](docs/RELEASE-TRUST.md)
- [Security reporting and least-privilege keys](SECURITY.md)

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), open an issue for larger changes, and submit plugins through pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
