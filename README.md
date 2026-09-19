# Codex Plugin Marketplace

An open-source collection of plugins for Codex. Each plugin lives in its own directory under `plugins/` and can provide skills, MCP servers, apps, hooks, scripts, or assets.

## Install this marketplace

Clone this repository, then add its marketplace definition in Codex:

```powershell
codex plugin marketplace add C:\path\to\codex-plugin-marketplace
```

Install any listed plugin from the Codex Plugins view.

## Add a plugin

1. Create `plugins/<plugin-name>/`.
2. Add a valid `plugins/<plugin-name>/.codex-plugin/plugin.json`.
3. Add the plugin to `marketplace.json`.
4. Run the validation workflow locally or in a pull request.

Use short, hyphenated names, keep each plugin self-contained, and document any setup it needs.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), open an issue for larger changes, and submit plugins through pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
