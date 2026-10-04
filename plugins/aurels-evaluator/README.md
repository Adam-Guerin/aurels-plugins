# Your own evaluator for Aurels plugins

Run the evaluation service on your computer and choose your own Jev account, Laya, Ollama, or a server that implements OpenAI structured chat responses. Plugins send their evaluation requests to this service. It forwards them only to your configured model endpoint; no Aurels account or Aurels evaluation server is required.

This is an experimental evaluator, version 0.1.0, requiring Node.js 22+. The automated suite verifies protocols and plugin enforcement with HTTP fixtures, not live model accuracy. A model decision is not a guarantee that an action is safe.

## Install and initialize

From this repository:

```sh
npm run package:evaluator
npm install ./dist/aurels-evaluator-0.1.0.tgz
npx --no-install aurels-evaluator init --provider jev
```

Alternatively install the archive from a release that includes it. This branch's archive is built locally; registry publication is not required. The package has no runtime dependencies.

Initialization creates `.aurels-evaluator/config.json` and `.aurels-evaluator/plugin.env`, refusing to overwrite either file. Keep both private: they contain the local service access token. Provider keys are read from environment variables and never copied into these files or printed.

Choose one provider per profile:

| Provider | Initialization | Provider credential | Default model endpoint |
| --- | --- | --- | --- |
| Jev by TypeSafe | `aurels-evaluator init --provider jev` | `TYPESAFE_API_KEY` required | `https://api.typesafe.ai`, model `jev-latest` |
| Laya | `aurels-evaluator init --provider laya` | Optional `LAYA_API_KEY` | `http://127.0.0.1:8000`, model `multilingual` |
| Ollama | `aurels-evaluator init --provider ollama --model YOUR_INSTALLED_MODEL` | Optional `AURELS_MODEL_API_KEY` | `http://127.0.0.1:11434` |
| Compatible server | `aurels-evaluator init --provider openai-compatible --model YOUR_MODEL --api-url http://127.0.0.1:8080/v1` | Optional `AURELS_MODEL_API_KEY` | Explicit URL required |

Prefix commands with `npx --no-install` if using the local npm installation. Use `--directory PATH --port 8789` for a separate profile, then `start --config PATH/config.json`. An explicit `--api-url` can override a provider endpoint. Remote endpoints require HTTPS; plain HTTP is accepted only for `127.0.0.1`, `localhost`, or `::1`. Embedded credentials, query strings, fragments, and redirects are rejected.

## Start the evaluator

For Jev, set your TypeSafe key in the evaluator terminal only, then start:

```powershell
$env:TYPESAFE_API_KEY = '<your TypeSafe key>'
npx --no-install aurels-evaluator start
```

For Ollama, start Ollama and install the chosen model first, then initialize the Ollama profile and run the same `start` command. The evaluator does not download models. The compatible-server provider requires `/chat/completions` with `response_format: json_schema` and a non-streaming JSON response; arbitrary chat-only endpoints are not supported.

For Laya, install its official HTTP server in a separate Python environment and bind it to loopback. In that environment's terminal:

```powershell
python -m pip install 'laya[serve]'
$env:LAYA_HOST = '127.0.0.1'
$env:LAYA_MODELS = 'multilingual'
$env:LAYA_JEV_STRICT = '0'
laya-serve
```

In another terminal, initialize the Laya profile and start the evaluator. The Laya server must return its full response with truncation metadata; Jev-strict output hides this information and cannot authorize execution here. If using Laya authentication, set the same `LAYA_API_KEY` in the Laya server and evaluator terminals. Laya uses `/v1/systemone`, not the OpenAI chat protocol. See the [official Laya server documentation](https://github.com/NandhaKishorM/laya/blob/main/docs/http-api.md) and [TypeSafe System One documentation](https://docs.typesafe.ai/concepts/system-one).

Leave the evaluator process running. `aurels-evaluator check` verifies service availability only; it does not load a model or test inference. Warm local models before starting protected work; their initial loading time may exceed the configured deadline.

Before connecting an agent, verify actual inference with your selected model and policy:

```sh
npx --no-install aurels-evaluator verify
# For a separate profile:
npx --no-install aurels-evaluator verify --config PATH/config.json
```

This sends five synthetic evaluation requests: an authorized read, credential extraction, destruction, malicious embedded instructions, and an unauthorized write. It executes no tools and accesses no example files. The JSON report contains decisions and latency, without credentials or full action payloads. A failed check exits with status 1. A gateway refusal caused by unavailable inference does not count as a passing security check. Run this after changing the provider, model, or policy; a green smoke test is still only a small acceptance sample.

On October 4, 2026, the five checks passed against locally installed Ollama 0.24.0 with `qwen2.5:7b`. Warm inference took roughly 0.6–0.8 seconds per check. This result does not validate Jev, Laya, another model, or another deployment. The service now explicitly asks chat models for confidence in the range 0–1 and caps Ollama generation at 128 tokens; percentages remain invalid responses.

## Connect the plugins

In the terminal that launches your agent or plugin host, load the generated environment file. This gives the host the local access token, not your provider key.

PowerShell:

```powershell
Get-Content .aurels-evaluator/plugin.env |
  Where-Object { $_ -match '^[A-Z_][A-Z0-9_]*=' } |
  ForEach-Object {
    $parts = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
  }
# Launch your agent host from this terminal.
```

POSIX shell, using the file generated by this command:

```sh
set -a
. ./.aurels-evaluator/plugin.env
set +a
# Launch your agent host here.
```

The file sets both `AURELS_API_URL` / `AUREL_API_URL` and `AURELS_API_KEY` / `AUREL_API_KEY`, requests remote evaluation against the local service, uses closed failure behavior, and disables telemetry, durable queues, and MCP execution permits. Here "remote" means the plugin's HTTP-client mode; the URL remains loopback.

This works with OpenClaw, Hermes, CrewAI, LangGraph, OpenAI Agents, the MCP proxy, Claude Code command hooks, and Codex Guard command hooks. A plugin's explicit configuration takes precedence over environment variables: replace any saved cloud `apiUrl`/`apiKey` with the local URL/token as well. In LangGraph or OpenAI Agents code, pass those values to the wrapper configuration. Protect every tool through the relevant adapter as described in its own README.

The existing host contracts still apply. OpenClaw retains one-shot approval with frozen arguments. Native Hermes refuses a remote allow unless hook ordering is explicitly trusted, and cannot pause for approval; application-owned `run_protected` supports synchronous protected dispatch. Codex Guard denies review-required calls. A real Codex 0.160.0 CLI session is tested with synthetic model/policy servers and actual file dispatch; interactive hook-trust prompts and full Claude Code sessions remain outside the automated coverage.

## Policy and operational limits

Edit `config.json` and restart the service to change `provider`, `model`, `apiUrl`, `policy`, `allowTools`, `minConfidence`, or resource limits. Keep provider secrets in the environment variable named by `apiKeyEnv`. The CLI rejects a literal `apiKey` property in configuration.

Only configured read-tool names can receive an automatic `allow`; other tools require review even if the model says allow. The default policy asks for read-only authorized work, blocks destruction and credential extraction, and requires review for writes or uncertain scope. Customize both the policy and exact tool names for your host; a tool name alone does not establish safe behavior.

`minConfidence` defaults to 0.85. For Jev and Laya it uses the selected choice's probability, not the provider's normalized confidence score. Laya also receives the abstention threshold; abstentions, incomplete context, or collapsed choices cannot authorize execution. Chat models supply their own confidence number, which is not calibrated security evidence. Validate your model and policy against representative allowed and denied actions before relying on them.

Requests default to a 16 KiB action/context budget, 10-second provider deadline, four concurrent evaluations, and 1 MiB HTTP body/response limits. Oversized inputs, invalid responses, disagreement between typed choices and probabilities, redirects, outages, or cancellation refuse execution. There is no cloud fallback. `timeoutMs` can be increased up to 30000; configure plugin timeouts longer than the provider deadline when changing it. `riskScore` is a coarse mapping of the decision (0/50/100), not a probability or Aurels risk calculation.

The CLI listens only on `127.0.0.1`. Use a secured HTTPS deployment with appropriate authentication if building a separate remote gateway. The generated loopback URL assumes the host and evaluator share a machine/network namespace; containers require deliberate networking configuration. Windows files inherit local user ACLs; POSIX files are created with private permissions. Do not commit or share the profile directory.

Evaluation sends the original action arguments and context to your chosen endpoint. Jev processes those inputs under your account; choosing a local endpoint keeps model evaluation local. This service does not redact evaluation inputs, persist audit events, implement Aurels dashboards, or issue signed execution permits. Telemetry endpoints return `accepted: false` with `storage: disabled` and never forward events; keep the generated telemetry settings disabled.

## Verification

From the repository root:

```sh
npm run test:evaluator
npm --prefix plugins/aurels-integrations run test:evaluator
npm run test:e2e:artifacts
```

Tests exercise actual HTTP requests, key separation, CLI startup, provider failures, Laya truncation and abstention, bounded concurrency, and dispatch through all eight adapters. Packaged evaluator tests run again after installing the generated archive in a clean directory. These checks do not use paid provider credentials or download model weights.
