# Aurels for Ollama

Install with Node.js 22+ and a running local Ollama server (verified on Ollama
0.24.0). From this directory or the extracted release archive:

```bash
node install.mjs
ollama run aurels-local
```

This preset is a local reasoning aid, not an execution-enforcement hook. Use it with an Aurels enforcement integration for actions that can have side effects.

The base is `qwen2.5:7b-instruct-q4_K_M` (4.7 GB). `model.lock.json` pins
the registry manifest and GGUF weights by full SHA-256, as well as the bundled
template and Apache-2.0 model license. The installer pulls missing weights,
refuses a changed manifest, and creates from the immutable GGUF blob rather
than resolving the tag again. It then verifies the installed weight reference.
Model weights are downloaded separately and are not included in the plugin ZIP.

To choose the output model name or local server:

```bash
node install.mjs aurels-local http://127.0.0.1:11434
```

Use the installer for digest verification. `ollama create -f Modelfile.aurels`
alone resolves a mutable tag and does not verify the lock. Do not manually
change a digest to bypass an installation failure; update the lock only after
verifying the model and rerunning deployment checks.

The preset embeds a security-analysis system prompt, temperature 0 and an 8192
token context. Model outputs still require validation and appropriate approval.
To use it as the model behind the separately packaged evaluator, select
`provider: "ollama"`, `model: "aurels-local"` and your local Ollama URL, then run
the evaluator's `verify` command before enabling it for an agent.
