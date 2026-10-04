# Support matrix

| Package | Version | Runtime | Status | Security boundary |
| --- | --- | --- | --- | --- |
| Aurels OpenClaw | 0.2.6 | Node 20+, OpenClaw 2026.3.28+ | Supported | Hook-runner contract tested on 2026.3.28 and 2026.9.6; 2026.3.2 explicitly fails closed. One-shot approval freezes the exact evaluated parameters; host-trusted/native paths outside the ordinary approval chain remain outside scope |
| Aurels Hermes | 0.2.6 | Python 3.11+, pinned Hermes native hook host | Supported with constraints | Native refusal tested through real dispatch. Remote native allow is blocked unless hook ordering is explicitly trusted. Application-owned synchronous `run_protected` binds evaluation to its argument snapshot. `retrospective` is advisory only |
| Aurels Ollama | 0.2.6 | Ollama with `qwen3-coder:q3` | Supported | Local analysis only; not an execution hook |

## Self-hosted evaluation

`@aurels/evaluator` 0.1.0 is an experimental Node 22+ service for Jev, Laya, Ollama, and OpenAI-compatible structured-output servers. All eight enforcement adapters are exercised through its real HTTP endpoint using fixture models; the installed archive is also verified. The five-case `verify` smoke test passed locally with Ollama 0.24.0 / `qwen2.5:7b` on October 4, 2026. Live Jev/Laya and broader model accuracy remain unverified. Existing host boundaries below still apply. See the [configuration guide](../plugins/aurels-evaluator/README.md).

## Experimental adapters: validated boundaries

These packages remain experimental and outside the supported marketplace release contract. Validation is stronger than a wrapper-only smoke test, but does not establish universal host compatibility.

| Adapter | Package version | Tested host | Evidence and remaining boundary |
| --- | --- | --- | --- |
| Claude Code | 0.1.0 | Native hook-format command scripts | Packaged pre/post scripts against a synthetic API; full Claude Code sessions and interactions between hooks unverified |
| Codex Guard | 0.1.0 | Codex CLI 0.160.0 | Real CLI dispatch with native hook declarations and synthetic model/policy servers: allow writes a disposable file; block/review/outage prevent it; packaged scripts repeated. Windows verified locally, Linux and Windows configured in CI. Hook trust UI and marketplace discovery unverified; approval and rewrite conservatively denied |
| CrewAI | 0.1.0 | CrewAI 1.15.23 | Real `BaseTool.run` and `BaseTool.arun`, including approval/refusal/rewrite/outage; installed wheel tested in CI; unwrapped tools remain outside the boundary |
| LangGraph | 0.1.0 | LangGraph 1.4.18 / core 1.2.13 | Compiled graph runs with synthetic model messages and protected ToolNode; repeated with an installed npm archive; other graph nodes/tools must be protected separately |
| OpenAI Agents | 0.1.0 | Agents SDK 0.18.0 | Real Runner dispatch using synthetic model responses; repeated with an installed npm archive; only wrapped function tools are covered |
| MCP proxy | 0.1.0 | MCP JavaScript SDK 1.32.0 | Real newline stdio initialization/list/call, refusal, rewrite, cancellation, pending cap, and structured errors; repeated with an installed npm archive; only proxied servers/calls are covered |

Hermes CI pins host commit `f97608f178d1ffeca59860195ab7da295f7c8e5f`. The automated suite uses synthetic policy/model responses and tool handlers; it does not validate live Aurels policy quality, production credentials, or every host execution path. Local Ollama inference was checked separately through the evaluator, using installed weights without a download; it does not validate the `qwen3-coder:q3` analysis preset. See the [hardening report and reproduction commands](PLUGIN-HARDENING-2026-10.md).
