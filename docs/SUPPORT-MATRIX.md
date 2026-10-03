# Support matrix

| Package | Version | Runtime | Status | Security boundary |
| --- | --- | --- | --- | --- |
| Aurels OpenClaw | 0.2.6 | Node 20+, OpenClaw 2026.3.28+ | Supported | Hook-runner contract tested on 2026.3.28 and 2026.9.6; 2026.3.2 explicitly fails closed. One-shot approval freezes the exact evaluated parameters; host-trusted/native paths outside the ordinary approval chain remain outside scope |
| Aurels Hermes | 0.2.6 | Python 3.11+, pinned Hermes native hook host | Supported with constraints | Native refusal tested through real dispatch. Remote native allow is blocked unless hook ordering is explicitly trusted. Application-owned synchronous `run_protected` binds evaluation to its argument snapshot. `retrospective` is advisory only |
| Aurels Ollama | 0.2.6 | Ollama with `qwen3-coder:q3` | Supported | Local analysis only; not an execution hook |

## Self-hosted evaluation

`@aurels/evaluator` 0.1.0 is an experimental Node 22+ service for Jev, Laya, Ollama, and OpenAI-compatible structured-output servers. All eight enforcement adapters are exercised through its real HTTP endpoint using fixture models; the installed archive is also verified. Live model quality and credentials remain unverified. Existing host boundaries below still apply. See the [configuration guide](../plugins/aurels-evaluator/README.md).

## Experimental adapters: validated boundaries

These packages remain experimental and outside the supported marketplace release contract. Validation is stronger than a wrapper-only smoke test, but does not establish universal host compatibility.

| Adapter | Package version | Tested host | Evidence and remaining boundary |
| --- | --- | --- | --- |
| Claude Code | 0.1.0 | Native hook-format command scripts | Packaged pre/post scripts against a synthetic API; full Claude Code sessions and interactions between hooks unverified |
| Codex Guard | 0.1.0 | Portable native hook-format command scripts | Installed archive layout and deny/allow/protocol validation; full Codex sessions and hook trust behavior unverified; approval and rewrite conservatively denied |
| CrewAI | 0.1.0 | CrewAI 1.15.23 | Real `BaseTool.run` and `BaseTool.arun`, including approval/refusal/rewrite/outage; installed wheel tested in CI; unwrapped tools remain outside the boundary |
| LangGraph | 0.1.0 | LangGraph 1.4.18 / core 1.2.13 | Compiled graph runs with synthetic model messages and protected ToolNode; repeated with an installed npm archive; other graph nodes/tools must be protected separately |
| OpenAI Agents | 0.1.0 | Agents SDK 0.18.0 | Real Runner dispatch using synthetic model responses; repeated with an installed npm archive; only wrapped function tools are covered |
| MCP proxy | 0.1.0 | MCP JavaScript SDK 1.32.0 | Real newline stdio initialization/list/call, refusal, rewrite, cancellation, pending cap, and structured errors; repeated with an installed npm archive; only proxied servers/calls are covered |

Hermes CI pins host commit `f97608f178d1ffeca59860195ab7da295f7c8e5f`. Tests use synthetic policy responses and tool handlers; they do not validate live Aurels policy quality, model performance, production credentials, or every host execution path. Ollama packaging is checked, but an actual local model download/inference is not part of this suite. See the [hardening report and reproduction commands](PLUGIN-HARDENING-2026-10.md).
