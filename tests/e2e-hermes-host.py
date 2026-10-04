"""Run the Aurels native hook through a real Hermes host dispatcher.

Set HERMES_SOURCE_DIR to a Hermes Agent checkout and run this script with that
checkout's Python environment. The Aurels API is replaced with a deterministic
fake so this never contacts Aurels or executes a real tool.
"""

import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


repo = Path(__file__).resolve().parents[1]
hermes_source = Path(os.environ.get("HERMES_SOURCE_DIR", ""))
if not (hermes_source / "hermes_cli" / "plugins.py").is_file():
    if os.environ.get("AURELS_SKIP_HERMES_HOST_E2E") == "1":
        print("SKIP Hermes host dispatcher E2E: HERMES_SOURCE_DIR is not configured")
        raise SystemExit(0)
    raise SystemExit("Set HERMES_SOURCE_DIR to a Hermes Agent source checkout or AURELS_SKIP_HERMES_HOST_E2E=1")

sys.path.insert(0, str(repo / "plugins" / "aurels-hermes"))
sys.path.insert(0, str(hermes_source))

from aurels_hermes.plugin import AurelsHermesPlugin  # noqa: E402
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest  # noqa: E402
from run_agent import AIAgent  # noqa: E402
import run_agent as host_run_agent  # noqa: E402

MODERN_HERMES_MODULES = bool(getattr(host_run_agent, "_PLUGIN_COMPAT_LAZY", None))
# Patch the actual tool body, leaving the host's pre/post hooks and outcome
# classifier running. Patching handle_function_call hides post-hook regressions.
DISPATCH_TARGET = "model_tools.registry.dispatch"


class FakeAurelsClient:
    def __init__(self, decision=None, fail=False):
        self.decision = decision
        self.fail = fail
        self.events = []

    def evaluate(self, _action):
        if self.fail:
            raise RuntimeError("synthetic network outage")
        return {"decision": self.decision, "traceId": "synthetic-trace"}

    def telemetry(self, event):
        self.events.append(event)


def make_host_agent():
    tool_defs = [{"type": "function", "function": {"name": "read_file", "description": "test", "parameters": {"type": "object", "properties": {}}}}]
    tool_module = "model_tools" if MODERN_HERMES_MODULES else "run_agent"
    openai_factory = "agent.process_bootstrap.OpenAI" if MODERN_HERMES_MODULES else "run_agent.OpenAI"
    with ExitStack() as stack:
        stack.enter_context(patch(f"{tool_module}.get_tool_definitions", return_value=tool_defs))
        stack.enter_context(patch(f"{tool_module}.check_toolset_requirements", return_value={}))
        stack.enter_context(patch("hermes_cli.config.load_config", return_value={}))
        stack.enter_context(patch(openai_factory))
        agent = AIAgent(api_key="synthetic", base_url="https://unused.invalid", max_iterations=1,
                        quiet_mode=True, skip_context_files=True, skip_memory=True)
    agent.client = MagicMock()
    agent._cached_system_prompt = "test"
    agent._use_prompt_caching = False
    agent.tool_delay = 0
    agent.compression_enabled = False
    agent.save_trajectories = False
    return agent


def run_case(label, config, fake_client, expected_dispatches, expected_outcome=None, tool_result='{"ok":true}'):
    manager = PluginManager()
    manifest = PluginManifest(name="aurels-hermes", version="test", provides_hooks=["pre_tool_call", "post_tool_call"], source="user", key="aurels-hermes")
    plugin = AurelsHermesPlugin(config, fake_client)
    context = PluginContext(manifest, manager)
    # Deliberately advertise a newer version: the real dispatcher below still
    # runs its block-only helper, so version-based approval assumptions must fail closed.
    context.hermes_version = "0.21.5"
    plugin.register(context)
    import hermes_cli.plugins as host_plugins
    previous_manager = host_plugins._plugin_manager
    host_plugins._plugin_manager = manager
    try:
        agent = make_host_agent()
        tool_call = SimpleNamespace(id=f"synthetic-{label}", type="function", function=SimpleNamespace(name="read_file", arguments=json.dumps({"path": "safe.txt"})))
        message = SimpleNamespace(content="", tool_calls=[tool_call])
        messages = []
        with patch(DISPATCH_TARGET, return_value=tool_result) as dispatch:
            agent._execute_tool_calls_sequential(message, messages, f"task-{label}")
        assert dispatch.call_count == expected_dispatches, (label, dispatch.call_count, expected_dispatches, messages)
        if expected_outcome is not None:
            assert len(fake_client.events) == 1, (label, fake_client.events)
            event = fake_client.events[0]
            assert event["outcome"]["status"] == expected_outcome, (label, event)
            assert event["actionId"] == tool_call.id, (label, event)
            assert event["traceId"] == "synthetic-trace", (label, event)
        print(f"PASS {label}: host dispatch count={dispatch.call_count}")
    finally:
        host_plugins._plugin_manager = previous_manager


run_case("local-ambiguous-blocked", {"mode": "local", "api_key": ""}, FakeAurelsClient(), 0)
run_case("remote-flag-version-spoof-blocked", {"mode": "remote", "api_key": "synthetic"}, FakeAurelsClient("flag"), 0)
run_case("remote-outage-blocked", {"mode": "remote", "api_key": "synthetic"}, FakeAurelsClient(fail=True), 0)
run_case("remote-allow-blocked-without-hook-order-trust", {"mode": "remote", "api_key": "synthetic"}, FakeAurelsClient("allow"), 0)
run_case(
    "remote-allow-dispatched-with-explicit-hook-order-trust",
    {"mode": "remote", "api_key": "synthetic", "trust_native_hook_order": True, "telemetry_enabled": True},
    FakeAurelsClient("allow"),
    1,
    "success",
)
run_case("remote-tool-error-telemetry", {"mode": "remote", "api_key": "synthetic", "trust_native_hook_order": True, "telemetry_enabled": True}, FakeAurelsClient("allow"), 1, "failure", '{"error":"synthetic tool error"}')
run_case("retrospective-advisory-dispatched", {"mode": "retrospective", "api_key": ""}, FakeAurelsClient(), 1)
