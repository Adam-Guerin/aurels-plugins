import unittest
from unittest.mock import patch

from aurels_hermes import register
from aurels_hermes.client import AurelsClient
from aurels_hermes.config import Config
from aurels_hermes.plugin import AurelsHermesPlugin
from aurels_hermes.redaction import redact


class Client:
    def __init__(self, decision=None, error=False):
        self.decision = decision
        self.error = error
        self.events = []

    def evaluate(self, request):
        if self.error:
            raise RuntimeError("offline")
        return self.decision

    def telemetry(self, event):
        self.events.append(event)


class PluginTests(unittest.TestCase):
    def test_allow(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": "allow"}))
        self.assertEqual(plugin.before_action("read_file")["action"], "allow")

    def test_flag_and_block_do_not_execute(self):
        for decision in ("flag", "block"):
            plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": decision}))
            self.assertIn(plugin.before_action("exec")["action"], {"approve", "block"})

    def test_failure_is_closed_by_default(self):
        self.assertEqual(
            AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client(error=True)).before_action("exec")["action"],
            "approve",
        )

    def test_register_requires_and_confirms_both_native_hooks(self):
        class Host:
            supported_hooks = {"pre_tool_call", "post_tool_call"}

            def __init__(self):
                self.hooks = []

            def register_hook(self, name, handler):
                self.hooks.append((name, handler))
                return True

        host = Host()
        plugin = register(host)
        self.assertEqual([name for name, _ in host.hooks], ["pre_tool_call", "post_tool_call"])
        self.assertIsInstance(plugin, AurelsHermesPlugin)

    def test_register_fails_when_post_tool_hook_is_not_declared(self):
        class Host:
            supported_hooks = {"pre_tool_call"}

            def register_hook(self, name, handler):
                return True

        with self.assertRaises(RuntimeError):
            AurelsHermesPlugin({"api_key": "", "mode": "local"}, Client()).register(Host())

    def test_pre_tool_callback_accepts_keyword_contract(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": "allow"}))
        result = plugin.pre_tool_call(
            tool_name="read_file",
            args={"path": "README.md"},
            task_id="task-1",
            tool_call_id="call-1",
            session_id="session-1",
            agent_id="agent-1",
        )
        self.assertEqual(result["action"], "allow")

    def test_local_mode_has_no_network_telemetry(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local", "telemetry_enabled": True}, client)
        plugin.before_action("exec", {"command": "rm -rf /"})
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "action-1"}, success=True)
        self.assertEqual(client.events, [])

    def test_disabled_plugin_has_no_post_action_telemetry(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"enabled": False, "api_key": "test", "mode": "remote", "telemetry_enabled": True}, client)
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "action-1"}, success=True)
        self.assertEqual(client.events, [])

    def test_local_mode_blocks_destructive_commands_without_a_key(self):
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local", "telemetry_enabled": False}, Client(error=True))
        self.assertEqual(plugin.before_action("exec", {"command": "rm -rf /"})["action"], "block")

    def test_only_ambiguous_action_reaches_model(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, client)
        self.assertEqual(plugin.before_action("send_email")["action"], "allow")

    def test_model_failure_flags_ambiguous_action(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, Client(error=True))
        result = plugin.before_action("send_email")
        self.assertEqual(result["action"], "approve")
        self.assertIn("approval", result["message"].lower())

    def test_rejects_non_strict_model_decisions(self):
        for decision in ("rewrite", "quarantine"):
            plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, Client({"decision": decision}))
            self.assertEqual(plugin.before_action("send_email")["action"], "approve")

    def test_client_rejects_non_https_api_urls(self):
        with self.assertRaises(ValueError):
            AurelsClient(Config(enabled=True, api_url="http://aurels.test", api_key="secret", mode="remote"))

    def test_client_bounds_remote_response_reads(self):
        class Response:
            status = 200

            def __init__(self):
                self.read_limit = None

            def read(self, size=-1):
                self.read_limit = size
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        response = Response()
        with patch("aurels_hermes.client.urlopen", return_value=response):
            self.assertEqual(AurelsClient(Config(enabled=True, api_url="https://www.aurels.dev", api_key="test", mode="remote")).evaluate({"action": {"id": "a"}}), {})
        self.assertEqual(response.read_limit, 1024 * 1024 + 1)

    def test_trace_cleanup_after_after_action(self):
        client = Client({"decision": "allow", "traceId": "trace-123"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": True}, client)
        plugin.before_action("read_file", {"path": "README.md"}, {"action_id": "trace-cleanup"})
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "trace-cleanup"})
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "trace-cleanup"})
        self.assertEqual(client.events[0]["traceId"], "trace-123")
        self.assertIsNone(client.events[1]["traceId"])

    def test_redacts_sensitive_values_embedded_in_strings(self):
        self.assertEqual(redact("Authorization: Bearer secret-token"), "[REDACTED]")
        self.assertEqual(redact({"command": "token=abc123"})["command"], "[REDACTED]")
        self.assertEqual(redact("safe-value"), "safe-value")


if __name__ == "__main__":
    unittest.main()
