import unittest
from aurels_hermes.plugin import AurelsHermesPlugin

class Client:
    def __init__(self, decision=None, error=False): self.decision, self.error, self.events = decision, error, []
    def evaluate(self, request):
        if self.error: raise RuntimeError("offline")
        return self.decision
    def telemetry(self, event): self.events.append(event)

class PluginTests(unittest.TestCase):
    def test_allow(self):
        plugin = AurelsHermesPlugin({"api_key": "test"}, Client({"decision": "allow"}))
        self.assertTrue(plugin.before_action("read_file")["allow"])
    def test_flag_and_block_do_not_execute(self):
        for decision in ("flag", "block"):
            plugin = AurelsHermesPlugin({"api_key": "test"}, Client({"decision": decision}))
            self.assertFalse(plugin.before_action("exec")["allow"])
    def test_failure_is_closed_by_default(self):
        self.assertFalse(AurelsHermesPlugin({"api_key": "test"}, Client(error=True)).before_action("exec")["allow"])
    def test_native_registration_requires_both_hooks(self):
        class Host:
            supported_hooks = {"pre_tool_call", "post_tool_call"}
            def __init__(self): self.hooks = []
            def register_hook(self, name, handler): self.hooks.append(name); return True
        host = Host()
        AurelsHermesPlugin({"api_key": "test"}, Client({"decision": "allow"})).register(host)
        self.assertEqual(host.hooks, ["pre_tool_call", "post_tool_call"])
    def test_missing_native_hooks_fails_startup(self):
        class Host: supported_hooks = {"pre_tool_call"}
        with self.assertRaises(RuntimeError):
            AurelsHermesPlugin({"api_key": "test"}, Client({"decision": "allow"})).register(Host())
    def test_privileged_fail_open_stays_blocked(self):
        self.assertFalse(AurelsHermesPlugin({"api_key": "test", "fail_mode": "open"}, Client(error=True)).before_action("filesystem.writeFile")["allow"])
    def test_malformed_metadata_fails_closed(self):
        self.assertFalse(AurelsHermesPlugin({"api_key": "test"}, Client({"decision": "allow", "riskScore": "bad"})).before_action("exec")["allow"])
    def test_adapter_conformance_only_allow_executes_handler(self):
        for decision, expected_calls in (("allow", 1), ("flag", 0), ("block", 0)):
            calls = []
            plugin = AurelsHermesPlugin({"api_key": "test"}, Client({"decision": decision}))
            preflight = plugin.before_action("send_email")
            if preflight["allow"]: calls.append("executed")
            self.assertEqual(len(calls), expected_calls, decision)
    def test_adapter_conformance_privileged_outage_does_not_execute(self):
        calls = []
        plugin = AurelsHermesPlugin({"api_key": "test", "fail_mode": "open"}, Client(error=True))
        preflight = plugin.before_action("filesystem.writeFile")
        if preflight["allow"]: calls.append("executed")
        self.assertEqual(calls, [])
    def test_local_mode_allows_benign_reads_without_a_key(self):
        plugin = AurelsHermesPlugin({"api_key": "", "telemetry_enabled": False}, Client(error=True))
        self.assertTrue(plugin.before_action("read_file", {"path": "README.md"})["allow"])
    def test_local_mode_blocks_destructive_commands_without_a_key(self):
        plugin = AurelsHermesPlugin({"api_key": "", "telemetry_enabled": False}, Client(error=True))
        self.assertFalse(plugin.before_action("exec", {"command": "rm -rf /"})["allow"])
    def test_local_deterministic_block_takes_priority_over_model_allow(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "telemetry_enabled": False}, client)
        self.assertFalse(plugin.before_action("exec", {"command": "rm -rf /"})["allow"])
    def test_only_ambiguous_action_reaches_model(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "telemetry_enabled": False}, client)
        self.assertTrue(plugin.before_action("send_email")["allow"])
    def test_model_failure_flags_ambiguous_action_even_in_fail_open_mode(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "fail_mode": "open", "telemetry_enabled": False}, Client(error=True))
        result = plugin.before_action("send_email")
        self.assertFalse(result["allow"])
        self.assertIn("approval", result["reason"].lower())
    def test_rejects_non_strict_model_decisions(self):
        for decision in ("rewrite", "quarantine"):
            plugin = AurelsHermesPlugin({"api_key": "test", "telemetry_enabled": False}, Client({"decision": decision}))
            self.assertFalse(plugin.before_action("send_email")["allow"])

if __name__ == "__main__": unittest.main()
