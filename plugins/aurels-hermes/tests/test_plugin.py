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

if __name__ == "__main__": unittest.main()
