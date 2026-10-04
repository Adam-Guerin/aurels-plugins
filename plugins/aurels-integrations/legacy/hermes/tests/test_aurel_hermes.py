import json
import sys
import time
import urllib.error
import unittest
from collections.abc import Mapping
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aurel_hermes.config import load_config
from aurel_hermes.client import AurelClient, AurelActionPayloadError, AurelClientError, AurelProtocolError
from aurel_hermes.plugin import AurelHermesPlugin, normalize_hermes_action


class FakeClient:
    def __init__(self, decisions=None, error=None):
        self.decisions = list(decisions or [{"decision": "allow", "traceId": "trace-default"}])
        self.error = error
        self.actions = []
        self.telemetry = []

    def evaluate_action(self, action):
        if self.error:
            raise self.error
        self.actions.append(action)
        return self.decisions.pop(0) if self.decisions else {"decision": "allow", "traceId": "trace-default"}

    def record_telemetry(self, telemetry):
        self.telemetry.append(telemetry)


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _size):
        return self.body


class ThrowingMapping(Mapping):
    def __iter__(self):
        return iter(["token"])

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise RuntimeError("mapping access should not escape")


class ThrowingIteratorMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("mapping iteration should not escape")

    def __len__(self):
        return 1

    def __getitem__(self, key):
        return "unreachable"


def plugin(decisions=None, error=None, **config):
    cfg = load_config({"api_key": "test-key", "api_url": "https://aurel.test", **config})
    return AurelHermesPlugin(cfg, FakeClient(decisions, error))


class HermesAurelTests(unittest.TestCase):
    def test_normalizes_tool_calls(self):
        action = normalize_hermes_action(
            "terminal",
            {"command": "pwd"},
            "task-1",
            {"session_id": "session-1", "agent_id": "agent-1", "tool_call_id": "call-1", "cwd": "/repo"},
        )
        self.assertEqual(action["integration"], "hermes")
        self.assertEqual(action["action"]["id"], "call-1")
        self.assertEqual(action["agent"]["sessionId"], "session-1")
        self.assertEqual(action["context"]["workingDirectory"], "/repo")

    def test_safe_action_allows(self):
        p = plugin([{"decision": "allow", "traceId": "tr"}])
        self.assertIsNone(p.pre_tool_call("read_file", {"path": "README.md"}, "task-1"))

    def test_fail_open_still_blocks_when_action_cannot_be_evaluated_exactly(self):
        cfg = load_config({"api_key": "test-key", "api_url": "https://aurel.test", "fail_mode": "open"})
        p = AurelHermesPlugin(cfg, AurelClient(cfg))
        result = p.pre_tool_call("read_file", {"content": "x" * (2 * 1024 * 1024)}, "task-large")
        self.assertEqual(result["action"], "block")

    def test_malicious_action_blocks(self):
        p = plugin([{"decision": "block", "reason": "secret rule", "traceId": "tr", "riskScore": 99}])
        result = p.pre_tool_call("terminal", {"command": "rm -rf important-directory", "authorization": "Bearer secret"}, "task-1")
        self.assertEqual(result, {"action": "block", "message": "Aurel blocked this action because it violates the active security policy."})
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["traceId"], "tr")
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "blocked")
        self.assertEqual(p.client.telemetry[0]["metadata"]["riskScore"], 99)
        self.assertEqual(p.client.telemetry[0]["metadata"]["tool"], "terminal")
        self.assertEqual(p.client.telemetry[0]["metadata"]["args"]["authorization"], "[REDACTED]")
        self.assertIsInstance(p.client.telemetry[0]["timings"]["aurelPostflightLatencyMs"], int)

    def test_blocked_action_is_not_reported_twice_if_post_hook_arrives(self):
        p = plugin([{"decision": "block", "traceId": "trace-block-once"}])
        p.pre_tool_call("terminal", {"command": "rm -rf important-directory"}, "task-1", tool_call_id="call-block")
        p.post_tool_call("terminal", {"command": "rm -rf important-directory"}, "unexpected", "task-1", 5, tool_call_id="call-block")
        time.sleep(0.05)
        self.assertEqual(len(p.client.telemetry), 1)
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "blocked")

    def test_suspicious_action_blocks_when_native_approval_is_unavailable(self):
        p = plugin([{"decision": "require_approval", "riskScore": 70, "traceId": "tr"}])
        result = p.pre_tool_call("send_email", {"to": "finance@example.com", "token": "secret"}, "task-1")
        self.assertEqual(result["action"], "block")
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "blocked")
        self.assertEqual(p.client.telemetry[0]["metadata"]["tool"], "send_email")
        self.assertEqual(p.client.telemetry[0]["metadata"]["args"]["token"], "[REDACTED]")
        self.assertIsInstance(p.client.telemetry[0]["timings"]["aurelPostflightLatencyMs"], int)

    def test_suspicious_action_can_use_explicit_native_approval_opt_in(self):
        p = plugin(
            [{"decision": "require_approval", "riskScore": 70, "traceId": "tr"}],
            approval={"native_directive": True},
        )
        result = p.pre_tool_call("send_email", {"to": "finance@example.com", "token": "secret"}, "task-1")
        self.assertEqual(result["action"], "approve")
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "approval_requested")

    def test_rewrite_falls_back_to_block_when_native_approval_is_unavailable(self):
        p = plugin([{"decision": "rewrite", "rewrittenArguments": {"command": "safe"}, "traceId": "tr"}])
        result = p.pre_tool_call("terminal", {"command": "unsafe"}, "task-1")
        self.assertEqual(result["action"], "block")
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "blocked")

    def test_rewrite_can_fall_back_to_native_approval_when_explicitly_enabled(self):
        p = plugin(
            [{"decision": "rewrite", "rewrittenArguments": {"command": "safe"}, "traceId": "tr"}],
            approval={"native_directive": True},
        )
        result = p.pre_tool_call("terminal", {"command": "unsafe"}, "task-1")
        self.assertEqual(result["action"], "approve")
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "approval_requested")

    def test_rewrite_can_fall_back_to_block(self):
        p = plugin(
            [{"decision": "rewrite", "rewrittenArguments": {"command": "safe"}, "traceId": "tr"}],
            rewrite={"unsupported_fallback": "block"},
        )
        result = p.pre_tool_call("terminal", {"command": "unsafe"}, "task-1")
        self.assertEqual(result["action"], "block")

    def test_fail_open_allows_on_aurel_error(self):
        p = plugin(error=RuntimeError("down"), fail_mode="open")
        self.assertIsNone(p.pre_tool_call("read_file", {"path": "README.md"}, "task-1"))

    def test_fail_open_blocks_privileged_actions_on_aurel_error_by_default(self):
        p = plugin(error=RuntimeError("down"), fail_mode="open")
        self.assertEqual(p.pre_tool_call("terminal", {"command": "pwd"}, "task-1"), {"action": "block", "message": "Aurel security verification is unavailable."})

    def test_fail_open_can_explicitly_allow_privileged_actions_on_aurel_error(self):
        p = plugin(error=RuntimeError("down"), fail_mode="open", fail_open_privileged_actions="allow")
        self.assertIsNone(p.pre_tool_call("terminal", {"command": "pwd"}, "task-1"))

    def test_fail_closed_returns_explicit_block_on_aurel_error(self):
        p = plugin(error=RuntimeError("down"), fail_mode="closed")
        self.assertEqual(p.pre_tool_call("terminal", {"command": "pwd"}, "task-1"), {"action": "block", "message": "Aurel security verification is unavailable."})

    def test_timeout_is_fail_closed_explicit_block(self):
        p = plugin(error=TimeoutError("timeout"), fail_mode="closed")
        self.assertEqual(p.pre_tool_call("browser", {"url": "https://example.com"}, "task-1")["action"], "block")

    def test_malformed_decision_blocks(self):
        p = plugin([{"decision": "unknown"}])
        self.assertEqual(p.pre_tool_call("terminal", {"command": "pwd"}, "task-1")["action"], "block")

    def test_concurrent_calls_keep_trace_ids_isolated(self):
        p = plugin([{"decision": "allow", "traceId": "trace-a"}, {"decision": "allow", "traceId": "trace-b"}])
        p.pre_tool_call("read_file", {"path": "a"}, "task-a")
        p.pre_tool_call("read_file", {"path": "b"}, "task-b")
        p.post_tool_call("read_file", {"path": "a"}, "ok", "task-a", 5)
        p.post_tool_call("read_file", {"path": "b"}, "ok", "task-b", 6)
        time.sleep(0.05)
        self.assertEqual(sorted(item["traceId"] for item in p.client.telemetry), ["trace-a", "trace-b"])

    def test_same_task_same_tool_uses_tool_call_id_for_correlation(self):
        p = plugin([{"decision": "allow", "traceId": "trace-a"}, {"decision": "allow", "traceId": "trace-b"}])
        p.pre_tool_call("read_file", {"path": "a"}, "task-1", tool_call_id="call-a")
        p.pre_tool_call("read_file", {"path": "b"}, "task-1", tool_call_id="call-b")
        p.post_tool_call("read_file", {"path": "a"}, "ok", "task-1", 5, tool_call_id="call-a")
        p.post_tool_call("read_file", {"path": "b"}, "ok", "task-1", 6, tool_call_id="call-b")
        time.sleep(0.05)
        self.assertEqual(sorted(item["traceId"] for item in p.client.telemetry), ["trace-a", "trace-b"])

    def test_duplicate_post_tool_call_reports_once(self):
        p = plugin([{"decision": "allow", "traceId": "trace-once"}])
        p.pre_tool_call("read_file", {"path": "a"}, "task-1", tool_call_id="call-1")
        p.post_tool_call("read_file", {"path": "a"}, "ok", "task-1", 5, tool_call_id="call-1")
        p.post_tool_call("read_file", {"path": "a"}, "ok", "task-1", 5, tool_call_id="call-1")
        time.sleep(0.05)
        self.assertEqual(len(p.client.telemetry), 1)
        self.assertEqual(p.client.telemetry[0]["traceId"], "trace-once")

    def test_stale_state_expires_before_late_post_hook(self):
        p = plugin([{"decision": "allow", "traceId": "trace-expired"}], state_ttl_ms=1000)
        with patch("aurel_hermes.plugin._now_ms", side_effect=[1000, 1001, 1002, 1002, 3000, 3000, 3000]):
            p.pre_tool_call("read_file", {"path": "a"}, "task-1", tool_call_id="call-expire")
            p.post_tool_call("read_file", {"path": "a"}, "ok", "task-1", 5, tool_call_id="call-expire")
        time.sleep(0.05)
        self.assertIsNone(p.client.telemetry[0]["traceId"])
        self.assertEqual(p.client.telemetry[0]["actionId"].startswith("hm-act-"), True)

    def test_credentials_are_redacted_from_telemetry(self):
        p = plugin([{"decision": "allow", "traceId": "trace-redact"}])
        args = {"authorization": "Bearer secret", "nested": {"api_key": "sk_live"}, "command": "echo ok"}
        p.pre_tool_call("terminal", args, "task-1")
        self.assertIs(p.client.actions[0]["action"]["arguments"], args)
        p.post_tool_call("terminal", args, "ok", "task-1", 5)
        time.sleep(0.05)
        sent_args = p.client.telemetry[0]["metadata"]["args"]
        self.assertEqual(sent_args["authorization"], "[REDACTED]")
        self.assertEqual(sent_args["nested"]["api_key"], "[REDACTED]")

    def test_redaction_preserves_repeated_non_circular_references(self):
        p = plugin([{"decision": "allow", "traceId": "trace-repeated-telemetry"}])
        shared = {"path": "README.md"}
        args = {"first": shared, "second": shared}
        p.pre_tool_call("read_file", args, "task-1")
        p.post_tool_call("read_file", args, "ok", "task-1", 5)
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["metadata"]["args"], {"first": {"path": "README.md"}, "second": {"path": "README.md"}})

    def test_after_tool_call_telemetry(self):
        p = plugin([{"decision": "allow", "traceId": "trace-post"}])
        p.pre_tool_call("read_file", {"path": "README.md"}, "task-1")
        p.post_tool_call("read_file", {"path": "README.md"}, {"ok": True}, "task-1", 12)
        time.sleep(0.05)
        self.assertEqual(p.client.telemetry[0]["outcome"]["status"], "success")
        self.assertEqual(p.client.telemetry[0]["outcome"]["durationMs"], 12)
        self.assertIsInstance(p.client.telemetry[0]["timings"]["aurelPostflightLatencyMs"], int)

    def test_tools_named_with_aurel_prefix_are_intercepted(self):
        p = plugin([{"decision": "block"}])
        self.assertEqual(p.pre_tool_call("aurel.telemetry", {"payload": True}, "task-1")["action"], "block")
        self.assertEqual(len(p.client.actions), 1)

    def test_environment_enabled_and_tool_filters(self):
        with patch.dict(
            "os.environ",
            {
                "AUREL_ENABLED": "0",
                "AUREL_TOOLS_INCLUDE": "terminal,send_email",
                "AUREL_TOOLS_EXCLUDE": "read_file",
                "AUREL_TELEMETRY_INCLUDE_RESULTS": "true",
                "AUREL_TELEMETRY_MAX_PAYLOAD_BYTES": "1024",
                "AUREL_REDACTION_ENABLED": "false",
            },
        ):
            cfg = load_config({"api_key": "test-key", "api_url": "https://aurel.test"})
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.tools.include, ("terminal", "send_email"))
        self.assertEqual(cfg.tools.exclude, ("read_file",))
        self.assertTrue(cfg.telemetry.include_results)
        self.assertEqual(cfg.telemetry.max_payload_bytes, 1024)
        self.assertFalse(cfg.redaction.enabled)

    def test_explicit_config_overrides_environment_defaults(self):
        with patch.dict(
            "os.environ",
            {
                "AUREL_TOOLS_INCLUDE": "terminal",
                "AUREL_TOOLS_EXCLUDE": "send_email",
                "AUREL_TELEMETRY_INCLUDE_RESULTS": "true",
                "AUREL_HERMES_NATIVE_APPROVAL": "true",
            },
        ):
            cfg = load_config(
                {
                    "api_key": "test-key",
                    "api_url": "https://aurel.test",
                    "tools": {"include": [], "exclude": []},
                    "telemetry": {"include_results": False},
                    "approval": {"native_directive": False},
                }
            )
        self.assertEqual(cfg.tools.include, ())
        self.assertEqual(cfg.tools.exclude, ())
        self.assertFalse(cfg.telemetry.include_results)
        self.assertFalse(cfg.approval.native_directive)

    def test_invalid_log_level_environment_uses_warning_default(self):
        with patch.dict("os.environ", {"AUREL_LOG_LEVEL": "verbose"}):
            cfg = load_config({"api_key": "test-key", "api_url": "https://aurel.test"})
        self.assertEqual(cfg.log_level, "warning")

    def test_rewrite_fallback_environment_can_select_block(self):
        with patch.dict("os.environ", {"AUREL_REWRITE_UNSUPPORTED_FALLBACK": "block"}):
            cfg = load_config({"api_key": "test-key", "api_url": "https://aurel.test"})
        self.assertEqual(cfg.rewrite.unsupported_fallback, "block")

    def test_does_not_upload_full_results_by_default(self):
        p = plugin([{"decision": "allow", "traceId": "trace"}])
        p.pre_tool_call("read_file", {"path": "README.md"}, "task-1")
        p.post_tool_call("read_file", {"path": "README.md"}, "very large output", "task-1", 1)
        time.sleep(0.05)
        self.assertNotIn("result", p.client.telemetry[0]["metadata"])

    def test_client_strips_query_and_fragment_from_base_url(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.full_url)
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test/base?token=secret#fragment"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            self.assertEqual(client.evaluate_action({"version": "1", "action": {"id": "a", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})["decision"], "allow")
        self.assertEqual(seen[0], "https://aurel.test/base/api/v1/actions/evaluate")

    def test_client_rejects_oversized_aurel_response(self):
        def fake_urlopen(request, timeout):
            return FakeResponse(b"x" * (1024 * 1024 + 1))

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaises(AurelProtocolError):
                client.evaluate_action({"version": "1", "action": {"id": "a", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})

    def test_client_rejects_malformed_decision_metadata(self):
        def fake_urlopen(request, timeout):
            return FakeResponse(b'{"decision":"allow","riskScore":500,"ruleIds":"not-an-array"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaises(AurelProtocolError):
                client.evaluate_action({"version": "1", "action": {"id": "a", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})

    def test_client_rejects_non_finite_risk_score(self):
        def fake_urlopen(request, timeout):
            return FakeResponse(b'{"decision":"allow","riskScore":NaN}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaises(AurelProtocolError):
                client.evaluate_action({"version": "1", "action": {"id": "a", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})

    def test_client_sends_idempotency_keys(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append((request.full_url, request.get_header("Idempotency-key")))
            return FakeResponse(b'{"decision":"allow"}' if request.full_url.endswith("/evaluate") else b'{"accepted":true}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            client.evaluate_action({"version": "1", "action": {"id": "call/1", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})
            telemetry = {"version": "1", "actionId": "call/1", "outcome": {"status": "success"}, "metadata": {"path": "one.txt"}, "timestamp": "now"}
            client.record_telemetry(telemetry)
            client.record_telemetry(telemetry)
            client.record_telemetry({**telemetry, "metadata": {"path": "two.txt"}})

        self.assertEqual(seen[0][0], "https://aurel.test/api/v1/actions/evaluate")
        self.assertRegex(seen[0][1], r"^action-evaluate:call%2F1:[a-f0-9]{64}$")
        self.assertEqual(seen[1][0], "https://aurel.test/api/v1/actions/telemetry")
        self.assertRegex(seen[1][1], r"^action-telemetry:call%2F1:success:[a-f0-9]{64}$")
        self.assertEqual(seen[1][1], seen[2][1])
        self.assertNotEqual(seen[1][1], seen[3][1])

    def test_client_binds_evaluation_idempotency_key_to_action_arguments(self):
        seen = []

        def fake_open(request, timeout):
            seen.append(request.get_header("Idempotency-key"))
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_open):
            for command in ("echo safe", "rm -rf important-directory"):
                client.evaluate_action({"version": "1", "action": {"id": "reused-call", "name": "terminal", "arguments": {"command": command}}, "agent": {}, "timestamp": "now"})
        self.assertNotEqual(seen[0], seen[1])

    def test_client_rejects_redirects_without_following_them(self):
        class RedirectingOpener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append(request)
                raise urllib.error.HTTPError(request.full_url, 303, "See Other", {}, None)

        opener = RedirectingOpener()
        client = AurelClient(load_config({"api_key": "test-key", "api_url": "https://aurel.test"}))
        with patch("urllib.request.build_opener", return_value=opener) as build_opener:
            with self.assertRaises(AurelClientError):
                client.evaluate_action({"version": "1", "action": {"id": "redirect", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].get_header("X-api-key"), "test-key")
        self.assertEqual(build_opener.call_count, 1)

    def test_client_rejects_circular_action_arguments_before_policy_request(self):
        seen = []
        args = {"command": "pwd"}
        args["self"] = args

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaisesRegex(AurelProtocolError, "losslessly JSON-serializable"):
                client.evaluate_action({"version": "1", "action": {"id": "call-circular", "name": "terminal", "arguments": args}, "agent": {}, "timestamp": "now"})

        self.assertIs(args["self"], args)
        self.assertEqual(seen, [])

    def test_client_preserves_repeated_non_circular_action_references(self):
        seen = []
        shared = {"path": "README.md"}

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            client.evaluate_action(
                {
                    "version": "1",
                    "action": {"id": "call-repeated-ref", "name": "read_file", "arguments": {"first": shared, "second": shared}},
                    "agent": {},
                    "timestamp": "now",
                }
            )

        self.assertEqual(json.loads(seen[0])["action"]["arguments"], {"first": {"path": "README.md"}, "second": {"path": "README.md"}})

    def test_client_rejects_throwing_mappings_before_policy_request(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaisesRegex(AurelProtocolError, "losslessly JSON-serializable"):
                client.evaluate_action(
                    {
                        "version": "1",
                        "action": {"id": "call-throwing-mapping", "name": "terminal", "arguments": ThrowingMapping()},
                        "agent": {},
                        "timestamp": "now",
                    }
                )

        self.assertEqual(seen, [])

    def test_client_rejects_throwing_mapping_iteration_before_policy_request(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaisesRegex(AurelProtocolError, "losslessly JSON-serializable"):
                client.evaluate_action(
                    {
                        "version": "1",
                        "action": {"id": "call-throwing-iteration", "name": "terminal", "arguments": ThrowingIteratorMapping()},
                        "agent": {},
                        "timestamp": "now",
                    }
                )

        self.assertEqual(seen, [])

    def test_client_rejects_oversized_action_arguments_before_policy_request(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.data)
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaisesRegex(AurelProtocolError, "exact arguments were not evaluated"):
                client.evaluate_action(
                    {
                        "version": "1",
                        "action": {"id": "call-large", "name": "terminal", "arguments": {"command": "x" * (2 * 1024 * 1024)}},
                        "agent": {},
                        "timestamp": "now",
                    }
                )

        self.assertEqual(seen, [])

    def test_client_bounds_total_preflight_request_size_preserving_action_envelope(self):
        seen = []
        many_large_fields = {f"field_{index}": "x" * 65536 for index in range(64)}

        def fake_urlopen(request, timeout):
            seen.append(request.data)
            return FakeResponse(b'{"decision":"allow"}')

        client = AurelClient(load_config({"api_key": "test", "api_url": "https://aurel.test"}))
        with patch("aurel_hermes.client._open_no_redirect", fake_urlopen):
            with self.assertRaisesRegex(AurelProtocolError, "exact arguments were not evaluated"):
                client.evaluate_action(
                    {
                        "version": "1",
                        "action": {"id": "call-total-bound", "name": "terminal", "arguments": many_large_fields},
                        "agent": {"id": "agent-1"},
                        "timestamp": "now",
                    }
                )

        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
