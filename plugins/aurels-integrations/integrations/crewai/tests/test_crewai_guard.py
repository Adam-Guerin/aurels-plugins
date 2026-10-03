import os
import asyncio
import json
import io
from contextlib import redirect_stdout
import sys
import unittest
from collections.abc import Mapping
from unittest.mock import patch
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aurel_crewai.guard import AurelCrewAIGuard, AurelCrewAIConfig, AurelToolBlockedError, protect_tool
from aurel_crewai.redaction import redact


class _FakeOpener:
    def __init__(self, open_fn):
        self._open_fn = open_fn

    def open(self, request, timeout):
        return self._open_fn(request, timeout)


class FakeGuard(AurelCrewAIGuard):
    def __init__(self, decisions):
        super().__init__(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        self.decisions = list(decisions)
        self.telemetry = []

    def _post_json(self, path, payload):
        if path.endswith("telemetry"):
            self.telemetry.append(payload)
            return {"accepted": True}
        return self.decisions.pop(0)


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


class CrewAITests(unittest.TestCase):
    def test_failure_logs_do_not_expose_raw_transport_errors(self):
        class FailingGuard(AurelCrewAIGuard):
            def _post_json(self, path, payload):
                raise RuntimeError("synthetic-secret-in-upstream-error")
        guard = FailingGuard(AurelCrewAIConfig(api_url="https://unused.invalid", api_key="synthetic", fail_mode="open", telemetry_async=False))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(guard.run_protected(tool_name="read_fixture", args={}, execute=lambda _: "ok"), "ok")
            guard._send_telemetry({})
        self.assertNotIn("synthetic-secret", output.getvalue())
        self.assertIn("RuntimeError", output.getvalue())

    def test_mixed_positional_and_keyword_calls_preserve_all_arguments(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                guard = FakeGuard([{"decision": "allow"}])
                seen = []
                def tool(path, *, mode):
                    seen.append((path, mode))
                    return path
                async def async_tool(path, *, mode):
                    return tool(path, mode=mode)
                protected = protect_tool(async_tool if asynchronous else tool, guard)
                result = protected("fixture.txt", mode="read")
                if asynchronous:
                    result = asyncio.run(result)
                self.assertEqual(result, "fixture.txt")
                self.assertEqual(seen, [("fixture.txt", "read")])
                self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"args": ["fixture.txt"], "kwargs": {"mode": "read"}})

    def test_mixed_call_rewrite_requires_the_complete_invocation(self):
        seen = []
        def tool(path, *, mode):
            seen.append((path, mode))
            return path
        guard = FakeGuard([{"decision": "rewrite", "rewrittenArguments": {"args": ["safe.txt"], "kwargs": {"mode": "read"}}}])
        self.assertEqual(protect_tool(tool, guard)("original.txt", mode="write"), "safe.txt")
        self.assertEqual(seen, [("safe.txt", "read")])
        guard = FakeGuard([{"decision": "rewrite", "rewrittenArguments": {"mode": "read"}}])
        with self.assertRaises(AurelToolBlockedError):
            protect_tool(tool, guard)("must-not-run.txt", mode="write")
        self.assertEqual(len(seen), 1)

    def test_async_callable_failure_is_reported_only_after_the_tool_finishes(self):
        guard = FakeGuard([{"decision": "allow"}])

        async def read_file(path):
            raise FileNotFoundError("synthetic async error")

        protected = protect_tool(read_file, guard)
        with self.assertRaises(FileNotFoundError):
            asyncio.run(protected(path="fixture.txt"))
        self.assertEqual([event["outcome"]["status"] for event in guard.telemetry], ["failure"])

    def test_telemetry_thread_failure_never_changes_successful_tool_execution(self):
        guard = FakeGuard([{"decision": "allow"}])
        guard.config = AurelCrewAIConfig(telemetry_async=True)
        with patch("threading.Thread.start", side_effect=RuntimeError("synthetic thread failure")):
            result = guard.run_protected(tool_name="read_file", args={}, execute=lambda _: "read:fixture")
        self.assertEqual(result, "read:fixture")

    def test_unreadable_policy_json_cannot_authorize_fail_open_dispatch(self):
        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://unused.invalid", api_key="synthetic", fail_mode="open", telemetry_enabled=False))
        executed = []
        with patch("urllib.request.build_opener", return_value=_FakeOpener(lambda *_args, **_kwargs: FakeResponse(b"invalid JSON"))):
            with self.assertRaises(AurelToolBlockedError):
                guard.run_protected(tool_name="read_file", args={}, execute=executed.append)
        self.assertEqual(executed, [])

    def test_invalid_protocol_cannot_use_fail_open_to_authorize_dispatch(self):
        for decision in [{"decision": "unknown"}, {"decision": "allow", "riskScore": True}, {"decision": "rewrite"}]:
            with self.subTest(decision=decision):
                guard = FakeGuard([decision])
                guard.config = AurelCrewAIConfig(fail_mode="open", telemetry_enabled=False)
                executed = []
                with self.assertRaises(AurelToolBlockedError):
                    guard.run_protected(tool_name="read_file", args={}, execute=executed.append)
                self.assertEqual(executed, [])

    def test_approval_callback_cannot_replace_the_evaluated_arguments(self):
        def approve(action, decision):
            action["action"]["arguments"]["command"] = "rm -rf /synthetic"
            return True

        guard = FakeGuard([{"decision": "require_approval"}])
        guard.config = AurelCrewAIConfig(approval_handler=approve, telemetry_enabled=False)
        executed = []
        guard.run_protected(tool_name="read_file", args={"command": "echo safe"}, execute=executed.append)
        self.assertEqual(executed, [{"command": "echo safe"}])

    def test_approval_requires_literal_true_instead_of_a_truthy_string(self):
        guard = FakeGuard([{"decision": "require_approval"}])
        guard.config = AurelCrewAIConfig(approval_handler=lambda *_: "denied", telemetry_enabled=False)
        executed = []
        with self.assertRaises(AurelToolBlockedError):
            guard.run_protected(tool_name="read_file", args={}, execute=executed.append)
        self.assertEqual(executed, [])

    def test_python_redaction_passes_the_cross_language_credential_corpus(self):
        corpus_path = ROOT.parent.parent / "tests" / "fixtures" / "redaction-corpus.json"
        for item in json.loads(corpus_path.read_text(encoding="utf-8")):
            self.assertNotIn(item["secret"], json.dumps(redact({"message": item["input"]})), item["name"])

    def test_executes_the_same_argument_snapshot_that_was_evaluated(self):
        entered_policy = Event()
        release_policy = Event()
        observed = {}

        class DelayedGuard(FakeGuard):
            def _post_json(self, path, payload):
                if path.endswith("telemetry"):
                    self.telemetry.append(payload)
                    return {"accepted": True}
                observed["evaluated"] = json.loads(json.dumps(payload["action"]["arguments"]))
                entered_policy.set()
                if not release_policy.wait(2):
                    raise TimeoutError("synthetic policy wait timed out")
                return {"decision": "allow", "traceId": "delayed"}

        guard = DelayedGuard([])
        args = {"command": "echo safe"}

        def execute(arguments):
            observed["executed"] = arguments
            return "done"

        result = []
        worker = Thread(target=lambda: result.append(guard.run_protected(tool_name="task", args=args, execute=execute)))
        worker.start()
        self.assertTrue(entered_policy.wait(2), "policy evaluation should be in flight before caller mutates arguments")
        args["command"] = "rm -rf /synthetic"
        release_policy.set()
        worker.join(2)

        self.assertFalse(worker.is_alive(), "the protected call should finish after policy returns")
        self.assertEqual(result, ["done"])
        self.assertEqual(observed["evaluated"], {"command": "echo safe"})
        self.assertEqual(observed["executed"], observed["evaluated"])

    def test_allows_callable(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        tool = protect_tool(lambda command: f"ran {command}", guard, name="terminal")
        self.assertEqual(tool("pwd"), "ran pwd")
        self.assertEqual(guard.telemetry[0]["outcome"]["status"], "success")

    def test_preserves_single_mapping_positional_callable_arguments(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        seen = []

        def structured_tool(payload):
            seen.append(payload)
            return payload["path"]

        tool = protect_tool(structured_tool, guard, name="read_file")
        self.assertEqual(tool({"path": "README.md"}), "README.md")
        self.assertEqual(seen, [{"path": "README.md"}])
        self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"path": "README.md"})

    def test_preserves_single_mapping_positional_basetool_arguments(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        seen = []

        class StructuredTool:
            name = "read_file"

            def _run(self, payload):
                seen.append(payload)
                return payload["path"]

        tool = protect_tool(StructuredTool(), guard)
        self.assertEqual(tool._run({"path": "README.md"}), "README.md")
        self.assertEqual(seen, [{"path": "README.md"}])
        self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"path": "README.md"})

    def test_blocks_before_execution(self):
        guard = FakeGuard([{"decision": "block", "traceId": "t", "riskScore": 95}])
        executed = False

        def dangerous(command):
            nonlocal executed
            executed = True
            return command

        tool = protect_tool(dangerous, guard, name="terminal")
        with self.assertRaises(AurelToolBlockedError):
            tool("rm -rf important-directory")
        self.assertFalse(executed)
        self.assertEqual(guard.telemetry[0]["outcome"]["status"], "blocked")
        self.assertEqual(guard.telemetry[0]["metadata"]["decision"], "block")
        self.assertEqual(guard.telemetry[0]["metadata"]["riskScore"], 95)

    def test_fail_open_still_blocks_when_action_cannot_be_evaluated_exactly(self):
        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", fail_mode="open", telemetry_async=False))
        executed = []
        with self.assertRaises(AurelToolBlockedError):
            guard.run_protected(tool_name="read_file", args={"content": "x" * (2 * 1024 * 1024)}, execute=lambda args: executed.append(args))
        self.assertEqual(executed, [])

    def test_approval_required_reports_approval_requested_before_execution(self):
        guard = FakeGuard([{"decision": "require_approval", "traceId": "t", "riskScore": 72}])
        executed = False

        def send_email(to, token):
            nonlocal executed
            executed = True
            return to

        tool = protect_tool(send_email, guard, name="send_email")
        with self.assertRaises(AurelToolBlockedError):
            tool(to="finance@example.com", token="secret")
        self.assertFalse(executed)
        self.assertEqual(guard.telemetry[0]["outcome"]["status"], "approval_requested")
        self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"to": "finance@example.com", "token": "[REDACTED]"})
        self.assertEqual(guard.telemetry[0]["metadata"]["decision"], "require_approval")
        self.assertEqual(guard.telemetry[0]["metadata"]["riskScore"], 72)
        self.assertIsInstance(guard.telemetry[0]["timings"]["aurelPostflightLatencyMs"], int)

    def test_approval_handler_can_allow_execution(self):
        guard = FakeGuard([{"decision": "require_approval", "traceId": "t", "riskScore": 72}])
        guard.config = AurelCrewAIConfig(
            api_url="https://aurel.test",
            api_key="test",
            telemetry_async=False,
            approval_handler=lambda action, decision: action["action"]["name"] == "send_email" and decision["riskScore"] == 72,
        )

        tool = protect_tool(lambda to: f"sent {to}", guard, name="send_email")
        self.assertEqual(tool(to="finance@example.com"), "sent finance@example.com")
        self.assertEqual([entry["outcome"]["status"] for entry in guard.telemetry], ["approval_requested", "approval_allowed", "success"])

    def test_approval_handler_denial_blocks_before_execution(self):
        guard = FakeGuard([{"decision": "require_approval", "traceId": "t", "riskScore": 72}])
        guard.config = AurelCrewAIConfig(
            api_url="https://aurel.test",
            api_key="test",
            telemetry_async=False,
            approval_handler=lambda _action, _decision: False,
        )
        executed = False

        def send_email(to):
            nonlocal executed
            executed = True
            return to

        tool = protect_tool(send_email, guard, name="send_email")
        with self.assertRaises(AurelToolBlockedError):
            tool(to="finance@example.com")
        self.assertFalse(executed)
        self.assertEqual([entry["outcome"]["status"] for entry in guard.telemetry], ["approval_requested", "approval_denied"])

    def test_legacy_flag_decision_requires_approval(self):
        guard = FakeGuard([{"decision": "flag", "traceId": "t", "riskScore": 64}])
        tool = protect_tool(lambda to: to, guard, name="send_email")
        with self.assertRaises(AurelToolBlockedError):
            tool(to="finance@example.com")
        self.assertEqual(guard.telemetry[0]["outcome"]["status"], "approval_requested")
        self.assertEqual(guard.telemetry[0]["metadata"]["decision"], "require_approval")

    def test_rewrites_arguments(self):
        guard = FakeGuard([{"decision": "rewrite", "rewrittenArguments": {"command": "pwd"}, "traceId": "t"}])
        tool = protect_tool(lambda command: command, guard, name="terminal")
        self.assertEqual(tool("rewrite-me"), "pwd")
        self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"command": "pwd"})
        self.assertEqual(guard.telemetry[0]["metadata"]["originalArgs"], "rewrite-me")
        self.assertTrue(guard.telemetry[0]["metadata"]["rewriteApplied"])
        self.assertIsInstance(guard.telemetry[0]["timings"]["aurelPostflightLatencyMs"], int)

    def test_strips_query_and_fragment_from_aurel_url(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.full_url)
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test/base?token=secret#fragment", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            self.assertEqual(guard._post_json("/api/v1/actions/evaluate", {"ok": True})["decision"], "allow")
        self.assertEqual(seen[0], "https://aurel.test/base/api/v1/actions/evaluate")

    def test_client_rejects_redirect_without_forwarding_api_key(self):
        received_keys = []

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                received_keys.append(self.headers.get("X-Api-Key"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"decision":"allow"}')

            def log_message(self, *_args):
                pass

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()
        target = f"http://127.0.0.1:{destination.server_port}/collect"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(303)
                self.send_header("Location", target)
                self.end_headers()

            def log_message(self, *_args):
                pass

        redirector = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirector_thread = Thread(target=redirector.serve_forever, daemon=True)
        redirector_thread.start()
        try:
            guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url=f"http://127.0.0.1:{redirector.server_port}", api_key="synthetic-redirect-secret", telemetry_async=False))
            with self.assertRaisesRegex(RuntimeError, "Aurel HTTP 303"):
                guard._post_json("/api/v1/actions/evaluate", {"action": {"id": "redirect", "arguments": {}}})
            self.assertEqual(received_keys, [])
        finally:
            redirector.shutdown()
            redirector.server_close()
            redirector_thread.join(timeout=2)
            destination.shutdown()
            destination.server_close()
            destination_thread.join(timeout=2)

    def test_sends_idempotency_keys(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append((request.full_url, request.get_header("Idempotency-key")))
            return FakeResponse(b'{"decision":"allow"}' if request.full_url.endswith("/evaluate") else b'{"accepted":true}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            guard._post_json("/api/v1/actions/evaluate", {"version": "1", "action": {"id": "call/1", "name": "read", "arguments": {}}, "agent": {}, "timestamp": "now"})
            telemetry = {"version": "1", "actionId": "call/1", "outcome": {"status": "success"}, "metadata": {"path": "first.txt"}, "timestamp": "now"}
            guard._post_json("/api/v1/actions/telemetry", telemetry)
            guard._post_json("/api/v1/actions/telemetry", telemetry)
            guard._post_json("/api/v1/actions/telemetry", {**telemetry, "metadata": {"path": "second.txt"}})

        self.assertEqual(len(seen), 4)
        self.assertTrue(seen[0][1].startswith("action-evaluate:call%2F1:"))
        self.assertTrue(seen[1][1].startswith("action-telemetry:call%2F1:success:"))
        self.assertEqual(seen[1][1], seen[2][1])
        self.assertNotEqual(seen[1][1], seen[3][1])

    def test_rejects_circular_action_arguments_before_policy_request(self):
        seen = []
        args = {"command": "pwd"}
        args["self"] = args

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            with self.assertRaisesRegex(RuntimeError, "losslessly JSON-serializable"):
                guard._post_json("/api/v1/actions/evaluate", {"version": "1", "action": {"id": "call-circular", "name": "terminal", "arguments": args}, "agent": {}, "timestamp": "now"})

        self.assertIs(args["self"], args)
        self.assertEqual(seen, [])

    def test_preserves_repeated_non_circular_action_references(self):
        seen = []
        shared = {"path": "README.md"}

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            guard._post_json(
                "/api/v1/actions/evaluate",
                {
                    "version": "1",
                    "action": {"id": "call-repeated-ref", "name": "read_file", "arguments": {"first": shared, "second": shared}},
                    "agent": {},
                    "timestamp": "now",
                },
            )

        self.assertEqual(json.loads(seen[0])["action"]["arguments"], {"first": {"path": "README.md"}, "second": {"path": "README.md"}})

    def test_rejects_throwing_mappings_before_policy_request(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            with self.assertRaisesRegex(RuntimeError, "losslessly JSON-serializable"):
                guard._post_json(
                    "/api/v1/actions/evaluate",
                    {"version": "1", "action": {"id": "call-throwing-mapping", "name": "terminal", "arguments": ThrowingMapping()}, "agent": {}, "timestamp": "now"},
                )

        self.assertEqual(seen, [])

    def test_rejects_throwing_mapping_iteration_before_policy_request(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.data.decode("utf-8"))
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            with self.assertRaisesRegex(RuntimeError, "losslessly JSON-serializable"):
                guard._post_json(
                    "/api/v1/actions/evaluate",
                    {"version": "1", "action": {"id": "call-throwing-iteration", "name": "terminal", "arguments": ThrowingIteratorMapping()}, "agent": {}, "timestamp": "now"},
                )

        self.assertEqual(seen, [])

    def test_rejects_oversized_action_arguments_before_policy_request(self):
        seen = []

        def fake_urlopen(request, timeout):
            seen.append(request.data)
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            with self.assertRaisesRegex(RuntimeError, "exact arguments were not evaluated"):
                guard._post_json(
                    "/api/v1/actions/evaluate",
                    {"version": "1", "action": {"id": "call-large", "name": "terminal", "arguments": {"command": "x" * (2 * 1024 * 1024)}}, "agent": {}, "timestamp": "now"},
                )

        self.assertEqual(seen, [])

    def test_bounds_total_preflight_request_size_preserving_action_envelope(self):
        seen = []
        many_large_fields = {f"field_{index}": "x" * 65536 for index in range(64)}

        def fake_urlopen(request, timeout):
            seen.append(request.data)
            return FakeResponse(b'{"decision":"allow"}')

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            with self.assertRaisesRegex(RuntimeError, "exact arguments were not evaluated"):
                guard._post_json(
                    "/api/v1/actions/evaluate",
                    {"version": "1", "action": {"id": "call-total-bound", "name": "terminal", "arguments": many_large_fields}, "agent": {"id": "agent-1"}, "timestamp": "now"},
                )

        self.assertEqual(seen, [])

    def test_rejects_oversized_aurel_response(self):
        def fake_urlopen(request, timeout):
            return FakeResponse(b"x" * (1024 * 1024 + 1))

        guard = AurelCrewAIGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", telemetry_async=False))
        with patch("urllib.request.build_opener", return_value=_FakeOpener(fake_urlopen)):
            with self.assertRaises(RuntimeError):
                guard._post_json("/api/v1/actions/evaluate", {"ok": True})

    def test_aurel_prefixed_tool_names_are_not_trusted_as_internal(self):
        guard = FakeGuard([{"decision": "block", "traceId": "t"}])
        tool = protect_tool(lambda event: f"sent {event}", guard, name="aurel.exec")
        with self.assertRaises(AurelToolBlockedError):
            tool(event="rm -rf /")
        self.assertEqual(len(guard.decisions), 0)
        self.assertEqual(guard.telemetry[0]["outcome"]["status"], "blocked")

    def test_disabled_guard_skips_aurel(self):
        guard = FakeGuard([{"decision": "block", "traceId": "t"}])
        guard.config = AurelCrewAIConfig(api_url="https://aurel.test", api_key="", enabled=False, telemetry_async=False)
        tool = protect_tool(lambda command: f"ran {command}", guard, name="terminal")
        self.assertEqual(tool("pwd"), "ran pwd")
        self.assertEqual(len(guard.decisions), 1)
        self.assertEqual(guard.telemetry, [])

    def test_legacy_tool_exclude_does_not_bypass_aurel(self):
        guard = FakeGuard([{"decision": "block", "traceId": "t"}])
        guard.config = AurelCrewAIConfig(api_url="https://aurel.test", api_key="", tools_exclude=("terminal",), telemetry_async=False)
        executed = False

        def terminal(command):
            nonlocal executed
            executed = True
            return command

        tool = protect_tool(terminal, guard, name="terminal")
        with self.assertRaises(AurelToolBlockedError):
            tool("rm -rf /synthetic")
        self.assertFalse(executed)
        self.assertEqual(len(guard.decisions), 0)
        self.assertEqual(guard.telemetry[0]["outcome"]["status"], "blocked")

    def test_tool_include_limits_interception(self):
        guard = FakeGuard([{"decision": "block", "traceId": "t"}])
        guard.config = AurelCrewAIConfig(api_url="https://aurel.test", api_key="", tools_include=("send_email",), telemetry_async=False)
        tool = protect_tool(lambda command: f"ran {command}", guard, name="terminal")
        self.assertEqual(tool("pwd"), "ran pwd")
        self.assertEqual(len(guard.decisions), 1)
        self.assertEqual(guard.telemetry, [])

    def test_redacts_arguments_in_telemetry(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        tool = protect_tool(lambda authorization: "ok", guard, name="terminal")
        self.assertEqual(tool(authorization="Bearer secret"), "ok")
        self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"authorization": "[REDACTED]"})
        self.assertFalse(guard.telemetry[0]["metadata"]["resultIncluded"])

    def test_redacts_common_credentials_embedded_in_ordinary_argument_text(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        tool = protect_tool(lambda message: "ok", guard, name="summarize")
        corpus_path = ROOT.parent.parent / "tests" / "fixtures" / "redaction-corpus.json"
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        tool(message=" | ".join(item["input"] for item in corpus))
        serialized = json.dumps(guard.telemetry[0]["metadata"]["args"])
        for item in corpus:
            self.assertNotIn(item["secret"], serialized, item["name"])

    def test_preserves_repeated_non_circular_references_in_telemetry_redaction(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        shared = {"path": "README.md"}
        tool = protect_tool(lambda **kwargs: kwargs, guard, name="read_file")
        self.assertEqual(tool(first=shared, second=shared), {"first": shared, "second": shared})
        self.assertEqual(guard.telemetry[0]["metadata"]["args"], {"first": {"path": "README.md"}, "second": {"path": "README.md"}})

    def test_can_include_redacted_results_when_configured(self):
        guard = FakeGuard([{"decision": "allow", "traceId": "t"}])
        guard.config = AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", include_results=True, telemetry_async=False)
        tool = protect_tool(lambda command: {"token": "secret", "ok": command}, guard, name="terminal")
        self.assertEqual(tool(command="pwd"), {"token": "secret", "ok": "pwd"})
        self.assertTrue(guard.telemetry[0]["metadata"]["resultIncluded"])
        self.assertEqual(guard.telemetry[0]["metadata"]["result"], {"token": "[REDACTED]", "ok": "pwd"})

    def test_malformed_decision_fails_closed_before_execution(self):
        guard = FakeGuard([{"notDecision": True}])
        executed = False

        def dangerous(command):
            nonlocal executed
            executed = True
            return command

        tool = protect_tool(dangerous, guard, name="terminal")
        with self.assertRaises(AurelToolBlockedError):
            tool(command="pwd")
        self.assertFalse(executed)

    def test_fail_open_blocks_privileged_actions_on_aurel_error_by_default(self):
        class FailingGuard(AurelCrewAIGuard):
            def _post_json(self, path, payload):
                raise RuntimeError("down")

        guard = FailingGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", fail_mode="open", telemetry_async=False))
        executed = False

        def terminal(command):
            nonlocal executed
            executed = True
            return command

        tool = protect_tool(terminal, guard, name="terminal")
        with self.assertRaises(AurelToolBlockedError):
            tool(command="pwd")
        self.assertFalse(executed)

    def test_fail_open_allows_low_risk_actions_on_aurel_error(self):
        class FailingGuard(AurelCrewAIGuard):
            def _post_json(self, path, payload):
                raise RuntimeError("down")

        guard = FailingGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", fail_mode="open", telemetry_async=False))
        tool = protect_tool(lambda path: path, guard, name="read_file")
        self.assertEqual(tool(path="README.md"), "README.md")

    def test_fail_open_blocks_destructive_arguments_even_with_benign_tool_name(self):
        class FailingGuard(AurelCrewAIGuard):
            def _post_json(self, path, payload):
                raise RuntimeError("down")

        guard = FailingGuard(AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", fail_mode="open", telemetry_async=False))
        executed = False

        def opaque_tool(payload):
            nonlocal executed
            executed = True
            return payload

        tool = protect_tool(opaque_tool, guard, name="task")
        with self.assertRaises(AurelToolBlockedError):
            tool(payload={"command": "rm -rf /important"})
        self.assertFalse(executed)

    def test_fail_open_can_explicitly_allow_privileged_actions_on_aurel_error(self):
        class FailingGuard(AurelCrewAIGuard):
            def _post_json(self, path, payload):
                raise RuntimeError("down")

        guard = FailingGuard(
            AurelCrewAIConfig(api_url="https://aurel.test", api_key="test", fail_mode="open", fail_open_privileged_actions="allow", telemetry_async=False)
        )
        tool = protect_tool(lambda command: command, guard, name="terminal")
        self.assertEqual(tool(command="pwd"), "pwd")

    def test_malformed_decision_metadata_fails_closed_before_execution(self):
        guard = FakeGuard([{"decision": "allow", "riskScore": 500, "ruleIds": "not-an-array"}])
        executed = False

        def dangerous(command):
            nonlocal executed
            executed = True
            return command

        tool = protect_tool(dangerous, guard, name="terminal")
        with self.assertRaises(AurelToolBlockedError):
            tool(command="pwd")
        self.assertFalse(executed)

    def test_non_finite_risk_score_fails_closed_before_execution(self):
        guard = FakeGuard([{"decision": "allow", "riskScore": float("nan")}])
        executed = False

        def dangerous(command):
            nonlocal executed
            executed = True
            return command

        tool = protect_tool(dangerous, guard, name="terminal")
        with self.assertRaises(AurelToolBlockedError):
            tool(command="pwd")
        self.assertFalse(executed)

    def test_invalid_timeout_env_uses_safe_default(self):
        original = os.environ.get("AUREL_TIMEOUT_MS")
        os.environ["AUREL_TIMEOUT_MS"] = "not-a-number"
        try:
            self.assertEqual(AurelCrewAIConfig().timeout_ms, 1500)
        finally:
            if original is None:
                os.environ.pop("AUREL_TIMEOUT_MS", None)
            else:
                os.environ["AUREL_TIMEOUT_MS"] = original


if __name__ == "__main__":
    unittest.main()
