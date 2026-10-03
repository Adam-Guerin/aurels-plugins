import unittest
import tempfile
from pathlib import Path
import json
import inspect
import threading
import os
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.error import HTTPError

from aurels_hermes import register
from aurels_hermes.client import AurelRateLimitError, AurelsClient
from aurels_hermes.config import Config
from aurels_hermes.outbox import MAX_BYTES, MAX_EVENT_BYTES, TelemetryOutbox
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
    def test_trusted_dispatch_wrapper_rejects_arguments_that_json_would_change(self):
        for arguments in [{1: "numeric key"}, {"values": (1, 2)}, {"value": float("nan")}, {"value": {1, 2}}]:
            client = Client({"decision": "allow"})
            plugin = AurelsHermesPlugin({"mode": "remote", "api_key": "test", "telemetry_enabled": False}, client)
            with patch.object(client, "evaluate") as evaluate:
                with self.assertRaisesRegex(RuntimeError, "Aurels"):
                    plugin.run_protected("read_file", arguments, lambda _: "must-not-run")
                evaluate.assert_not_called()

    def test_synchronous_dispatch_wrapper_never_reports_an_unawaited_tool_as_success(self):
        async def execute(_arguments):
            return "not-yet-executed"

        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"mode": "remote", "api_key": "test"}, client)
        result = None
        try:
            with self.assertRaises(TypeError):
                result = plugin.run_protected("read_file", {}, execute)
        finally:
            if inspect.iscoroutine(result):
                result.close()
        self.assertEqual(client.events[-1]["outcome"]["status"], "failure")

    def test_explicitly_disabled_native_plugin_allows_without_hook_order_override(self):
        plugin = AurelsHermesPlugin({"enabled": False, "mode": "remote", "api_key": "test"}, Client(error=True))
        self.assertEqual(plugin.pre_tool_call(tool_name="read_file", args={})["action"], "allow")

    def test_trusted_dispatch_wrapper_executes_the_snapshot_even_if_source_args_change(self):
        arguments = {"path": "safe.txt"}

        class MutatingClient(Client):
            def evaluate(self, action):
                arguments["path"] = "changed.txt"
                return {"decision": "allow"}

        plugin = AurelsHermesPlugin({"mode": "remote", "api_key": "test", "telemetry_enabled": False}, MutatingClient())
        dispatched = []
        plugin.run_protected("read_file", arguments, dispatched.append)
        self.assertEqual(dispatched, [{"path": "safe.txt"}])

    def test_trusted_dispatch_wrapper_blocks_denial_approval_and_outage(self):
        for client in [Client({"decision": "block"}), Client({"decision": "flag"}), Client(error=True)]:
            plugin = AurelsHermesPlugin({"mode": "remote", "api_key": "test", "telemetry_enabled": False}, client)
            dispatched = []
            with self.assertRaisesRegex(RuntimeError, "Aurels"):
                plugin.run_protected("read_file", {}, dispatched.append)
            self.assertEqual(dispatched, [])

    def test_trusted_dispatch_wrapper_records_an_actual_tool_error(self):
        client = Client({"decision": "allow", "traceId": "dispatch-trace"})
        plugin = AurelsHermesPlugin({"mode": "remote", "api_key": "test"}, client)

        def execute(_arguments):
            raise FileNotFoundError("synthetic tool error")

        with self.assertRaises(FileNotFoundError):
            plugin.run_protected("read_file", {"path": "missing.txt"}, execute)
        self.assertEqual(client.events[-1]["outcome"]["status"], "failure")
        self.assertEqual(client.events[-1]["traceId"], "dispatch-trace")

    def test_normal_enforcement_registers_without_loading_an_optional_host_llm(self):
        class Context:
            def __init__(self):
                self.hooks = {}

            @property
            def llm(self):
                raise RuntimeError("optional model provider unavailable")

            def register_hook(self, name, handler):
                self.hooks[name] = handler

        context = Context()
        AurelsHermesPlugin({"mode": "remote", "api_key": "test"}, Client({"decision": "block"})).register(context)
        self.assertEqual(set(context.hooks), {"pre_tool_call", "post_tool_call"})
        self.assertEqual(context.hooks["pre_tool_call"](tool_name="read_file", args={})["action"], "block")

    @unittest.skipUnless(os.name == "nt", "Windows process inspection regression")
    def test_windows_queue_lock_probe_never_sends_a_process_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / ".enqueue.lock"
            lock_path.write_text(str(os.getpid()), encoding="ascii")
            # Python's os.kill(pid, 0) terminates processes on Windows.
            # Intercept it before exercising the real liveness check.
            with patch("aurels_hermes.outbox.os.kill") as kill:
                self.assertFalse(TelemetryOutbox._stale_queue_lock(lock_path))
                kill.assert_not_called()

    def test_missing_queue_lock_is_not_classified_as_stale(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing_lock = Path(temporary) / ".enqueue.lock"
            self.assertFalse(TelemetryOutbox._stale_queue_lock(missing_lock))

    def test_stale_pid_probe_rejects_a_replaced_queue_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / ".enqueue.lock"
            dead_pid = 2_000_000_000
            lock_path.write_text(str(dead_pid), encoding="ascii")

            def replace_lock_and_report_dead(pid):
                self.assertEqual(pid, dead_pid)
                lock_path.unlink()
                lock_path.write_text(str(os.getpid()), encoding="ascii")
                raise ProcessLookupError("simulated stale owner")

            with patch("aurels_hermes.outbox._probe_process", side_effect=replace_lock_and_report_dead):
                self.assertFalse(TelemetryOutbox._stale_queue_lock(lock_path))
            self.assertEqual(lock_path.read_text(encoding="ascii"), str(os.getpid()))

    def test_telemetry_queue_does_not_remove_a_replacement_lock_after_stale_pid_probe(self):
        with tempfile.TemporaryDirectory() as spool_dir:
            lock_path = Path(spool_dir) / ".enqueue.lock"
            dead_pid = 2_000_000_000
            lock_path.write_text(str(dead_pid), encoding="ascii")

            def replace_lock_and_report_dead(pid):
                self.assertEqual(pid, dead_pid)
                lock_path.unlink()
                lock_path.write_text(str(os.getpid()), encoding="ascii")
                raise ProcessLookupError("simulated stale owner")

            with patch("aurels_hermes.outbox._probe_process", side_effect=replace_lock_and_report_dead), patch(
                "aurels_hermes.outbox.time.monotonic", side_effect=[0.0, 1.0]
            ):
                with self.assertRaisesRegex(OSError, "queue is busy"):
                    TelemetryOutbox(spool_dir).enqueue({"actionId": "must-not-steal-lock"})

            self.assertEqual(lock_path.read_text(encoding="ascii"), str(os.getpid()))

    def test_telemetry_outbox_enforces_queue_cap_across_concurrent_instances(self):
        # Keep this concurrency regression fast while exercising the exact same
        # admission/locking logic; an 8 MiB fixture made the test needlessly slow.
        with patch("aurels_hermes.outbox.MAX_BYTES", 1024), patch(__name__ + ".MAX_BYTES", 1024), tempfile.TemporaryDirectory() as spool_dir:
            events = [{"actionId": f"concurrent-{index}"} for index in range(16)]
            event_bytes = max(len(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) for event in events)
            fixture_bytes = MAX_BYTES - 5 * event_bytes
            (Path(spool_dir) / "occupier.json").write_bytes(b"x" * fixture_bytes)
            failures = []

            def enqueue(index):
                try:
                    TelemetryOutbox(spool_dir).enqueue({"actionId": f"concurrent-{index}"})
                    return True
                except OSError as error:
                    failures.append(str(error))
                    return False

            with ThreadPoolExecutor(max_workers=16) as executor:
                results = list(executor.map(enqueue, range(len(events))))
            queued = list(Path(spool_dir).glob("*.json"))
            self.assertGreater(sum(results), 0, f"queue contention must not reject every otherwise eligible event: {failures}")
            self.assertLessEqual(sum(results), 5, "only five maximum-sized events fit in the remaining byte capacity")
            self.assertEqual(len(queued), sum(results) + 1, "each successful enqueue must correspond to one persisted event")
            self.assertLessEqual(sum(path.stat().st_size for path in queued), MAX_BYTES, "concurrent enqueues must not exceed the byte cap")

    def test_telemetry_outbox_prunes_abandoned_staging_files_but_preserves_recent_writers(self):
        with tempfile.TemporaryDirectory() as spool_dir:
            abandoned = Path(spool_dir) / ".pending-crashed.tmp"
            active = Path(spool_dir) / ".pending-active.tmp"
            abandoned.write_text("interrupted event", encoding="utf-8")
            active.write_text("active writer", encoding="utf-8")
            stale_at = time.time() - 25 * 60 * 60
            os.utime(abandoned, (stale_at, stale_at))
            outbox = TelemetryOutbox(spool_dir)
            outbox.enqueue({"actionId": "new-event"})
            self.assertFalse(abandoned.exists())
            self.assertTrue(active.exists())

    def test_telemetry_outbox_retries_a_queued_event_after_a_temporary_outage(self):
        with tempfile.TemporaryDirectory() as spool_dir:
            outbox = TelemetryOutbox(spool_dir)
            outbox.enqueue({"actionId": "retry-after-outage"})
            online = threading.Event()
            failed = threading.Event()
            delivered = threading.Event()
            received = []

            def sender(event):
                if not online.is_set():
                    failed.set()
                    raise RuntimeError("network offline")
                received.append(event)
                delivered.set()

            self.assertTrue(outbox.flush_async(sender))
            self.assertTrue(failed.wait(3), "the first attempt should observe the outage")
            online.set()
            self.assertTrue(delivered.wait(5), "queued telemetry should retry without a restart or new event")
            for _ in range(100):
                if not list(Path(spool_dir).glob("*.json")):
                    break
                threading.Event().wait(0.01)
            self.assertEqual(received, [{"actionId": "retry-after-outage"}])
            self.assertEqual(list(Path(spool_dir).glob("*.json")), [])

    def test_durable_telemetry_outbox_expires_old_events_without_sending_them(self):
        with tempfile.TemporaryDirectory() as spool_dir:
            outbox = TelemetryOutbox(spool_dir)
            path = outbox.enqueue({"actionId": "expired"})
            expired_at = time.time() - 8 * 24 * 60 * 60
            os.utime(path, (expired_at, expired_at))
            sent = []
            self.assertEqual(outbox.flush(sent.append), 0)
            self.assertEqual(sent, [])
            self.assertFalse(path.exists())

    def test_telemetry_unicode_serialization_stays_within_the_backend_body_cap(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"accepted":true}'

        config = Config.from_mapping({"api_key": "test", "api_url": "https://aurels.test"})
        request_bodies = []
        client = AurelsClient(config)

        def capture(request, timeout):
            request_bodies.append(request.data)
            return Response()

        with patch("aurels_hermes.client.build_opener") as opener:
            opener.return_value.open.side_effect = capture
            client.telemetry({"actionId": "unicode", "metadata": {"text": "é" * 20_000}})
        self.assertLessEqual(len(request_bodies[0]), 64_000)

    def test_durable_telemetry_configuration_is_opt_in(self):
        self.assertFalse(Config.from_mapping({"mode": "remote", "api_key": "test"}).telemetry_durable)
        config = Config.from_mapping({"telemetry_durable": True, "telemetry_spool_dir": "C:/aurels-spool"})
        self.assertTrue(config.telemetry_durable)
        self.assertEqual(config.telemetry_spool_dir, "C:/aurels-spool")

    def test_native_hook_order_trust_is_opt_in(self):
        self.assertFalse(Config.from_mapping({"mode": "remote"}).trust_native_hook_order)
        self.assertTrue(Config.from_mapping({"trust_native_hook_order": True}).trust_native_hook_order)

    def test_durable_telemetry_outbox_rejects_events_above_disk_bound(self):
        with tempfile.TemporaryDirectory() as spool_dir:
            outbox = TelemetryOutbox(spool_dir)
            with self.assertRaisesRegex(ValueError, "spool limit"):
                outbox.enqueue({"payload": "x" * MAX_EVENT_BYTES})
            self.assertEqual(list(Path(spool_dir).glob("*.json")), [])

    def test_invalid_telemetry_spool_does_not_disable_action_enforcement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            spool_path = Path(temp_dir) / "not-a-directory"
            spool_path.write_text("unrelated", encoding="utf-8")
            plugin = AurelsHermesPlugin(
                {"api_key": "test", "mode": "remote", "telemetry_durable": True, "telemetry_spool_dir": str(spool_path)},
                Client({"decision": "block"}),
            )
            self.assertEqual(plugin.before_action("send_email", {"to": "person@example.test"})["action"], "block")

    def test_durable_telemetry_replays_a_redacted_event_after_restart(self):
        class OfflineClient(Client):
            def __init__(self):
                super().__init__()
                self.attempted = threading.Event()

            def telemetry(self, event):
                self.attempted.set()
                raise RuntimeError("network offline")

        with tempfile.TemporaryDirectory() as spool_dir:
            config = {
                "api_key": "test",
                "mode": "remote",
                "telemetry_durable": True,
                "telemetry_spool_dir": spool_dir,
            }
            offline = OfflineClient()
            first = AurelsHermesPlugin(config, offline)
            first._telemetry(
                "call-1", "send_email", {
                    "to": "person@example.test",
                    "api_key": "secret",
                    "content": "OpenAI key sk-proj-" + "B" * 32,
                },
                {"session_id": "session-1"}, "success",
            )
            self.assertTrue(offline.attempted.wait(3), "the failed event should be attempted in background")
            queued = list(Path(spool_dir).glob("*.json"))
            self.assertEqual(len(queued), 1, "failed delivery should leave one durable event")

            online = Client()
            replay = AurelsHermesPlugin(config, online)
            for _ in range(300):
                if online.events:
                    break
                threading.Event().wait(0.01)
            self.assertEqual(len(online.events), 1, "a restarted plugin should replay pending telemetry")
            self.assertEqual(online.events[0]["metadata"]["arguments"]["api_key"], "[REDACTED]")
            self.assertEqual(online.events[0]["metadata"]["arguments"]["content"], "[REDACTED]")
            replay._telemetry_outbox.flush(online.telemetry)
            self.assertEqual(list(Path(spool_dir).glob("*.json")), [])

    def test_rate_limited_evaluation_blocks_instead_of_requesting_approval(self):
        class RateLimitedClient:
            def evaluate(self, request):
                raise AurelRateLimitError(12)

            def telemetry(self, event):
                raise AssertionError("429 evaluation must not create more API traffic")

        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, RateLimitedClient())
        result = plugin.before_action("send_email", {"to": "recipient@example.test"})
        self.assertEqual(result["action"], "block")
        self.assertIn("12 seconds", result["message"])

    def test_client_preserves_retry_after_from_http_429(self):
        config = Config.from_mapping({"api_key": "test", "api_url": "https://aurels.test"})
        client = AurelsClient(config)

        def rate_limited(request, timeout):
            raise HTTPError(request.full_url, 429, "Too Many Requests", {"Retry-After": "12"}, None)

        with patch("aurels_hermes.client.build_opener") as opener:
            opener.return_value.open.side_effect = rate_limited
            with self.assertRaises(AurelRateLimitError) as raised:
                client.evaluate({"action": {"id": "call-1", "name": "send_email", "arguments": {}}})
        self.assertEqual(raised.exception.retry_after_seconds, 12)

    def test_client_rejects_oversized_action_before_network(self):
        config = Config.from_mapping({"api_key": "test", "api_url": "https://aurels.test"})
        client = AurelsClient(config)
        with patch("aurels_hermes.client.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "request exceeds"):
                client.evaluate({"action": {"id": "oversized", "arguments": {"content": "x" * (1024 * 1024)}}})
        opener.assert_not_called()

    def test_allow(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": "allow"}))
        self.assertEqual(plugin.before_action("read_file")["action"], "allow")

    def test_aurels_prefixed_tools_are_evaluated(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": "block"}))
        self.assertEqual(plugin.before_action("aurels.exec")["action"], "block")

    def test_flag_and_block_do_not_execute(self):
        for decision in ("flag", "block"):
            plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": decision}))
            self.assertIn(plugin.before_action("exec")["action"], {"approve", "block"})

    def test_failure_is_closed_by_default(self):
        self.assertEqual(
            AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client(error=True)).before_action("exec")["action"],
            "approve",
        )

    def test_register_registers_both_native_hooks(self):
        class Host:
            def __init__(self):
                self.hooks = []

            def register_hook(self, name, handler):
                self.hooks.append((name, handler))

        host = Host()
        plugin = register(host)
        self.assertEqual([name for name, _ in host.hooks], ["pre_tool_call", "post_tool_call"])
        self.assertIsInstance(plugin, AurelsHermesPlugin)

    def test_retrospective_mode_registers_finalize_hook_and_uses_host_llm(self):
        class Review:
            content_type = "json"
            parsed = {"summary": "Reviewed", "concerns": [], "recommendations": [], "confidence": 0.8}
            provider = "openai"
            model = "gpt-test"

        class Host:
            def __init__(self):
                self.hooks = {}
                self.llm = type("LLM", (), {"complete_structured": lambda _self, **kwargs: (calls.append(kwargs) or Review())})()

            def register_hook(self, name, handler):
                self.hooks[name] = handler

        calls = []
        host = Host()
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": "", "telemetry_enabled": True})
        plugin.register(host)
        self.assertEqual(set(host.hooks), {"pre_tool_call", "post_tool_call", "on_session_finalize"})
        preflight = host.hooks["pre_tool_call"](
            tool_name="write_file", args={"path": "notes.txt", "content": "Authorization: Bearer very-secret", "message": "OpenAI key sk-proj-" + "A" * 32},
            task_id="task-1", session_id="session-1", tool_call_id="",
        )
        self.assertEqual(preflight["action"], "allow")
        self.assertTrue(preflight["action_id"])
        host.hooks["post_tool_call"](
            tool_name="write_file", args={"path": "notes.txt", "content": "Authorization: Bearer very-secret", "message": "OpenAI key sk-proj-" + "A" * 32},
            task_id="task-1", session_id="session-1", tool_call_id="", status="success",
        )
        host.hooks["on_session_finalize"](session_id="session-1")
        self.assertEqual(len(calls), 1)
        self.assertIn("aurels_retrospective_review", calls[0]["schema_name"])
        serialized = calls[0]["input"][0]["text"]
        self.assertNotIn("very-secret", serialized)
        self.assertNotIn("sk-proj-", serialized)
        self.assertNotIn("A" * 32, serialized)
        self.assertIn("write_file", serialized)
        self.assertEqual(calls[0]["purpose"], "aurels-retrospective-review")

    def test_retrospective_review_never_uses_aurels_api_client(self):
        client = Client(error=True)
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": "", "telemetry_enabled": True}, client)
        preflight = plugin.before_action("read_file", {"path": "README.md"}, {"session_id": "session-1"})
        self.assertEqual(preflight["action"], "allow")
        plugin.after_action("read_file", {"path": "README.md"}, {"session_id": "session-1"}, status="success")
        self.assertEqual(client.events, [])
        self.assertEqual(client.error, True)

    def test_retrospective_model_input_is_bounded(self):
        captured = []

        class Review:
            content_type = "json"
            parsed = {"summary": "Reviewed", "concerns": [], "recommendations": [], "confidence": 0.8}
            provider = "openai"
            model = "gpt-test"

        class LLM:
            def complete_structured(self, **kwargs):
                captured.append(kwargs)
                return Review()

        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""})
        plugin.llm = LLM()
        plugin._retrospective["bounded-session"] = [
            {"action_id": str(index), "tool": "write_file", "arguments": "x" * 4096, "outcome": "success"}
            for index in range(100)
        ]
        plugin.on_session_finalize(session_id="bounded-session")
        sent = captured[0]["input"][0]["text"]
        self.assertLessEqual(len(sent), 16000)
        self.assertEqual(captured[0]["timeout"], 20)

    def test_retrospective_rejects_out_of_schema_model_review_before_logging(self):
        class InvalidReview:
            content_type = "json"
            parsed = {"summary": "review", "concerns": ["x" * 501], "recommendations": [], "confidence": 0.5}

        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""})
        plugin.llm = type("LLM", (), {"complete_structured": lambda *_args, **_kwargs: InvalidReview()})()
        plugin._remember_retrospective("a1", "read_file", {}, {"session_id": "invalid-review"}, True)
        with self.assertLogs("aurels_hermes", level="WARNING") as logs:
            plugin.on_session_finalize(session_id="invalid-review")
        self.assertTrue(any("retrospective review failed" in line for line in logs.output))
        self.assertFalse(any("x" * 100 in line for line in logs.output))

    def test_retrospective_model_failure_logs_safe_provider_setup_guidance(self):
        class UnavailableLLM:
            def complete_structured(self, **_kwargs):
                raise RuntimeError("provider credential failed: synthetic-secret-value")

        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""})
        plugin.llm = UnavailableLLM()
        plugin._remember_retrospective("a1", "read_file", {}, {"session_id": "provider-error"}, True)
        with self.assertLogs("aurels_hermes", level="WARNING") as logs:
            plugin.on_session_finalize(session_id="provider-error")
        self.assertTrue(any("check the Hermes model provider and authentication" in line for line in logs.output))
        self.assertFalse(any("synthetic-secret-value" in line for line in logs.output))

    def test_retrospective_actions_expire_if_session_finalize_is_missing(self):
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""})
        plugin.llm = type("LLM", (), {"complete_structured": lambda *_args, **_kwargs: self.fail("expired actions must not reach the model")})()
        with patch("aurels_hermes.plugin.time.monotonic", return_value=10):
            plugin._remember_retrospective("a1", "write_file", {"content": "private"}, {"session_id": "stale"}, True)
        with patch("aurels_hermes.plugin.time.monotonic", return_value=3610):
            plugin.on_session_finalize(session_id="stale")
        self.assertNotIn("stale", plugin._retrospective)
        self.assertNotIn("stale", plugin._retrospective_last_seen)

    def test_retrospective_activity_refreshes_session_retention(self):
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""})
        with patch("aurels_hermes.plugin.time.monotonic", return_value=10):
            plugin._remember_retrospective("a1", "read_file", {"path": "safe"}, {"session_id": "active"}, True)
        with patch("aurels_hermes.plugin.time.monotonic", return_value=3500):
            plugin._remember_retrospective("a2", "read_file", {"path": "safe2"}, {"session_id": "active"}, True)
        with patch("aurels_hermes.plugin.time.monotonic", return_value=7099):
            plugin._prune_retrospective()
        self.assertIn("active", plugin._retrospective)
        with patch("aurels_hermes.plugin.time.monotonic", return_value=7100):
            plugin._prune_retrospective()
        self.assertNotIn("active", plugin._retrospective)

    def test_retrospective_session_limit_evicts_least_recently_active(self):
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""})
        with patch("aurels_hermes.plugin.MAX_RETROSPECTIVE_SESSIONS", 2):
            for session_id, now in (("older", 10), ("newer", 20), ("older", 30), ("incoming", 40)):
                with patch("aurels_hermes.plugin.time.monotonic", return_value=now):
                    plugin._remember_retrospective(session_id, "read_file", {}, {"session_id": session_id}, True)
        self.assertIn("older", plugin._retrospective)
        self.assertIn("incoming", plugin._retrospective)
        self.assertNotIn("newer", plugin._retrospective)

    def test_pending_action_correlates_post_hook_without_tool_call_id(self):
        client = Client({"decision": "allow", "traceId": "trace-no-call-id"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": True}, client)
        before = plugin.pre_tool_call(tool_name="read_file", args={"path": "README.md"}, task_id="task-7", session_id="s-7")
        self.assertTrue(before["action_id"])
        plugin.post_tool_call(tool_name="read_file", args={"path": "README.md"}, task_id="task-7", session_id="s-7", status="success")
        self.assertEqual(client.events[0]["actionId"], before["action_id"])
        self.assertEqual(client.events[0]["traceId"], "trace-no-call-id")

    def test_retrospective_mode_validation(self):
        self.assertEqual(Config.from_mapping({"mode": "retrospective"}).mode, "retrospective")

    def test_pre_tool_callback_accepts_keyword_contract(self):
        plugin = AurelsHermesPlugin(
            {"api_key": "test", "mode": "remote", "trust_native_hook_order": True},
            Client({"decision": "allow"}),
        )
        result = plugin.pre_tool_call(
            tool_name="read_file",
            args={"path": "README.md"},
            task_id="task-1",
            tool_call_id="call-1",
            session_id="session-1",
            agent_id="agent-1",
        )
        self.assertEqual(result["action"], "allow")

    def test_native_hook_converts_approval_to_block_because_hermes_ignores_approve(self):
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local"}, Client())
        result = plugin.pre_tool_call(tool_name="read_file", args={"path": "README.md"})
        self.assertEqual(result["action"], "block")
        self.assertTrue(result["message"])
        self.assertTrue(result["action_id"])

    def test_native_hook_never_trusts_host_version_string_for_approval(self):
        class Context:
            llm = None
            hermes_version = "0.21.5"

            def register_hook(self, name, handler):
                pass

        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": "flag"}))
        plugin.register(Context())
        result = plugin.pre_tool_call(tool_name="send_email", args={"to": "x@example.test"})
        self.assertEqual(result["action"], "block")
        self.assertTrue(result["message"])

    def test_unknown_host_version_never_receives_native_approve(self):
        class Context:
            llm = None

            def register_hook(self, name, handler):
                pass

        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local"}, Client())
        plugin.register(Context())
        self.assertEqual(plugin.pre_tool_call(tool_name="read_file", args={})["action"], "block")

    def test_native_hook_preserves_explicit_flag_block_and_model_outage_as_blocks(self):
        cases = (
            (Client({"decision": "flag"}), "flag"),
            (Client({"decision": "block"}), "block"),
            (Client(error=True), "error"),
            (Client({"decision": "rewrite"}), "invalid"),
        )
        for client, case in cases:
            with self.subTest(case=case):
                plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, client)
                result = plugin.pre_tool_call(tool_name="send_email", args={"to": "x@example.test"})
                self.assertEqual(result["action"], "block")
                self.assertTrue(result["message"])

    def test_native_remote_allow_requires_explicit_trust_in_hermes_hook_order(self):
        remote = AurelsHermesPlugin({"api_key": "test", "mode": "remote"}, Client({"decision": "allow"}))
        trusted_remote = AurelsHermesPlugin(
            {"api_key": "test", "mode": "remote", "trust_native_hook_order": True},
            Client({"decision": "allow"}),
        )
        retrospective = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""}, Client())
        denied = remote.pre_tool_call(tool_name="read_file", args={})
        self.assertEqual(denied["action"], "block")
        self.assertIn("later hook", denied["message"])
        self.assertEqual(remote._pending, {})
        self.assertEqual(trusted_remote.pre_tool_call(tool_name="read_file", args={})["action"], "allow")
        self.assertEqual(retrospective.pre_tool_call(tool_name="read_file", args={})["action"], "allow")

    def test_unexpected_pre_hook_error_returns_explicit_host_block(self):
        plugin = AurelsHermesPlugin({"mode": "remote", "api_key": "test"}, Client({"decision": "allow"}))
        plugin.before_action = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("unexpected"))
        result = plugin.pre_tool_call(tool_name="exec", args={"command": "safe"})
        self.assertEqual(result["action"], "block")
        self.assertIn("execution was blocked", result["message"])

    def test_local_mode_has_no_network_telemetry(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local", "telemetry_enabled": True}, client)
        plugin.before_action("exec", {"command": "rm -rf /"})
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "action-1"}, status="success")
        self.assertEqual(client.events, [])

    def test_disabled_plugin_has_no_post_action_telemetry(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"enabled": False, "api_key": "test", "mode": "remote", "telemetry_enabled": True}, client)
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "action-1"}, status="success")
        self.assertEqual(client.events, [])

    def test_local_mode_blocks_destructive_commands_without_a_key(self):
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local", "telemetry_enabled": False}, Client(error=True))
        self.assertEqual(plugin.before_action("exec", {"command": "rm -rf /"})["action"], "block")

    def test_local_mode_scans_nested_arguments_independent_of_field_names(self):
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local", "telemetry_enabled": False}, Client(error=True))
        cases = (
            ("task", {"cmd": "rm -rf /important"}),
            ("write_file", {"content": "drop table customers"}),
            ("aurels.exec", {"payload": {"body": "chmod 777 /srv/app"}}),
            ("task", {"steps": [{"message": "transfer funds now"}]}),
        )
        for tool_name, arguments in cases:
            with self.subTest(tool_name=tool_name, arguments=arguments):
                self.assertEqual(plugin.before_action(tool_name, arguments)["action"], "block")

    def test_local_mode_still_requires_approval_for_non_destructive_actions(self):
        plugin = AurelsHermesPlugin({"api_key": "", "mode": "local", "telemetry_enabled": False}, Client(error=True))
        result = plugin.before_action("read_file", {"path": "README.md"})
        self.assertEqual(result["action"], "approve")

    def test_only_ambiguous_action_reaches_model(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, client)
        self.assertEqual(plugin.before_action("send_email")["action"], "allow")

    def test_model_failure_flags_ambiguous_action(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, Client(error=True))
        result = plugin.before_action("send_email")
        self.assertEqual(result["action"], "approve")
        self.assertIn("could not safely evaluate", result["message"])
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
        with patch("aurels_hermes.client.build_opener") as build_opener:
            build_opener.return_value.open.return_value = response
            self.assertEqual(AurelsClient(Config(enabled=True, api_url="https://www.aurels.dev", api_key="test", mode="remote")).evaluate({"action": {"id": "a"}}), {})
        self.assertEqual(response.read_limit, 1024 * 1024 + 1)

    def test_client_rejects_redirects_without_following_them(self):
        class Opener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append(request)
                raise HTTPError(request.full_url, 303, "See Other", {}, None)

        opener = Opener()
        client = AurelsClient(Config(enabled=True, api_url="https://www.aurels.dev", api_key="test-key", mode="remote"))
        with patch("aurels_hermes.client.build_opener", return_value=opener):
            with self.assertRaises(RuntimeError):
                client.evaluate({"action": {"id": "redirect"}})
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].get_header("X-api-key"), "test-key")

    def test_client_binds_idempotency_key_to_evaluated_arguments(self):
        left = AurelsClient._idempotency_key("/api/v1/actions/evaluate", {"action": {"id": "same-call", "arguments": {"command": "echo safe"}}})
        right = AurelsClient._idempotency_key("/api/v1/actions/evaluate", {"action": {"id": "same-call", "arguments": {"command": "rm -rf /"}}})
        self.assertNotEqual(left, right)

    def test_client_binds_telemetry_idempotency_to_event_content(self):
        original = {"actionId": "same-call", "outcome": {"status": "success"}, "metadata": {"arguments": {"path": "safe.txt"}}}
        changed = {"actionId": "same-call", "outcome": {"status": "success"}, "metadata": {"arguments": {"path": "sensitive.txt"}}}
        original_key = AurelsClient._idempotency_key("/api/v1/actions/telemetry", original)
        self.assertEqual(original_key, AurelsClient._idempotency_key("/api/v1/actions/telemetry", original))
        self.assertNotEqual(original_key, AurelsClient._idempotency_key("/api/v1/actions/telemetry", changed))

    def test_trace_cleanup_after_after_action(self):
        client = Client({"decision": "allow", "traceId": "trace-123"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": True}, client)
        plugin.before_action("read_file", {"path": "README.md"}, {"action_id": "trace-cleanup"})
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "trace-cleanup"}, status="success")
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "trace-cleanup"}, status="success")
        self.assertEqual(client.events[0]["traceId"], "trace-123")
        self.assertIsNone(client.events[1]["traceId"])

    def test_redacts_sensitive_values_embedded_in_strings(self):
        self.assertEqual(redact("Authorization: Bearer secret-token"), "[REDACTED]")
        self.assertEqual(redact({"command": "token=abc123"})["command"], "[REDACTED]")
        self.assertEqual(redact("safe-value"), "safe-value")

    def test_redacts_common_secret_formats_inside_ordinary_text_fields(self):
        cases = (
            ("content", "sk-proj-" + "A" * 32),
            ("message", "AWS key AKIAIOSFODNN7EXAMPLE"),
            ("payload", "GitHub token ghp_" + "a" * 36),
            ("body", "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"),
        )
        for field, secret_text in cases:
            with self.subTest(field=field):
                self.assertEqual(redact({field: secret_text})[field], "[REDACTED]")

    def test_hermes_redaction_passes_the_shared_cross_language_credential_corpus(self):
        repo_root = Path(__file__).resolve().parents[3]
        corpus_path = repo_root / "plugins" / "aurels-integrations" / "tests" / "fixtures" / "redaction-corpus.json"
        for item in json.loads(corpus_path.read_text(encoding="utf-8")):
            with self.subTest(name=item["name"]):
                self.assertNotIn(item["secret"], json.dumps(redact({"message": item["input"]})))

    def test_status_parameter_drives_success(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": True}, client)
        plugin.before_action("read_file", {"path": "README.md"}, {"action_id": "action-1"})
        plugin.after_action("read_file", {"path": "README.md"}, {"action_id": "action-1"}, status="error")
        self.assertEqual(client.events[0]["outcome"]["status"], "failure")

    def test_explicit_failure_status_is_retrospected_as_failure(self):
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""}, Client())
        plugin.after_action("write_file", {"path": "important.txt"}, {"session_id": "session-status"}, success=True, status="error")
        self.assertEqual(plugin._retrospective["session-status"][0]["outcome"], "failure")

    def test_explicit_success_status_overrides_false_success_argument(self):
        plugin = AurelsHermesPlugin({"mode": "retrospective", "api_key": ""}, Client())
        plugin.after_action("write_file", {"path": "important.txt"}, {"session_id": "session-status"}, success=False, status="success")
        self.assertEqual(plugin._retrospective["session-status"][0]["outcome"], "success")

    def test_native_post_hook_marks_host_error_result_as_failure(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": True, "trust_native_hook_order": True}, client)
        directive = plugin.pre_tool_call(tool_name="write_file", args={"path": "missing"}, tool_call_id="host-error")
        self.assertEqual(directive["action"], "allow", "post-hook fixture must actually have reached dispatch")
        plugin.post_tool_call(
            tool_name="write_file", args={"path": "missing"}, tool_call_id="host-error",
            result='{"error":"file not found"}',
        )
        self.assertEqual(client.events[0]["outcome"]["status"], "failure")

    def test_pending_correlation_state_stays_bounded_after_many_completed_actions(self):
        client = Client({"decision": "allow"})
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, client)
        for index in range(1000):
            call_id = f"bounded-{index}"
            arguments = {"path": f"file-{index}"}
            context = {"action_id": call_id, "task_id": "same-task", "session_id": "same-session"}
            plugin.before_action("read_file", arguments, context)
            plugin.after_action("read_file", arguments, context)
        self.assertEqual(plugin._pending, {})
        self.assertEqual(len(plugin._pending_order), 0)

    def test_pending_correlation_state_evicts_oldest_when_callbacks_are_missing(self):
        plugin = AurelsHermesPlugin({"api_key": "test", "mode": "remote", "telemetry_enabled": False}, Client({"decision": "allow"}))
        for index in range(150):
            plugin.before_action("read_file", {"path": f"file-{index}"}, {"action_id": f"orphan-{index}"})
        self.assertLessEqual(len(plugin._pending), 100)
        self.assertLessEqual(len(plugin._pending_order), 100)

    def test_redaction_handles_circular_structures(self):
        circular = {"key": "value"}
        circular["self"] = circular
        result = redact(circular)
        self.assertEqual(result["key"], "value")
        self.assertEqual(result["self"], "[Circular]")


if __name__ == "__main__":
    unittest.main()
