from datetime import datetime, timezone
from uuid import uuid4

from .client import AurelsClient
from .config import Config
from .redaction import redact

BLOCKED = "Aurels blocked this action because it violates the active security policy."
APPROVAL_REQUIRED = "Aurels requires human approval before this action can run."


class AurelsHermesPlugin:
    def __init__(self, config=None, client=None):
        self.config = Config.from_mapping(config)
        self.client = client or AurelsClient(self.config)
        self._traces = {}

    def register(self, ctx):
        register_hook = getattr(ctx, "register_hook", None)
        if not callable(register_hook):
            raise RuntimeError("Aurels Hermes requires a host with callable register_hook.")
        register_hook("pre_tool_call", self.pre_tool_call)
        register_hook("post_tool_call", self.post_tool_call)

    def pre_tool_call(self, tool_name=None, args=None, task_id=None, tool_call_id=None, session_id=None, agent_id=None, **kwargs):
        arguments = args if isinstance(args, dict) else {}
        context = {
            "task_id": task_id,
            "action_id": tool_call_id or kwargs.get("action_id"),
            "session_id": session_id or kwargs.get("session_id"),
            "agent_id": agent_id or kwargs.get("agent_id"),
        }
        return self.before_action(tool_name or kwargs.get("name") or "unknown", arguments, context)

    def post_tool_call(self, tool_name=None, args=None, task_id=None, tool_call_id=None, session_id=None, agent_id=None, status=None, **kwargs):
        arguments = args if isinstance(args, dict) else {}
        context = {
            "task_id": task_id,
            "action_id": tool_call_id or kwargs.get("action_id"),
            "session_id": session_id or kwargs.get("session_id"),
            "agent_id": agent_id or kwargs.get("agent_id"),
        }
        success = status is None or status == "success"
        self.after_action(tool_name or kwargs.get("name") or "unknown", arguments, context, success=success)

    def before_action(self, action_name, arguments=None, context=None):
        context = context or {}
        if not self.config.enabled or str(action_name or "").startswith("aurels."):
            return {"action": "allow"}
        action_id = context.get("action_id") or str(uuid4())
        action = {
            "version": "1",
            "integration": "hermes",
            "action": {"id": action_id, "name": action_name, "arguments": arguments or {}},
            "agent": {"id": context.get("agent_id"), "sessionId": context.get("session_id"), "runId": context.get("task_id")},
            "timestamp": self._now(),
        }
        local = self._local_decision(arguments or {})
        if local["decision"] == "block":
            self._telemetry(action_id, action_name, arguments, context, "blocked")
            return {"action": "block", "message": BLOCKED}
        if self.config.mode == "local" or not self.config.api_key:
            return {"action": "approve", "message": APPROVAL_REQUIRED}
        try:
            decision = self.client.evaluate(action)
            outcome = decision.get("decision") if isinstance(decision, dict) else None
            if outcome not in {"allow", "flag", "block"}:
                raise RuntimeError("Malformed Aurels decision")
            if "riskScore" in decision and (
                not isinstance(decision["riskScore"], (int, float))
                or isinstance(decision["riskScore"], bool)
                or not 0 <= decision["riskScore"] <= 100
            ):
                raise RuntimeError("Malformed Aurels decision")
            trace_id = decision.get("traceId")
            if trace_id:
                self._traces[action_id] = trace_id
            if outcome == "allow":
                return {"action": "allow"}
            self._telemetry(action_id, action_name, arguments, context, "blocked")
            if outcome == "flag":
                return {"action": "approve", "message": APPROVAL_REQUIRED}
            return {"action": "block", "message": BLOCKED}
        except Exception:
            return {"action": "approve", "message": APPROVAL_REQUIRED}

    def after_action(self, action_name, arguments=None, context=None, success=True, status=None):
        context = context or {}
        action_id = context.get("action_id", "unknown")
        if status is not None:
            success = status == "success"
        try:
            self._telemetry(action_id, action_name, arguments, context, "success" if success else "failure")
        finally:
            self._traces.pop(action_id, None)

    def _telemetry(self, action_id, action_name, arguments, context, status):
        if not self._should_send_telemetry():
            return
        try:
            self.client.telemetry(
                {
                    "version": "1",
                    "integration": "hermes",
                    "actionId": action_id,
                    "traceId": self._traces.get(action_id),
                    "agent": {"id": context.get("agent_id"), "sessionId": context.get("session_id"), "runId": context.get("task_id")},
                    "outcome": {"status": status},
                    "metadata": {"action": action_name, "arguments": redact(arguments or {})},
                    "timestamp": self._now(),
                }
            )
        except Exception:
            pass

    def _should_send_telemetry(self):
        return self.config.enabled and self.config.telemetry_enabled and self.config.mode != "local" and bool(self.config.api_key)

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _local_decision(arguments):
        command = str(arguments.get("command", arguments.get("script", ""))).lower() if isinstance(arguments, dict) else ""
        if any(pattern in command for pattern in ("rm -rf", "del /", "format ", "drop table", "| sh", "| bash", "chmod 777")):
            return {"decision": "block"}
        return {"decision": "ambiguous"}
