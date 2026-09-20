from datetime import datetime, timezone
from uuid import uuid4
from .client import AurelsClient
from .config import Config
from .redaction import redact

class AurelsHermesPlugin:
    def __init__(self, config=None, client=None):
        self.config = Config.from_mapping(config)
        self.client = client or AurelsClient(self.config)
        self._traces = {}

    def before_action(self, action_name, arguments=None, context=None):
        context = context or {}
        action_id = context.get("action_id") or str(uuid4())
        request = {"version": "1", "integration": "hermes", "action": {"id": action_id, "name": action_name, "arguments": arguments or {}}, "agent": {"id": context.get("agent_id"), "sessionId": context.get("session_id")}, "timestamp": self._now()}
        try:
            decision = self.client.evaluate(request)
            outcome = decision.get("decision") if isinstance(decision, dict) else None
            if outcome not in {"allow", "flag", "block", "quarantine", "rewrite"}:
                raise RuntimeError("Malformed Aurels decision")
            self._traces[action_id] = decision.get("traceId")
            if outcome == "allow":
                return {"allow": True, "action_id": action_id}
            if outcome == "rewrite" and isinstance(decision.get("rewrittenArguments"), dict):
                return {"allow": True, "action_id": action_id, "arguments": decision["rewrittenArguments"]}
            self._telemetry(action_id, action_name, arguments, context, "blocked")
            return {"allow": False, "action_id": action_id, "reason": "Aurels requires human approval before this action can run." if outcome == "flag" else "Aurels blocked this action because it violates the active security policy."}
        except Exception:
            if self.config.fail_mode == "open":
                return {"allow": True, "action_id": action_id, "degraded": True}
            return {"allow": False, "action_id": action_id, "reason": "Aurels security verification is unavailable."}

    def after_action(self, action_name, arguments=None, context=None, success=True):
        context = context or {}
        self._telemetry(context.get("action_id", "unknown"), action_name, arguments, context, "success" if success else "failure")

    def _telemetry(self, action_id, action_name, arguments, context, status):
        if not self.config.telemetry_enabled: return
        try:
            self.client.telemetry({"version": "1", "integration": "hermes", "actionId": action_id, "traceId": self._traces.get(action_id), "outcome": {"status": status}, "metadata": {"action": action_name, "arguments": redact(arguments or {})}, "timestamp": self._now()})
        except Exception: pass

    @staticmethod
    def _now(): return datetime.now(timezone.utc).isoformat()
