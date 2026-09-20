import json
from urllib.parse import urlparse, urlunparse, quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MAX_RESPONSE_BYTES = 1024 * 1024

class AurelsClient:
    def __init__(self, config):
        self.config = config
        parsed = urlparse(config.api_url)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise ValueError("Aurels API URL must use HTTPS and contain no credentials")
        self.base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))

    def evaluate(self, action):
        return self._post("/api/v1/actions/evaluate", action)

    def telemetry(self, event):
        return self._post("/api/v1/actions/telemetry", event)

    def _post(self, path, payload):
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": self.config.api_key, "Idempotency-Key": self._idempotency_key(path, payload)},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.config.timeout_ms / 1000) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Aurels returned HTTP {response.status}")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Aurels response exceeds the maximum allowed size")
                return json.loads(body.decode())
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            raise RuntimeError("Aurels request failed") from error

    @staticmethod
    def _idempotency_key(path, payload):
        action_id = payload.get("action", {}).get("id") if path.endswith("/evaluate") else payload.get("actionId")
        status = payload.get("outcome", {}).get("status", "")
        return f"{'action-evaluate' if path.endswith('/evaluate') else 'action-telemetry'}:{quote(str(action_id or 'unknown'), safe='')}" + (f":{status}" if status else "")
