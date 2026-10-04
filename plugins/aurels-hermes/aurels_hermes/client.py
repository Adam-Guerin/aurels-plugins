import json
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse, urlunparse, quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, build_opener

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024


class AurelRateLimitError(RuntimeError):
    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = max(1, min(3600, int(retry_after_seconds)))
        super().__init__(f"Aurels API rate limit reached. Retry in {self.retry_after_seconds} seconds.")


class _RejectRedirects(HTTPRedirectHandler):
    """Do not forward an authenticated request to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class AurelsClient:
    def __init__(self, config):
        self.config = config
        parsed = urlparse(config.api_url)
        loopback_http = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if (parsed.scheme != "https" and not loopback_http) or parsed.username or parsed.password:
            raise ValueError("Aurels API URL must use HTTPS (or loopback HTTP) and contain no credentials")
        self.base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))

    def evaluate(self, action):
        return self._post("/api/v1/actions/evaluate", action)

    def telemetry(self, event):
        return self._post("/api/v1/actions/telemetry", event)

    def _post(self, path, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise ValueError("Aurels request exceeds the maximum allowed size")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json", "X-API-Key": self.config.api_key, "Idempotency-Key": self._idempotency_key(path, payload)},
            method="POST",
        )
        try:
            with build_opener(_RejectRedirects()).open(request, timeout=self.config.timeout_ms / 1000) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Aurels returned HTTP {response.status}")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Aurels response exceeds the maximum allowed size")
                return json.loads(body.decode())
        except HTTPError as error:
            if error.code == 429:
                raise AurelRateLimitError(_retry_after_seconds(error.headers.get("Retry-After"))) from error
            raise RuntimeError(f"Aurels request failed with HTTP {error.code}") from error
        except (URLError, TimeoutError, ValueError) as error:
            raise RuntimeError("Aurels request failed") from error

    @staticmethod
    def _idempotency_key(path, payload):
        action_id = payload.get("action", {}).get("id") if path.endswith("/evaluate") else payload.get("actionId")
        status = payload.get("outcome", {}).get("status", "")
        prefix = "action-evaluate" if path.endswith("/evaluate") else "action-telemetry"
        fingerprint_payload = payload.get("action", {}) if path.endswith("/evaluate") else payload
        serialized = json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        fingerprint = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        key = f"{prefix}:{quote(str(action_id or 'unknown'), safe='')}"
        if status:
            key += f":{quote(str(status), safe='')}"
        return f"{key}:{fingerprint}"


def _retry_after_seconds(value):
    if not value:
        return 1
    try:
        return max(1, min(3600, int(float(value))))
    except (TypeError, ValueError):
        try:
            reset = parsedate_to_datetime(value)
            if reset.tzinfo is None:
                reset = reset.replace(tzinfo=timezone.utc)
            return max(1, min(3600, int((reset - datetime.now(timezone.utc)).total_seconds())))
        except (TypeError, ValueError, OverflowError):
            return 1
