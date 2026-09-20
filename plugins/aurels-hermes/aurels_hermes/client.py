import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

class AurelsClient:
    def __init__(self, config):
        self.config = config

    def evaluate(self, action):
        return self._post("/api/v1/actions/evaluate", action)

    def telemetry(self, event):
        return self._post("/api/v1/actions/telemetry", event)

    def _post(self, path, payload):
        request = Request(
            f"{self.config.api_url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.config.api_key}"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.config.timeout_ms / 1000) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Aurels returned HTTP {response.status}")
                return json.loads(response.read().decode())
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            raise RuntimeError("Aurels request failed") from error
