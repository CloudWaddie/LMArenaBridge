import json
import tempfile
import unittest
from pathlib import Path

import httpx


class FakeStreamResponse:
    """A fake response for httpx.AsyncClient.stream context manager."""

    def __init__(self, status_code: int, headers: dict | None = None, text: str = "") -> None:
        self.status_code = int(status_code)
        self.headers = headers or {}
        self._text = text or ""

    async def aiter_lines(self):
        for line in (self._text or "").splitlines():
            yield line

    async def aread(self) -> bytes:
        return (self._text or "").encode("utf-8")

    def raise_for_status(self) -> None:
        if int(self.status_code or 0) >= 400:
            request = httpx.Request("POST", "https://lmarena.ai/nextjs-api/stream/create-evaluation")
            response = httpx.Response(
                int(self.status_code or 0),
                request=request,
                content=(self._text or "").encode("utf-8"),
            )
            raise httpx.HTTPStatusError("HTTP error", request=request, response=response)


class FakeStreamContext:
    """A fake async context manager for httpx.AsyncClient.stream."""

    def __init__(self, response: FakeStreamResponse) -> None:
        self._response = response

    async def __aenter__(self) -> FakeStreamResponse:
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        return False


class BaseBridgeTest(unittest.IsolatedAsyncioTestCase):
    """Base class for LMArenaBridge tests, handling common setup/teardown."""

    async def asyncSetUp(self) -> None:
        from src import main

        self.main = main
        self._orig_debug = self.main.DEBUG
        self.main.DEBUG = False

        self.main.chat_sessions.clear()
        self.main.api_key_usage.clear()

        self._orig_config_file = self.main.CONFIG_FILE
        self._orig_token_index = getattr(self.main, "current_token_index", 0)

        self._temp_dir = tempfile.TemporaryDirectory()
        self._config_path = Path(self._temp_dir.name) / "config.json"

        # Set a minimal valid config by default
        self.setup_config(
            {
                "password": "admin",
                "cf_clearance": "",
                "auth_tokens": ["auth-token-1"],
                "api_keys": [{"name": "Test Key", "key": "test-key", "rpm": 999}],
            }
        )
        self.main.CONFIG_FILE = str(self._config_path)

    async def asyncTearDown(self) -> None:
        self.main.DEBUG = self._orig_debug
        self.main.CONFIG_FILE = self._orig_config_file
        if hasattr(self.main, "current_token_index"):
            self.main.current_token_index = self._orig_token_index
        self._temp_dir.cleanup()

    def setup_config(self, config_data: dict) -> None:
        """Helper to write or update the mock config.json."""
        current_config = {}
        if self._config_path.exists():
            try:
                current_config = json.loads(self._config_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        current_config.update(config_data)
        self._config_path.write_text(json.dumps(current_config), encoding="utf-8")
