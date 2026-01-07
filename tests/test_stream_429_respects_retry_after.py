import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx


class _FakeStreamResponse:
    def __init__(self, status_code: int, headers: dict | None = None, text: str = "") -> None:
        self.status_code = int(status_code)
        self.headers = headers or {}
        self._text = text

    async def aiter_lines(self):
        for line in (self._text or "").splitlines():
            yield line

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://lmarena.ai/nextjs-api/stream/create-evaluation")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("HTTP error", request=request, response=response)


class _FakeStreamContext:
    def __init__(self, response: _FakeStreamResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _FakeStreamResponse:
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class TestStream429RespectsRetryAfter(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from src import main

        self.main = main
        self._orig_debug = self.main.DEBUG
        self.main.DEBUG = False
        self.main.chat_sessions.clear()
        self.main.api_key_usage.clear()

        self._temp_dir = tempfile.TemporaryDirectory()
        self._config_path = Path(self._temp_dir.name) / "config.json"
        self._config_path.write_text(
            json.dumps(
                {
                    "password": "admin",
                    "cf_clearance": "",
                    "auth_tokens": ["auth-token-1"],
                    "api_keys": [{"name": "Test Key", "key": "test-key", "rpm": 999}],
                }
            ),
            encoding="utf-8",
        )

        self._orig_config_file = self.main.CONFIG_FILE
        self.main.CONFIG_FILE = str(self._config_path)

    async def asyncTearDown(self) -> None:
        self.main.DEBUG = self._orig_debug
        self.main.CONFIG_FILE = self._orig_config_file
        self._temp_dir.cleanup()

    async def test_stream_429_waits_retry_after_seconds(self) -> None:
        stream_calls: dict[str, int] = {"count": 0}

        def fake_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            stream_calls["count"] += 1
            if stream_calls["count"] == 1:
                return _FakeStreamContext(
                    _FakeStreamResponse(
                        status_code=429,
                        headers={"Retry-After": "7"},
                        text='{"error":"Too Many Requests","message":"Too Many Requests"}',
                    )
                )
            return _FakeStreamContext(
                _FakeStreamResponse(
                    status_code=200,
                    headers={},
                    text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
                )
            )

        sleep_mock = AsyncMock()

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "refresh_recaptcha_token",
            AsyncMock(return_value="recaptcha-token"),
        ), patch.object(
            httpx.AsyncClient,
            "stream",
            new=fake_stream,
        ), patch("src.main.asyncio.sleep", sleep_mock), patch("src.main.time.time") as time_mock:
            # Make keepalive/backoff deterministic and fast by advancing a mocked clock when sleep() is awaited.
            now = [1000.0]

            def _time() -> float:
                return now[0]

            async def _sleep(seconds: float) -> None:
                try:
                    now[0] += float(seconds)
                except Exception:
                    now[0] += 0.0
                return None

            time_mock.side_effect = _time
            sleep_mock.side_effect = _sleep
            get_models_mock.return_value = [
                {
                    "publicName": "test-search-model",
                    "id": "model-id",
                    "organization": "test-org",
                    "capabilities": {
                        "inputCapabilities": {"text": True},
                        "outputCapabilities": {"search": True},
                    },
                }
            ]

            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-search-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )
                body_text = response.text

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", body_text)
        self.assertIn("[DONE]", body_text)
        self.assertGreaterEqual(stream_calls["count"], 2)
        sleep_args = [call.args[0] for call in sleep_mock.await_args_list if call.args]
        total_slept = sum(float(arg) for arg in sleep_args if isinstance(arg, (int, float)) and float(arg) > 0)
        self.assertGreaterEqual(total_slept, 7.0, msg=f"Expected ~7s of backoff. Got: {total_slept!r} from {sleep_args!r}")


if __name__ == "__main__":
    unittest.main()
