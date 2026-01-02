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

    async def aread(self) -> bytes:
        return (self._text or "").encode("utf-8")

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


class TestStream403RecaptchaRetries(unittest.IsolatedAsyncioTestCase):
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

    async def test_stream_403_recaptcha_validation_failed_retries_with_fresh_token(self) -> None:
        stream_calls: dict[str, int] = {"count": 0}
        payload_tokens: list[str] = []

        def fake_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            stream_calls["count"] += 1
            if isinstance(json, dict) and "recaptchaV3Token" in json:
                payload_tokens.append(str(json.get("recaptchaV3Token")))
            if stream_calls["count"] == 1:
                return _FakeStreamContext(
                    _FakeStreamResponse(
                        status_code=403,
                        headers={},
                        text='{"error":"recaptcha validation failed"}',
                    )
                )
            return _FakeStreamContext(
                _FakeStreamResponse(
                    status_code=200,
                    headers={},
                    text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
                )
            )

        refresh_mock = AsyncMock(side_effect=["recaptcha-1", "recaptcha-2"])
        sleep_mock = AsyncMock()

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "refresh_recaptcha_token",
            refresh_mock,
        ), patch.object(
            httpx.AsyncClient,
            "stream",
            new=fake_stream,
        ), patch(
            "src.main.print",
        ), patch(
            "src.main.asyncio.sleep",
            sleep_mock,
        ):
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

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        self.assertGreaterEqual(stream_calls["count"], 2)
        self.assertGreaterEqual(len(payload_tokens), 2)
        self.assertEqual(payload_tokens[0], "recaptcha-1")
        self.assertEqual(payload_tokens[1], "recaptcha-2")
        self.assertGreaterEqual(refresh_mock.await_count, 2)
        first_call = refresh_mock.await_args_list[0]
        self.assertTrue(first_call.kwargs.get("force_new"), first_call)
        sleep_mock.assert_awaited()


if __name__ == "__main__":
    unittest.main()
