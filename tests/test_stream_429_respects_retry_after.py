import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStream429RespectsRetryAfter(BaseBridgeTest):
    async def test_stream_429_waits_retry_after_seconds(self) -> None:
        stream_calls: dict[str, int] = {"count": 0}

        def fake_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            stream_calls["count"] += 1
            if stream_calls["count"] == 1:
                return FakeStreamContext(
                    FakeStreamResponse(
                        status_code=429,
                        headers={"Retry-After": "7"},
                        text='{"error":"Too Many Requests","message":"Too Many Requests"}',
                    )
                )
            return FakeStreamContext(
                FakeStreamResponse(
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
