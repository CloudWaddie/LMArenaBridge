import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStream403RecaptchaRetries(BaseBridgeTest):
    async def test_stream_403_recaptcha_validation_failed_retries_with_fresh_token(self) -> None:
        stream_calls: dict[str, int] = {"count": 0}
        payload_tokens: list[str] = []

        def fake_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            stream_calls["count"] += 1
            if isinstance(json, dict) and "recaptchaV3Token" in json:
                payload_tokens.append(str(json.get("recaptchaV3Token")))
            if stream_calls["count"] == 1:
                return FakeStreamContext(
                    FakeStreamResponse(
                        status_code=403,
                        headers={},
                        text='{"error":"recaptcha validation failed"}',
                    )
                )
            return FakeStreamContext(
                FakeStreamResponse(
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
