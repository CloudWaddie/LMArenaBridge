import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStrictModelsForceChromeFetch(BaseBridgeTest):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.setup_config({"chrome_fetch_recaptcha_max_attempts": 6})

    async def test_gemini_grounding_stream_uses_userscript_proxy(self) -> None:
        proxy_resp = FakeStreamContext(
            FakeStreamResponse(
                status_code=200,
                headers={},
                text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
            )
        )

        proxy_mock = AsyncMock(return_value=proxy_resp)
        refresh_mock = AsyncMock()
        chrome_fetch_mock = AsyncMock()

        def fail_if_httpx_stream_called(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError("httpx.AsyncClient.stream should not be called when proxy is active")

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "_userscript_proxy_is_active",
            return_value=True,
        ), patch.object(
            self.main,
            "fetch_via_proxy_queue",
            proxy_mock,
        ), patch.object(
            self.main,
            "refresh_recaptcha_token",
            refresh_mock,
        ), patch.object(
            self.main,
            "fetch_lmarena_stream_via_chrome",
            chrome_fetch_mock,
        ), patch.object(
            httpx.AsyncClient,
            "stream",
            new=fail_if_httpx_stream_called,
        ), patch(
            "src.main.print",
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "gemini-3-pro-grounding",
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
                        "model": "gemini-3-pro-grounding",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        proxy_mock.assert_awaited()
        chrome_fetch_mock.assert_not_awaited()
        self.assertEqual(refresh_mock.await_count, 0)


if __name__ == "__main__":
    unittest.main()
