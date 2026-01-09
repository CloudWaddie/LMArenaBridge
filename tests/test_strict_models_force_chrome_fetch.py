import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestStrictModelsForceChromeFetch(BaseBridgeTest):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.setup_config({"chrome_fetch_recaptcha_max_attempts": 6})

    async def test_gemini_grounding_stream_uses_chrome_fetch_first_try(self) -> None:
        refresh_mock = AsyncMock(return_value="recaptcha-1")
        chrome_resp = self.main.BrowserFetchStreamResponse(
            status_code=200,
            headers={},
            text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
            method="POST",
            url="https://lmarena.ai/nextjs-api/stream/create-evaluation",
        )
        chrome_fetch_mock = AsyncMock(return_value=chrome_resp)

        def fail_if_httpx_stream_called(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError("httpx.AsyncClient.stream should not be called for strict models")

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
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
        chrome_fetch_mock.assert_awaited()
        self.assertEqual(chrome_fetch_mock.await_args.kwargs.get("max_recaptcha_attempts"), 6)


if __name__ == "__main__":
    unittest.main()
