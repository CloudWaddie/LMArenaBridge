import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStreamWebModelsUseUserscriptProxy(BaseBridgeTest):
    async def test_stream_web_capability_model_prefers_userscript_proxy(self) -> None:
        proxy_resp = FakeStreamContext(
            FakeStreamResponse(
                status_code=200,
                headers={},
                text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
            )
        )

        proxy_mock = AsyncMock(return_value=proxy_resp)
        refresh_mock = AsyncMock()

        def fail_httpx_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError("direct httpx streaming should not run")

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
            httpx.AsyncClient,
            "stream",
            new=fail_httpx_stream,
        ), patch(
            "src.main.print",
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "test-web-model",
                    "id": "model-id",
                    "organization": "test-org",
                    "capabilities": {
                        "inputCapabilities": {"text": True},
                        "outputCapabilities": {"text": True, "web": True},
                    },
                }
            ]

            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-web-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        self.assertEqual(refresh_mock.await_count, 0)
        proxy_mock.assert_awaited()

    async def test_stream_text_model_prefers_userscript_proxy(self) -> None:
        proxy_resp = FakeStreamContext(
            FakeStreamResponse(
                status_code=200,
                headers={},
                text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
            )
        )

        proxy_mock = AsyncMock(return_value=proxy_resp)
        refresh_mock = AsyncMock()

        def fail_httpx_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError("direct httpx streaming should not run")

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
            httpx.AsyncClient,
            "stream",
            new=fail_httpx_stream,
        ), patch(
            "src.main.print",
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "test-text-model",
                    "id": "model-id",
                    "organization": "test-org",
                    "capabilities": {
                        "inputCapabilities": {"text": True},
                        "outputCapabilities": {"text": True},
                    },
                }
            ]

            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-text-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        self.assertEqual(refresh_mock.await_count, 0)
        proxy_mock.assert_awaited()


if __name__ == "__main__":
    unittest.main()
