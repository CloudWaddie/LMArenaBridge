import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamResponse


class TestChatCompletionsNonStreamParsing(BaseBridgeTest):
    async def test_non_stream_parses_reasoning_and_citations(self) -> None:
        citation_args = {"source": [{"url": "https://example.com", "title": "Example"}]}
        citation_obj = {"argsTextDelta": json.dumps(citation_args)}

        upstream_text = "\n".join(
            [
                'ag:"Think"',
                'a0:"Hello"',
                f'ac:{json.dumps(citation_obj)}',
                'ad:{"finishReason":"stop"}',
                "",
            ]
        )

        response_obj = FakeStreamResponse(status_code=200, headers={}, text=upstream_text)

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "_userscript_proxy_is_active",
            return_value=True,
        ), patch.object(
            self.main,
            "fetch_via_proxy_queue",
            AsyncMock(return_value=response_obj),
        ), patch.object(self.main.uuid, "uuid4", return_value=self.main.uuid.UUID(int=0)), patch.object(
            self.main.time, "time", return_value=1234567890.0
        ), patch(
            "src.main.print",
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "test-chat-model",
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
                        "model": "test-chat-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": False,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        message = (body.get("choices") or [{}])[0].get("message") or {}
        self.assertIn("Hello", str(message.get("content") or ""))
        self.assertEqual(str(message.get("reasoning_content") or ""), "Think")
        citations = message.get("citations") or []
        self.assertTrue(isinstance(citations, list) and citations, citations)
        self.assertIn("Sources:", str(message.get("content") or ""))

    async def test_non_stream_a3_error_becomes_openai_error_payload(self) -> None:
        upstream_text = "\n".join(['a3:\"boom\"', 'ad:{"finishReason":"stop"}', ""])
        response_obj = FakeStreamResponse(status_code=200, headers={}, text=upstream_text)

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "_userscript_proxy_is_active",
            return_value=True,
        ), patch.object(
            self.main,
            "fetch_via_proxy_queue",
            AsyncMock(return_value=response_obj),
        ), patch(
            "src.main.print",
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "test-chat-model",
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
                        "model": "test-chat-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": False,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        err = body.get("error") or {}
        self.assertIn("boom", str(err.get("message") or ""))


if __name__ == "__main__":
    unittest.main()

