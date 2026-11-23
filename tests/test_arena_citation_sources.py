import json
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestArenaCitationSources(BaseBridgeTest):
    async def _complete_with_citations(self, *, stream: bool):
        ignored_source = {"title": "Not a citation", "url": "https://example.com/ignored"}
        sources = [
            {"title": "One", "url": "https://example.com/one"},
            {"title": "Two", "url": "https://example.com/two"},
        ]

        def tool_delta(tool_call_id, args):
            return "ac:" + json.dumps({"toolCallId": tool_call_id, "argsTextDelta": args})

        body = "\n".join(
            [
                'a0:"Hello"',
                tool_delta("other-tool", json.dumps({"source": ignored_source})),
                tool_delta("citation-source", None),
                tool_delta("citation-source", "{"),
                tool_delta("citation-source", json.dumps({"source": sources[0]})),
                tool_delta("citation-source", json.dumps({"source": [None, *sources]})),
                'ad:{"finishReason":"stop"}',
            ]
        )
        models = [
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
        upstream = FakeStreamResponse(status_code=200, text=body)

        with (
            patch.object(self.main, "get_models", return_value=models),
            patch.object(self.main, "refresh_recaptcha_token", AsyncMock(return_value="test-token")),
            patch.object(httpx.AsyncClient, "stream", return_value=FakeStreamContext(upstream)),
            patch("cloudscraper.create_scraper") as create_scraper,
        ):
            create_scraper.return_value.post.return_value = upstream
            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-search-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": stream,
                    },
                )

        self.assertEqual(response.status_code, 200)
        sessions = self.main.chat_sessions["test-key"]
        self.assertEqual(len(sessions), 1)
        assistant = next(iter(sessions.values()))["messages"][-1]
        self.assertEqual(assistant["citations"], sources)
        return response, sources

    async def test_streaming_stores_only_citation_source_deltas(self):
        response, _ = await self._complete_with_citations(stream=True)
        self.assertIn('"content": "Hello"', response.text)
        self.assertIn("data: [DONE]", response.text)

    async def test_buffered_completion_only_displays_citation_source_deltas(self):
        response, sources = await self._complete_with_citations(stream=False)
        message = response.json()["choices"][0]["message"]
        self.assertEqual(message["citations"], sources)
        self.assertIn("[One](https://example.com/one)", message["content"])
        self.assertNotIn("https://example.com/ignored", message["content"])
