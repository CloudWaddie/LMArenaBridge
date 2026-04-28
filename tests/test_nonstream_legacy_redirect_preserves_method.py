import json
from unittest.mock import AsyncMock, patch

import httpx
import requests

from tests._stream_test_utils import BaseBridgeTest


class _FakeHeaders(dict):
    def get(self, key, default=None):  # noqa: ANN001
        for existing_key, value in self.items():
            if str(existing_key).lower() == str(key).lower():
                return value
        return default


class _FakeRequestsResponse:
    def __init__(self, status_code: int, url: str, text: str = "", headers: dict | None = None) -> None:
        self.status_code = int(status_code)
        self.url = url
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = _FakeHeaders(headers or {})

    def json(self):
        return json.loads(self.text or "{}")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"{self.status_code} Client Error",
                response=self,
            )


class TestNonstreamLegacyRedirectPreservesMethod(BaseBridgeTest):
    async def test_create_evaluation_replays_legacy_redirect_as_post(self) -> None:
        calls: list[dict] = []

        class _FakeScraper:
            def post(self, url, **kwargs):  # noqa: ANN001
                calls.append({"method": "POST", "url": url, **kwargs})
                if str(url).startswith("https://lmarena.ai"):
                    if kwargs.get("allow_redirects") is not False:
                        return _FakeRequestsResponse(
                            405,
                            "https://arena.ai/nextjs-api/stream/create-evaluation",
                        )
                    return _FakeRequestsResponse(
                        301,
                        str(url),
                        headers={"Location": "https://arena.ai/nextjs-api/stream/create-evaluation"},
                    )
                return _FakeRequestsResponse(
                    200,
                    str(url),
                    'a0:"Hello"\nad:{"finishReason":"stop"}\n',
                )

            def put(self, url, **kwargs):  # noqa: ANN001
                calls.append({"method": "PUT", "url": url, **kwargs})
                raise AssertionError("new conversation should use POST")

        with (
            patch.object(self.main, "ARENA_ORIGIN", "https://lmarena.ai"),
            patch.object(self.main, "_canonicalize_arena_url", side_effect=lambda value: value),
            patch.object(self.main, "get_models") as get_models_mock,
            patch.object(self.main, "refresh_recaptcha_token", AsyncMock(return_value="recaptcha-token")),
            patch("cloudscraper.create_scraper", return_value=_FakeScraper()),
            patch("src.main.print"),
            patch("src.main.asyncio.sleep", AsyncMock()),
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "test-model",
                    "id": "model-id",
                    "organization": "test-org",
                    "capabilities": {
                        "inputCapabilities": {"text": True},
                        "outputCapabilities": {},
                    },
                }
            ]

            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": False,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("choices", body, body)
        self.assertEqual(body["choices"][0]["message"]["content"], "Hello")
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[0]["method"], "POST")
        self.assertTrue(str(calls[0]["url"]).startswith("https://lmarena.ai"))
        self.assertIs(calls[0].get("allow_redirects"), False)
        self.assertEqual(calls[1]["method"], "POST")
        self.assertEqual(calls[1]["url"], "https://arena.ai/nextjs-api/stream/create-evaluation")
        self.assertIs(calls[1].get("allow_redirects"), False)
        self.assertIn('"modelAId": "model-id"', calls[1].get("data", ""))
