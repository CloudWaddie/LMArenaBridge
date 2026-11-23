import unittest
from unittest.mock import patch

from src import constants
from src import main
from src import state as _state_module
from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class _FakeHttpxResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise main.httpx.HTTPStatusError("err", request=None, response=None)

    def json(self):
        return self._json_data


class TestArenaParityStorageAndMedia(BaseBridgeTest):
    def setUp(self):
        super().setUp()
        _state_module.IMAGES_CACHE.clear()

    def test_recaptcha_sitekeys_match_live_arena_bundle(self):
        self.assertEqual(constants.RECAPTCHA_SITEKEY, "6LeTGMcsAAAAALuIlkVwIxaAuZA8VledA6d3Nnb0")
        self.assertEqual(constants.RECAPTCHA_V2_SITEKEY, "6Le3_cYsAAAAAGwWOK2RLDgNI15Bh8C0yLBOL1yL")
        self.assertEqual(main.RECAPTCHA_SITEKEY, constants.RECAPTCHA_SITEKEY)
        self.assertEqual(main.RECAPTCHA_V2_SITEKEY, constants.RECAPTCHA_V2_SITEKEY)

    async def test_upload_image_uses_storage_rest_endpoints(self):
        calls = []

        class _FakeAsyncClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, headers=None, json=None, timeout=None):
                calls.append(("POST", url, headers, json))
                if url.endswith("/api/storage/generate-upload-url"):
                    return _FakeHttpxResponse(
                        200,
                        {"uploadUrl": "https://r2.example.invalid/upload", "key": "/uploads/abc.png"},
                    )
                if url.endswith("/api/storage/get-signed-url"):
                    return _FakeHttpxResponse(
                        200,
                        {"url": "https://r2.example.invalid/download/abc.png"},
                    )
                return _FakeHttpxResponse(404, {})

            async def put(self, url, content=None, headers=None, timeout=None):
                calls.append(("PUT", url, headers, content))
                return _FakeHttpxResponse(200)

        with patch.object(main, "get_request_headers", return_value={"Cookie": "arena-auth-prod-v1=tok"}), \
             patch.object(main.httpx, "AsyncClient", _FakeAsyncClient):
            result = await main.upload_image_to_lmarena(b"\x89PNG\r\n\x1a\n", "image/png", "sample.png")

        self.assertEqual(result, ("/uploads/abc.png", "https://r2.example.invalid/download/abc.png"))
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][1], "https://arena.ai/api/storage/generate-upload-url")
        self.assertEqual(calls[0][3], {"fileName": "sample.png", "contentType": "image/png"})
        self.assertEqual(calls[1][0], "PUT")
        self.assertEqual(calls[1][1], "https://r2.example.invalid/upload")
        self.assertEqual(calls[2][0], "POST")
        self.assertEqual(calls[2][1], "https://arena.ai/api/storage/get-signed-url")
        self.assertEqual(calls[2][3], {"key": "uploads/abc.png"})

    def test_extract_arena_media_markdown_variants(self):
        self.assertEqual(
            main._extract_arena_media_markdown('a2:[{"type":"image","image":"https://img.example/a.png"}]'),
            "![Generated Image](https://img.example/a.png)",
        )
        self.assertEqual(
            main._extract_arena_media_markdown('a2:[{"type":"image","data":"AAAA","mimeType":"image/webp"}]'),
            "![Generated Image](data:image/webp;base64,AAAA)",
        )
        self.assertEqual(
            main._extract_arena_media_markdown('a2:[{"type":"video","url":"https://vid.example/v.mp4"}]'),
            "![Generated Video](https://vid.example/v.mp4)",
        )
        self.assertEqual(
            main._extract_arena_media_markdown('ak:{"data":"BBBB","mimeType":"image/png"}'),
            "![Generated Image](data:image/png;base64,BBBB)",
        )
        self.assertEqual(
            main._extract_arena_media_markdown('ak:{"data":"CCCC","mimeType":"application/pdf"}'),
            "",
        )

    async def test_non_streaming_parses_ak_base64_image_part(self):
        fake_resp = FakeStreamResponse(
            status_code=200,
            text='ak:{"data":"iVBORw0KGgo=","mimeType":"image/png"}\nad:{"finishReason":"stop"}\n',
        )
        models = [{
            "publicName": "test-image-model",
            "id": "img-1",
            "organization": "test-org",
            "capabilities": {"outputCapabilities": {"image": True}},
        }]

        with patch.object(self.main, "get_models", return_value=models), \
             patch.object(self.main, "refresh_recaptcha_token", unittest.mock.AsyncMock(return_value="rc-tok")), \
             patch.object(main.httpx.AsyncClient, "stream", return_value=FakeStreamContext(fake_resp)), \
             patch("cloudscraper.create_scraper") as create_scraper:
            create_scraper.return_value.post.return_value = fake_resp
            transport = main.httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with main.httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-image-model",
                        "messages": [{"role": "user", "content": "draw a cat"}],
                        "stream": False,
                    },
                )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(
            body["choices"][0]["message"]["content"],
            "![Generated Image](data:image/png;base64,iVBORw0KGgo=)",
        )


if __name__ == "__main__":
    unittest.main()
