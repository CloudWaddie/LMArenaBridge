import unittest
from unittest.mock import patch

import httpx

from src import main


class TestPublicModelCatalog(unittest.IsolatedAsyncioTestCase):
    async def test_initial_refresh_uses_public_catalog_even_without_browser(self):
        def handle(request):
            self.assertEqual(request.method, "GET")
            self.assertEqual(str(request.url), "https://arena.ai/nextjs-api/model-catalog")
            self.assertNotIn("cookie", request.headers)
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(
                200,
                json=[
                    {
                        "arena": "document",
                        "models": [{"id": "a", "publicName": "model-a", "rank": 4}],
                    },
                    {"arena": "text", "models": [{"id": "a", "rank": 2}]},
                    {"arena": "search", "models": [{"id": "a", "rank": 5}]},
                    {"arena": "text-to-image", "models": [{"id": "b"}]},
                ],
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        with (
            patch.object(main.httpx, "AsyncClient", return_value=client),
            patch.object(main, "AsyncCamoufox", side_effect=RuntimeError("browser unavailable")),
            patch.object(main, "save_models") as save_models,
        ):
            await main.get_initial_data()

        save_models.assert_called_once_with(
            [
                {
                    "id": "a",
                    "publicName": "model-a",
                    "rank": 4,
                    "rankByModality": {"chat": 2, "search": 5},
                },
                {"id": "b", "rankByModality": {"image": 2**53 - 1}},
            ]
        )

    async def test_failed_or_incomplete_catalog_leaves_cache_intact(self):
        responses = [
            httpx.Response(429),
            httpx.Response(200, json=[]),
            httpx.Response(
                200,
                json=[
                    {"arena": "text", "models": [{"id": "a"}], "complete": True},
                    {"arena": "search", "models": [{"id": "b"}], "complete": False},
                ],
            ),
        ]
        for response in responses:
            with self.subTest(status=response.status_code, body=response.text):
                client = httpx.AsyncClient(
                    transport=httpx.MockTransport(lambda request: response)
                )
                with (
                    patch.object(main.httpx, "AsyncClient", return_value=client),
                    patch.object(main, "save_models") as save_models,
                ):
                    await main._refresh_public_model_catalog()
                save_models.assert_not_called()
