import unittest

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestApiKeyEnforcement(BaseBridgeTest):
    """A configured API key list must not be bypassed by omitting the Authorization header."""

    async def test_request_without_key_is_rejected_when_keys_are_configured(self) -> None:
        transport = httpx.ASGITransport(app=self.main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/models")
        self.assertEqual(response.status_code, 401)

    async def test_request_with_unknown_key_is_rejected(self) -> None:
        transport = httpx.ASGITransport(app=self.main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/models", headers={"Authorization": "Bearer not-a-real-key"}
            )
        self.assertEqual(response.status_code, 401)

    async def test_request_with_configured_key_is_allowed(self) -> None:
        transport = httpx.ASGITransport(app=self.main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/models", headers={"Authorization": "Bearer test-key"}
            )
        self.assertEqual(response.status_code, 200)

    async def test_anonymous_access_allowed_when_no_keys_configured(self) -> None:
        self.setup_config({"api_keys": []})
        transport = httpx.ASGITransport(app=self.main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/models")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
