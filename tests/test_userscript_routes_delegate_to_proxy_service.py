import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestUserscriptRoutesDelegateToProxyService(BaseBridgeTest):
    async def test_userscript_poll_delegates_to_proxy_service(self) -> None:
        poll_mock = AsyncMock(return_value=None)

        with patch.object(self.main._PROXY_SERVICE, "poll_next_job", poll_mock):
            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/userscript/poll",
                    json={"timeout_seconds": 0},
                    timeout=10.0,
                )

        self.assertEqual(resp.status_code, 204)
        poll_mock.assert_awaited()

    async def test_userscript_push_delegates_to_proxy_service(self) -> None:
        push_mock = AsyncMock(return_value=False)

        with patch.object(self.main._PROXY_SERVICE, "push_job_update", push_mock):
            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/userscript/push",
                    json={"job_id": "unknown-job", "done": True},
                    timeout=10.0,
                )

        self.assertEqual(resp.status_code, 404)
        push_mock.assert_awaited()


if __name__ == "__main__":
    unittest.main()

