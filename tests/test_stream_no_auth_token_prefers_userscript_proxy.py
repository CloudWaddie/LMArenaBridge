import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestStreamNoAuthTokenPrefersUserscriptProxy(BaseBridgeTest):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.setup_config(
            {
                "auth_token": "",
                "auth_tokens": [],
                "persist_arena_auth_cookie": False,
                "browser_cookies": {},
            }
        )
        self.main.EPHEMERAL_ARENA_AUTH_TOKEN = None

    async def test_stream_no_auth_token_uses_userscript_proxy_when_active(self) -> None:
        proxy_calls: dict[str, int] = {"count": 0}

        orig_proxy = self.main.fetch_lmarena_stream_via_userscript_proxy

        async def _proxy_stream(*args, **kwargs):  # noqa: ANN001
            proxy_calls["count"] += 1
            resp = await orig_proxy(*args, **kwargs)
            self.assertIsNotNone(resp)

            job_id = str(resp.job_id)
            job = self.main._USERSCRIPT_PROXY_JOBS.get(job_id)
            self.assertIsInstance(job, dict)

            picked = job.get("picked_up_event")
            if isinstance(picked, asyncio.Event) and not picked.is_set():
                picked.set()
            job["phase"] = "fetch"
            job["picked_up_at_monotonic"] = float(self.main.time.monotonic())
            job["upstream_started_at_monotonic"] = float(self.main.time.monotonic())
            job["upstream_fetch_started_at_monotonic"] = float(self.main.time.monotonic())
            job["status_code"] = 200
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()

            q = job.get("lines_queue")
            if isinstance(q, asyncio.Queue):
                await q.put('a0:"Hello"')
                await q.put('ad:{"finishReason":"stop"}')
                await q.put(None)

            job["done"] = True
            done_event = job.get("done_event")
            if isinstance(done_event, asyncio.Event):
                done_event.set()

            return resp

        proxy_mock = AsyncMock(side_effect=_proxy_stream)

        async def _fail_if_chrome_called(*args, **kwargs):  # noqa: ANN001,ARG001
            raise AssertionError("Chrome fetch should not be used when userscript proxy is active")

        chrome_mock = AsyncMock(side_effect=_fail_if_chrome_called)

        def _fail_if_httpx_stream_called(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError("httpx.AsyncClient.stream should not be called when proxy is active")

        with (
            patch.object(self.main, "get_models") as get_models_mock,
            patch.object(self.main, "fetch_lmarena_stream_via_userscript_proxy", proxy_mock),
            patch.object(self.main, "fetch_lmarena_stream_via_chrome", chrome_mock),
            patch.object(httpx.AsyncClient, "stream", new=_fail_if_httpx_stream_called),
            patch("src.main.print"),
        ):
            # Mark proxy as active so proxy-first routing is taken.
            self.main._touch_userscript_poll()

            get_models_mock.return_value = [
                {
                    "publicName": "claude-3-opus",
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
                        "model": "claude-3-opus",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        self.assertGreaterEqual(proxy_calls["count"], 1)


if __name__ == "__main__":
    unittest.main()

