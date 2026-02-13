import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStream301RedirectRetriesViaUserscriptProxy(BaseBridgeTest):
    async def test_non_strict_redirect_retries_via_userscript_proxy(self) -> None:
        stream_calls: dict[str, int] = {"count": 0}
        bridge = self.main

        def fake_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            stream_calls["count"] += 1
            if stream_calls["count"] == 1:
                # Simulate the proxy becoming available after the initial redirect response.
                bridge._touch_userscript_poll()
                return FakeStreamContext(
                    FakeStreamResponse(
                        status_code=301,
                        headers={"Location": "https://arena.ai/nextjs-api/stream/create-evaluation"},
                        text="",
                    )
                )
            raise AssertionError("httpx stream should not be used after redirect when userscript proxy is active")

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
        sleep_mock = AsyncMock()

        chrome_mock = AsyncMock(side_effect=AssertionError("Chrome fetch should not be used when userscript proxy is active"))
        camoufox_mock = AsyncMock(
            side_effect=AssertionError("Camoufox fetch should not be used when userscript proxy is active")
        )

        with (
            patch.object(self.main, "get_models") as get_models_mock,
            patch.object(self.main, "refresh_recaptcha_token", AsyncMock(return_value="recaptcha-token")),
            patch.object(self.main, "fetch_lmarena_stream_via_userscript_proxy", proxy_mock),
            patch.object(self.main, "fetch_lmarena_stream_via_chrome", chrome_mock),
            patch.object(self.main, "fetch_lmarena_stream_via_camoufox", camoufox_mock),
            patch.object(httpx.AsyncClient, "stream", new=fake_stream),
            patch("src.main.print"),
            patch("src.main.asyncio.sleep", sleep_mock),
        ):
            get_models_mock.return_value = [
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

            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={
                        "model": "test-search-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        self.assertEqual(stream_calls["count"], 1)
        self.assertGreaterEqual(proxy_calls["count"], 1)


if __name__ == "__main__":
    unittest.main()

