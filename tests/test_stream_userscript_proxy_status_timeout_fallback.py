import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestStreamUserscriptProxyStatusTimeoutFallback(BaseBridgeTest):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        # Keep the proxy timeout small so the test exercises the fallback path quickly.
        self.setup_config(
            {
                "userscript_proxy_status_timeout_seconds": 5,
                "userscript_proxy_pickup_timeout_seconds": 10,
            }
        )

    async def test_stream_proxy_status_timeout_falls_back_to_chrome_fetch(self) -> None:
        sleep_mock = AsyncMock()
        clock = [1000.0]

        def _now() -> float:
            return float(clock[0])

        async def _sleep(seconds: float) -> None:
            try:
                clock[0] += float(seconds)
            except Exception:
                pass
            return None

        sleep_mock.side_effect = _sleep

        proxy_calls: dict[str, int] = {"count": 0}
        chrome_calls: dict[str, int] = {"count": 0}

        orig_proxy = self.main.fetch_lmarena_stream_via_userscript_proxy

        async def _proxy_stream(*args, **kwargs):  # noqa: ANN001
            proxy_calls["count"] += 1
            resp = await orig_proxy(*args, **kwargs)
            self.assertIsNotNone(resp)
            job = self.main._USERSCRIPT_PROXY_JOBS.get(str(resp.job_id))
            if isinstance(job, dict):
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
                # Simulate the proxy starting the upstream fetch, but never reporting status.
                # The bridge should trigger the *status* timeout (not preflight) and fall back to Chrome.
                job["phase"] = "fetch"
                job["picked_up_at_monotonic"] = float(self.main.time.monotonic())
                job["upstream_started_at_monotonic"] = float(self.main.time.monotonic())
                job["upstream_fetch_started_at_monotonic"] = float(self.main.time.monotonic())
            return resp

        proxy_mock = AsyncMock(side_effect=_proxy_stream)

        chrome_resp = self.main.BrowserFetchStreamResponse(
            status_code=200,
            headers={},
            text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
            method="POST",
            url="https://lmarena.ai/nextjs-api/stream/create-evaluation",
        )

        async def _chrome_stream(*args, **kwargs):  # noqa: ANN001
            chrome_calls["count"] += 1
            return chrome_resp

        chrome_mock = AsyncMock(side_effect=_chrome_stream)

        with (
            patch.object(self.main, "get_models") as get_models_mock,
            patch.object(self.main, "refresh_recaptcha_token", AsyncMock(return_value="recaptcha-token")),
            patch.object(self.main, "fetch_lmarena_stream_via_userscript_proxy", proxy_mock),
            patch.object(self.main, "fetch_lmarena_stream_via_chrome", chrome_mock),
            patch("src.main.print"),
            patch("src.main.asyncio.sleep", sleep_mock),
            patch("src.main.time.time") as time_mock,
            patch("src.main.time.monotonic") as mono_mock,
        ):
            time_mock.side_effect = _now
            mono_mock.side_effect = _now

            # Mark proxy as active so strict-model routing prefers it initially.
            self.main._touch_userscript_poll()

            get_models_mock.return_value = [
                {
                    "publicName": "gemini-3-pro-grounding",
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
                        "model": "gemini-3-pro-grounding",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

            self.assertEqual(response.status_code, 200)
            self.assertIn("Hello", response.text)
            self.assertIn("[DONE]", response.text)
            self.assertGreaterEqual(proxy_calls["count"], 1)
            self.assertGreaterEqual(chrome_calls["count"], 1)

            # The timeout path must NOT keep the proxy marked active; otherwise strict-model requests keep routing
            # back into a dead proxy and stall streaming.
            self.assertFalse(self.main._userscript_proxy_is_active(self.main.get_config()))


if __name__ == "__main__":
    unittest.main()

