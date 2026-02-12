import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestStreamUserscriptProxyFetchPreflightTimerResetsAfterSignup(BaseBridgeTest):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        # Repro: signup phase exceeds preflight timeout (5s), then phase switches to fetch and the upstream fetch
        # begins 3s later. The server should measure fetch-phase preflight from upstream_started_at_monotonic rather
        # than pickup time to avoid an immediate fallback.
        self.setup_config(
            {
                "userscript_proxy_status_timeout_seconds": 5,
                "userscript_proxy_pickup_timeout_seconds": 10,
                "userscript_proxy_preflight_timeout_seconds": 5,
                "userscript_proxy_signup_preflight_timeout_seconds": 20,
            }
        )

    async def test_fetch_phase_preflight_does_not_include_signup_time(self) -> None:
        sleep_mock = AsyncMock()
        clock = [1000.0]
        real_sleep = asyncio.sleep

        def _now() -> float:
            return float(clock[0])

        async def _sleep(seconds: float) -> None:
            try:
                clock[0] += float(seconds)
            except Exception:
                pass
            # Yield control so background tasks (proxy simulation) can run deterministically.
            await real_sleep(0)
            return None

        sleep_mock.side_effect = _sleep

        proxy_calls: dict[str, int] = {"count": 0}
        chrome_calls: dict[str, int] = {"count": 0}
        camoufox_calls: dict[str, int] = {"count": 0}

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

            job["picked_up_at_monotonic"] = float(self.main.time.monotonic())
            job["phase"] = "signup"
            job["upstream_started_at_monotonic"] = None
            job["upstream_fetch_started_at_monotonic"] = None

            async def _simulate_signup_then_fetch_then_stream() -> None:
                signup_started_at = float(self.main.time.monotonic())
                # Signup lasts 8 seconds (longer than userscript_proxy_preflight_timeout_seconds=5).
                while float(self.main.time.monotonic()) < (signup_started_at + 8.0):
                    await asyncio.sleep(0)

                # Switch to fetch phase and record the fetch-phase start marker.
                job["phase"] = "fetch"
                job["upstream_started_at_monotonic"] = float(self.main.time.monotonic())
                job["upstream_fetch_started_at_monotonic"] = None

                fetch_phase_started_at = float(self.main.time.monotonic())
                # Upstream fetch starts 3 seconds after fetch phase begins.
                while float(self.main.time.monotonic()) < (fetch_phase_started_at + 3.0):
                    await asyncio.sleep(0)

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

            asyncio.create_task(_simulate_signup_then_fetch_then_stream())
            return resp

        proxy_mock = AsyncMock(side_effect=_proxy_stream)

        async def _chrome_stream(*args, **kwargs):  # noqa: ANN001
            chrome_calls["count"] += 1
            raise AssertionError("Chrome fetch should not be called when proxy completes after signup+fetch delay")

        chrome_mock = AsyncMock(side_effect=_chrome_stream)

        async def _camoufox_stream(*args, **kwargs):  # noqa: ANN001
            camoufox_calls["count"] += 1
            raise AssertionError("Camoufox fetch should not be called when proxy completes after signup+fetch delay")

        camoufox_mock = AsyncMock(side_effect=_camoufox_stream)

        def _fail_if_httpx_stream_called(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError(
                "httpx.AsyncClient.stream should not be called when userscript proxy completes successfully"
            )

        with (
            patch.object(self.main, "get_models") as get_models_mock,
            patch.object(self.main, "refresh_recaptcha_token", AsyncMock(return_value="recaptcha-token")),
            patch.object(self.main, "fetch_lmarena_stream_via_userscript_proxy", proxy_mock),
            patch.object(self.main, "fetch_lmarena_stream_via_chrome", chrome_mock),
            patch.object(self.main, "fetch_lmarena_stream_via_camoufox", camoufox_mock),
            patch.object(httpx.AsyncClient, "stream", new=_fail_if_httpx_stream_called),
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
        self.assertEqual(chrome_calls["count"], 0)
        self.assertEqual(camoufox_calls["count"], 0)


if __name__ == "__main__":
    unittest.main()

