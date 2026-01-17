import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStream429RespectsRetryAfter(BaseBridgeTest):
    async def test_stream_429_waits_retry_after_seconds(self) -> None:
        proxy_calls: dict[str, int] = {"count": 0}

        sleep_mock = AsyncMock()

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "_userscript_proxy_is_active",
            return_value=True,
        ), patch.object(
            self.main,
            "refresh_recaptcha_token",
            AsyncMock(),
        ), patch("src.main.asyncio.sleep", sleep_mock), patch("src.main.time.time") as time_mock:
            # Make keepalive/backoff deterministic and fast by advancing a mocked clock when sleep() is awaited.
            now = [1000.0]

            def _time() -> float:
                return now[0]

            async def _sleep(seconds: float) -> None:
                try:
                    now[0] += float(seconds)
                except Exception:
                    now[0] += 0.0
                return None

            time_mock.side_effect = _time
            sleep_mock.side_effect = _sleep
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

            jobs = self.main._USERSCRIPT_PROXY_JOBS
            original_jobs = dict(jobs)
            jobs.clear()

            first_ctx = FakeStreamContext(
                FakeStreamResponse(
                    status_code=200,
                    headers={},
                    text='{"error":"Too Many Requests","message":"Too Many Requests"}',
                )
            )
            first_ctx.job_id = "job-429"
            jobs[first_ctx.job_id] = {
                "status_code": 429,
                "headers": {"Retry-After": "7"},
                "status_event": asyncio.Event(),
            }
            jobs[first_ctx.job_id]["status_event"].set()

            second_ctx = FakeStreamContext(
                FakeStreamResponse(
                    status_code=200,
                    headers={},
                    text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
                )
            )
            second_ctx.job_id = "job-200"
            jobs[second_ctx.job_id] = {
                "status_code": 200,
                "headers": {},
                "status_event": asyncio.Event(),
            }
            jobs[second_ctx.job_id]["status_event"].set()

            async def proxy_side_effect(**kwargs):  # noqa: ANN001
                proxy_calls["count"] += 1
                return first_ctx if proxy_calls["count"] == 1 else second_ctx

            proxy_mock = AsyncMock(side_effect=proxy_side_effect)

            transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
            try:
                with patch.object(self.main, "fetch_via_proxy_queue", proxy_mock), patch("src.main.print"):
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
                        body_text = response.text
            finally:
                jobs.clear()
                jobs.update(original_jobs)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", body_text)
        self.assertIn("[DONE]", body_text)
        self.assertGreaterEqual(proxy_calls["count"], 2)
        sleep_args = [call.args[0] for call in sleep_mock.await_args_list if call.args]
        total_slept = sum(float(arg) for arg in sleep_args if isinstance(arg, (int, float)) and float(arg) > 0)
        self.assertGreaterEqual(total_slept, 7.0, msg=f"Expected ~7s of backoff. Got: {total_slept!r} from {sleep_args!r}")


if __name__ == "__main__":
    unittest.main()
