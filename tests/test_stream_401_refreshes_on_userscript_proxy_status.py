import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamResponse


class FakeUserscriptContext:
    def __init__(self, response: FakeStreamResponse, job_id: str) -> None:
        self._response = response
        self.job_id = str(job_id)

    async def __aenter__(self) -> FakeStreamResponse:
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        return False


class TestStream401RefreshesOnUserscriptProxyStatus(BaseBridgeTest):
    async def test_userscript_proxy_status_401_refreshes_token_before_failing(self) -> None:
        self.setup_config({"auth_tokens": ["base64-expired-session"]})

        job1_id = "job-401"
        job2_id = "job-ok"

        status_event_1 = asyncio.Event()
        status_event_1.set()
        self.main._USERSCRIPT_PROXY_JOBS[job1_id] = {
            "status_code": 401,
            "headers": {},
            "error": "unauthorized",
            "status_event": status_event_1,
            "done_event": asyncio.Event(),
            "picked_up_event": asyncio.Event(),
        }

        status_event_2 = asyncio.Event()
        status_event_2.set()
        self.main._USERSCRIPT_PROXY_JOBS[job2_id] = {
            "status_code": 200,
            "headers": {},
            "error": None,
            "status_event": status_event_2,
            "done_event": asyncio.Event(),
            "picked_up_event": asyncio.Event(),
        }

        proxy_mock = AsyncMock(
            side_effect=[
                FakeUserscriptContext(FakeStreamResponse(status_code=200, text=""), job1_id),
                FakeUserscriptContext(
                    FakeStreamResponse(
                        status_code=200,
                        headers={},
                        text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
                    ),
                    job2_id,
                ),
            ]
        )

        refresh_http_mock = AsyncMock(return_value="base64-refreshed-session")
        refresh_supabase_mock = AsyncMock(return_value=None)

        def fail_httpx_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            raise AssertionError("direct httpx streaming should not run")

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "_userscript_proxy_is_active",
            return_value=True,
        ), patch.object(
            self.main,
            "fetch_via_proxy_queue",
            proxy_mock,
        ), patch.object(
            self.main,
            "refresh_arena_auth_token_via_lmarena_http",
            refresh_http_mock,
        ), patch.object(
            self.main,
            "refresh_arena_auth_token_via_supabase",
            refresh_supabase_mock,
        ), patch.object(
            httpx.AsyncClient,
            "stream",
            new=fail_httpx_stream,
        ), patch(
            "src.main.print",
        ):
            get_models_mock.return_value = [
                {
                    "publicName": "test-text-model",
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
                        "model": "test-text-model",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "stream": True,
                    },
                    timeout=30.0,
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello", response.text)
        self.assertIn("[DONE]", response.text)
        self.assertGreaterEqual(proxy_mock.await_count, 2)
        self.assertGreaterEqual(refresh_http_mock.await_count, 1)


if __name__ == "__main__":
    unittest.main()
