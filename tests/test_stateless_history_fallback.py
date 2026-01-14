import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStatelessHistoryFallback(BaseBridgeTest):
    async def test_stream_missing_session_includes_history_in_prompt(self) -> None:
        """
        When the bridge has no in-memory session (e.g. after restart) but the client sends a full messages[]
        transcript, the bridge should include that history in the outbound prompt so the model can answer
        consistently.
        """

        token = "test-token-123"
        captured_payloads: list[dict] = []

        jobs = self.main._USERSCRIPT_PROXY_JOBS
        original_jobs = dict(jobs)
        jobs.clear()

        ctx = FakeStreamContext(
            FakeStreamResponse(
                status_code=200,
                headers={},
                text='a0:"OK"\nad:{"finishReason":"stop"}\n',
            )
        )
        ctx.job_id = "job-200"
        jobs[ctx.job_id] = {
            "status_code": 200,
            "headers": {},
            "status_event": asyncio.Event(),
        }
        jobs[ctx.job_id]["status_event"].set()

        async def proxy_side_effect(*, payload=None, **kwargs):  # noqa: ANN001
            if isinstance(payload, dict):
                captured_payloads.append(payload)
            return ctx

        try:
            with patch.object(self.main, "get_models") as get_models_mock, patch.object(
                self.main,
                "_userscript_proxy_is_active",
                return_value=True,
            ), patch.object(
                self.main,
                "fetch_via_proxy_queue",
                AsyncMock(side_effect=proxy_side_effect),
            ), patch(
                "src.main.print",
            ):
                get_models_mock.return_value = [
                    {
                        "publicName": "test-chat-model",
                        "id": "model-id",
                        "organization": "test-org",
                        "capabilities": {
                            "inputCapabilities": {"text": True},
                            "outputCapabilities": {"text": True},
                        },
                    }
                ]

                # Simulate bridge restart: no in-memory sessions.
                self.main.chat_sessions.clear()

                transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.post(
                        "/api/v1/chat/completions",
                        headers={"Authorization": "Bearer test-key"},
                        json={
                            "model": "test-chat-model",
                            "messages": [
                                {"role": "user", "content": f"Memory test. Token: {token}. Reply OK only."},
                                {"role": "assistant", "content": "OK"},
                                {"role": "user", "content": "What token did I give you earlier? Reply token only."},
                            ],
                            "stream": True,
                        },
                        timeout=30.0,
                    )
        finally:
            jobs.clear()
            jobs.update(original_jobs)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(captured_payloads, "Expected an outbound LMArena payload to be captured")
        user_message = (captured_payloads[0].get("userMessage") or {}).get("content") or ""
        self.assertIn(token, str(user_message))


if __name__ == "__main__":
    unittest.main()
