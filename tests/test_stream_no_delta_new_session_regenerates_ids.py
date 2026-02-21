import unittest
from unittest.mock import AsyncMock, patch

import httpx

from tests._stream_test_utils import BaseBridgeTest, FakeStreamContext, FakeStreamResponse


class TestStreamNoDeltaNewSessionRegeneratesIds(BaseBridgeTest):
    async def test_new_session_retry_regenerates_ids_after_no_delta(self) -> None:
        payloads: list[dict] = []

        def fake_stream(self, method, url, json=None, headers=None, timeout=None):  # noqa: ARG001
            payload = dict(json or {})
            payloads.append(payload)

            if len(payloads) == 1:
                # Upstream responded with an in-stream error and no deltas.
                return FakeStreamContext(
                    FakeStreamResponse(
                        status_code=200,
                        headers={},
                        text='a3:"Resource exhausted. Please try again later."\n',
                    )
                )

            first = payloads[0]
            same_ids = (
                payload.get("id") == first.get("id")
                and payload.get("userMessageId") == first.get("userMessageId")
                and payload.get("modelAMessageId") == first.get("modelAMessageId")
                and payload.get("modelBMessageId") == first.get("modelBMessageId")
            )
            if same_ids:
                return FakeStreamContext(
                    FakeStreamResponse(
                        status_code=400,
                        headers={},
                        text='{"error":"duplicate ids"}',
                    )
                )

            return FakeStreamContext(
                FakeStreamResponse(
                    status_code=200,
                    headers={},
                    text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
                )
            )

        with patch.object(self.main, "get_models") as get_models_mock, patch.object(
            self.main,
            "refresh_recaptcha_token",
            AsyncMock(return_value="recaptcha-token"),
        ), patch.object(
            httpx.AsyncClient,
            "stream",
            new=fake_stream,
        ), patch(
            "src.main.print",
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
        self.assertGreaterEqual(len(payloads), 2)
        for key in ("id", "userMessageId", "modelAMessageId", "modelBMessageId"):
            with self.subTest(key=key):
                self.assertNotEqual(payloads[0].get(key), payloads[1].get(key))


if __name__ == "__main__":
    unittest.main()
