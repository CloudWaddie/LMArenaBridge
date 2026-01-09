import unittest
from unittest.mock import patch


class TestProxyService(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_service_roundtrip_poll_push(self) -> None:
        from src import proxy

        service = proxy.ProxyService()

        with patch.object(proxy.uuid, "uuid4", return_value=proxy.uuid.UUID(int=0)):
            stream = await service.enqueue_stream_job(
                url="https://lmarena.ai/nextjs-api/stream/create-evaluation",
                http_method="POST",
                payload={"hello": "world"},
                auth_token="auth-token",
                timeout_seconds=5,
                config={"recaptcha_sitekey": "key", "recaptcha_action": "action"},
            )

        job = await service.poll_next_job(timeout_seconds=0.1)
        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job["job_id"], stream.job_id)

        await service.push_job_update(
            job_id=stream.job_id,
            status=200,
            headers={"Content-Type": "text/event-stream"},
            error=None,
            lines=['a0:"Hello"', 'ad:{"finishReason":"stop"}'],
            done=True,
        )

        collected: list[str] = []
        async for line in stream.aiter_lines():
            collected.append(line)

        self.assertIn('a0:"Hello"', collected)


if __name__ == "__main__":
    unittest.main()

