import asyncio
import unittest
from unittest.mock import patch


class TestProxyQueueFallback(unittest.IsolatedAsyncioTestCase):
    """Regression: fetch_via_proxy_queue referenced module-level names that live in main.py."""

    async def asyncSetUp(self) -> None:
        from src import main

        self.main = main
        main.proxy_pending_tasks.clear()
        main.proxy_task_queue.clear()

    async def asyncTearDown(self) -> None:
        self.main.proxy_pending_tasks.clear()
        self.main.proxy_task_queue.clear()

    async def test_proxy_queue_fallback_does_not_raise_name_error(self) -> None:
        from src import transport

        async def _no_stream(**kwargs):  # noqa: ARG001
            return None

        with patch.object(self.main, "fetch_lmarena_stream_via_userscript_proxy", _no_stream):
            result = await transport.fetch_via_proxy_queue(
                url="https://arena.ai/nextjs-api/stream/create-evaluation",
                payload={"x": 1},
                http_method="POST",
                timeout_seconds=0.05,
            )

        self.assertIsNone(result)
        # The timed-out task must be cleaned up from both registries.
        self.assertEqual(self.main.proxy_pending_tasks, {})
        self.assertEqual(self.main.proxy_task_queue, [])

    async def test_proxy_queue_fallback_queues_task_for_userscript(self) -> None:
        from src import transport

        async def _no_stream(**kwargs):  # noqa: ARG001
            return None

        async def _deliver() -> None:
            # The userscript polls /proxy/tasks, then posts the result back.
            for _ in range(100):
                if self.main.proxy_task_queue:
                    break
                await asyncio.sleep(0.01)
            tasks = list(self.main.proxy_task_queue)
            self.main.proxy_task_queue.clear()
            self.assertEqual(len(tasks), 1)
            task_id = tasks[0]["id"]
            future = self.main.proxy_pending_tasks.get(task_id)
            self.assertIsNotNone(future)
            future.set_result({"status": 200, "headers": {}, "text": "hello"})

        deliver = asyncio.create_task(_deliver())
        with patch.object(self.main, "fetch_lmarena_stream_via_userscript_proxy", _no_stream):
            response = await transport.fetch_via_proxy_queue(
                url="https://arena.ai/nextjs-api/stream/create-evaluation",
                payload={"x": 1},
                http_method="POST",
                timeout_seconds=5,
            )
        await deliver

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response._text, "hello")

    async def test_proxy_result_endpoint_resolves_pending_future(self) -> None:
        future = asyncio.get_running_loop().create_future()
        self.main.proxy_pending_tasks["task-1"] = future

        class _Request:
            async def json(self):
                return {"status": 200, "headers": {}, "text": "hi"}

        response = await self.main.post_proxy_result("task-1", _Request(), api_key={"key": "k"})

        self.assertEqual(response, {"status": "ok"})
        self.assertEqual(future.result(), {"status": 200, "headers": {}, "text": "hi"})


if __name__ == "__main__":
    unittest.main()
