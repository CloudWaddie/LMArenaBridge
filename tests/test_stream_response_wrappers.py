import asyncio
import unittest
from unittest.mock import patch

import httpx


class TestBrowserFetchStreamResponse(unittest.IsolatedAsyncioTestCase):
    async def test_queue_mode_ends_on_done_event(self) -> None:
        from src.streaming import BrowserFetchStreamResponse

        lines_queue: asyncio.Queue = asyncio.Queue()
        done_event = asyncio.Event()

        await lines_queue.put("line1")
        await lines_queue.put("line2")
        done_event.set()

        response = BrowserFetchStreamResponse(
            status_code=200,
            headers={},
            method="POST",
            url="https://lmarena.ai/",
            lines_queue=lines_queue,
            done_event=done_event,
        )

        collected: list[str] = []
        async for line in response.aiter_lines():
            collected.append(line)

        self.assertEqual(collected, ["line1", "line2"])

    async def test_aread_buffers_queue_mode_then_iterates_buffered(self) -> None:
        from src.streaming import BrowserFetchStreamResponse

        lines_queue: asyncio.Queue = asyncio.Queue()
        done_event = asyncio.Event()

        await lines_queue.put("a0:\"A\"")
        await lines_queue.put("a0:\"B\"")
        done_event.set()

        response = BrowserFetchStreamResponse(
            status_code=200,
            headers={},
            method="POST",
            url="https://lmarena.ai/",
            lines_queue=lines_queue,
            done_event=done_event,
        )

        body = await response.aread()
        self.assertEqual(body.decode("utf-8"), "a0:\"A\"\na0:\"B\"")
        self.assertEqual(response.text, "a0:\"A\"\na0:\"B\"")

        collected: list[str] = []
        async for line in response.aiter_lines():
            collected.append(line)

        self.assertEqual(collected, ["a0:\"A\"", "a0:\"B\""])


class TestUserscriptProxyStreamResponse(unittest.IsolatedAsyncioTestCase):
    async def test_deadline_sets_timeout_error_and_done(self) -> None:
        from src.proxy import ProxyService, UserscriptProxyStreamResponse

        service = ProxyService()
        job_id = "job-timeout"

        job = {
            "job_id": job_id,
            "method": "POST",
            "url": "https://lmarena.ai/",
            "status_code": 200,
            "headers": {},
            "lines_queue": asyncio.Queue(),
            "done_event": asyncio.Event(),
            "status_event": asyncio.Event(),
            "done": False,
            "error": None,
        }
        service.jobs[job_id] = job

        response = UserscriptProxyStreamResponse(service, job_id, timeout_seconds=1)

        calls = {"n": 0}

        def _time() -> float:
            calls["n"] += 1
            return 0.0 if calls["n"] == 1 else 1000.0

        with patch("src.proxy.time.time", side_effect=_time):
            collected = [line async for line in response.aiter_lines()]

        self.assertEqual(collected, [])
        self.assertTrue(job["done"])
        self.assertEqual(job["error"], "userscript proxy timeout")
        self.assertTrue(job["done_event"].is_set())

    async def test_raise_for_status_uses_job_error_body(self) -> None:
        from src.proxy import ProxyService, UserscriptProxyStreamResponse

        service = ProxyService()
        job_id = "job-error"
        job = {
            "job_id": job_id,
            "method": "POST",
            "url": "https://lmarena.ai/",
            "status_code": 200,
            "headers": {},
            "lines_queue": asyncio.Queue(),
            "done_event": asyncio.Event(),
            "status_event": asyncio.Event(),
            "done": False,
            "error": "boom",
        }
        service.jobs[job_id] = job

        response = UserscriptProxyStreamResponse(service, job_id, timeout_seconds=1)

        with self.assertRaises(httpx.HTTPStatusError) as ctx:
            response.raise_for_status()

        self.assertEqual(int(ctx.exception.response.status_code), 503)
        self.assertIn(b"boom", ctx.exception.response.content)

    async def test_enter_waits_for_status_event(self) -> None:
        from src.proxy import ProxyService, UserscriptProxyStreamResponse

        service = ProxyService()
        job_id = "job-status"

        status_event = asyncio.Event()
        job = {
            "job_id": job_id,
            "method": "POST",
            "url": "https://lmarena.ai/",
            "status_code": 200,
            "headers": {},
            "lines_queue": asyncio.Queue(),
            "done_event": asyncio.Event(),
            "status_event": status_event,
            "done": False,
            "error": None,
        }
        service.jobs[job_id] = job

        response = UserscriptProxyStreamResponse(service, job_id, timeout_seconds=1)

        async def _set_status() -> None:
            await asyncio.sleep(0)
            job["status_code"] = 201
            job["headers"] = {"Content-Type": "text/plain"}
            status_event.set()

        asyncio.create_task(_set_status())
        async with response as r:
            self.assertEqual(int(r.status_code), 201)
            self.assertEqual(r.headers.get("Content-Type"), "text/plain")


if __name__ == "__main__":
    unittest.main()

