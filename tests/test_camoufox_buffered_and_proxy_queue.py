import asyncio
import unittest
from unittest.mock import AsyncMock, patch


class TestCamoufoxBufferedAndProxyQueue(unittest.IsolatedAsyncioTestCase):
    async def test_camoufox_fetch_returns_buffered_body_when_report_chunk_unused(self) -> None:
        from src import main

        body = 'a0:"hello from camoufox"\nad:{"finishReason":"stop"}\n'

        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"

        async def eval_side_effect(script, arg=None):
            if isinstance(script, str) and script.lstrip().startswith("async ({url, method, body, extraHeaders"):
                return {"status": 200, "headers": {"content-type": "text/plain"}, "text": body}
            return "user-agent"

        mock_page.evaluate.side_effect = eval_side_effect

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.new_page.return_value = mock_page

        class _FakeCamoufox:
            async def __aenter__(self):
                return mock_browser

            async def __aexit__(self, exc_type, exc, tb):
                return False

        with patch("src.main.AsyncCamoufox", return_value=_FakeCamoufox()), \
             patch("src.main.get_config", return_value={}), \
             patch("src.main.get_recaptcha_settings", return_value=("key", "action")), \
             patch("src.main.click_turnstile", AsyncMock(return_value=True)), \
             patch("src.main.asyncio.sleep", AsyncMock()):
            resp = await main.fetch_lmarena_stream_via_camoufox(
                "POST",
                "https://arena.ai/nextjs-api/stream/create-evaluation",
                {"p": 1, "recaptchaV3Token": "tok"},
                "auth-token",
            )

        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        lines = []
        async with resp as stream:
            async for line in stream.aiter_lines():
                lines.append(line)
        self.assertIn('a0:"hello from camoufox"', lines)

    async def test_fetch_via_proxy_queue_uses_main_state_and_resolves(self) -> None:
        from src import main

        main.proxy_pending_tasks.clear()
        main.proxy_task_queue.clear()

        async def _complete_queued_task():
            while not main.proxy_task_queue:
                await asyncio.sleep(0.01)
            task = main.proxy_task_queue.pop(0)
            fut = main.proxy_pending_tasks.pop(task["id"])
            fut.set_result({"status": 200, "headers": {"x-test": "1"}, "text": 'a0:"ok"'})

        completer = asyncio.create_task(_complete_queued_task())
        try:
            with patch("src.main.fetch_lmarena_stream_via_userscript_proxy", AsyncMock(return_value=None)):
                resp = await main.fetch_via_proxy_queue(
                    "https://arena.ai/nextjs-api/stream/create-evaluation",
                    {"hello": "world"},
                    timeout_seconds=5,
                )
        finally:
            await completer
            main.proxy_pending_tasks.clear()
            main.proxy_task_queue.clear()

        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp._text, 'a0:"ok"')

    async def test_fetch_via_proxy_queue_cleans_up_on_timeout(self) -> None:
        from src import main

        main.proxy_pending_tasks.clear()
        main.proxy_task_queue.clear()

        try:
            with patch("src.main.fetch_lmarena_stream_via_userscript_proxy", AsyncMock(return_value=None)):
                resp = await main.fetch_via_proxy_queue(
                    "https://arena.ai/nextjs-api/stream/create-evaluation",
                    {"hello": "world"},
                    timeout_seconds=0.05,
                )
        finally:
            pending_left = len(main.proxy_pending_tasks)
            queued_left = len(main.proxy_task_queue)
            main.proxy_pending_tasks.clear()
            main.proxy_task_queue.clear()

        self.assertIsNone(resp)
        self.assertEqual(pending_left, 0)
        self.assertEqual(queued_left, 0)


if __name__ == "__main__":
    unittest.main()
