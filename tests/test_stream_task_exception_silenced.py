import asyncio
import gc
import unittest
from unittest.mock import AsyncMock, patch


class TestStreamTaskExceptionSilenced(unittest.IsolatedAsyncioTestCase):
    async def test_chrome_stream_task_exception_is_not_unretrieved(self) -> None:
        from src import main

        loop = asyncio.get_running_loop()
        seen: list[dict] = []
        old_handler = loop.get_exception_handler()

        def _handler(_loop, context):  # noqa: ANN001
            seen.append(dict(context or {}))

        loop.set_exception_handler(_handler)
        try:
            report_cb = None
            allow_finish = asyncio.Event()

            async def _expose_binding(name, func):  # noqa: ANN001
                nonlocal report_cb
                if str(name) == "reportChunk":
                    report_cb = func

            mock_page = AsyncMock()
            mock_page.title.return_value = "LMArena"
            mock_page.expose_binding.side_effect = _expose_binding
            mock_page.mouse = AsyncMock()
            mock_page.mouse.move = AsyncMock()
            mock_page.mouse.wheel = AsyncMock()

            async def _evaluate(script, arg=None):  # noqa: ANN001
                if script == "() => navigator.userAgent":
                    return "user-agent"
                if isinstance(script, str) and script.lstrip().startswith("async ({url, method, body, extraHeaders"):
                    assert report_cb is not None
                    await report_cb(None, '{"__type":"meta","status":200,"headers":{}}')
                    await report_cb(None, "data: hi")
                    await allow_finish.wait()
                    raise RuntimeError("Page.evaluate: Target page, context or browser has been closed")
                raise AssertionError(f"Unexpected evaluate script: {str(script)[:80]}")

            mock_page.evaluate.side_effect = _evaluate

            mock_context = AsyncMock()
            mock_context.new_page.return_value = mock_page
            mock_context.cookies.return_value = []

            mock_playwright = AsyncMock()
            mock_playwright.chromium.launch_persistent_context.return_value = mock_context
            mock_playwright.__aenter__.return_value = mock_playwright

            with (
                patch("playwright.async_api.async_playwright", return_value=mock_playwright),
                patch("src.main.find_chrome_executable", return_value="C:\\fake\\chrome.exe"),
                patch("src.main.get_config", return_value={}),
                patch("src.main.get_recaptcha_settings", return_value=("key", "action")),
                patch("src.main.click_turnstile", AsyncMock(return_value=False)),
                patch("src.main.asyncio.sleep", AsyncMock()),
            ):
                resp = await main.fetch_lmarena_stream_via_chrome(
                    "POST",
                    "https://lmarena.ai/api",
                    {"recaptchaV3Token": "payload-token"},
                    "token",
                    timeout_seconds=2,
                )

                self.assertIsNotNone(resp)
                self.assertEqual(resp.status_code, 200)

                allow_finish.set()
                data = await resp.aread()
                self.assertIn(b"data: hi", data)

            gc.collect()
            await asyncio.sleep(0)

            leaked = [c for c in seen if "Task exception was never retrieved" in str(c.get("message") or "")]
            self.assertEqual(leaked, [])
        finally:
            loop.set_exception_handler(old_handler)


if __name__ == "__main__":
    unittest.main()

