import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from src import main


def _mk_playwright(page: AsyncMock) -> AsyncMock:
    ctx = AsyncMock()
    ctx.new_page.return_value = page
    ctx.cookies.return_value = []

    pw = AsyncMock()
    pw.chromium.launch_persistent_context.return_value = ctx
    pw.__aenter__.return_value = pw
    return pw


def _patch_chrome_env(
    playwright: AsyncMock,
    *,
    click: AsyncMock | None = None,
) -> tuple[ExitStack, AsyncMock]:
    stack = ExitStack()
    stack.enter_context(patch("playwright.async_api.async_playwright", return_value=playwright))
    stack.enter_context(patch("src.main.find_chrome_executable", return_value="/path/to/chrome"))
    stack.enter_context(patch("src.main.get_config", return_value={}))
    stack.enter_context(patch("src.main.get_recaptcha_settings", return_value=("key", "action")))

    click_mock = click or AsyncMock(return_value=True)
    stack.enter_context(patch("src.main.click_turnstile", click_mock))
    stack.enter_context(patch("src.main.asyncio.sleep", AsyncMock()))
    return stack, click_mock

class TestChromeFetchRobustness(unittest.IsolatedAsyncioTestCase):
    async def test_fetch_via_chrome_retries_cloudflare(self):
        mock_page = AsyncMock()
        mock_page.title.side_effect = ["Just a moment...", "Just a moment...", "LMArena"]
        mock_page.evaluate.side_effect = [
            "user-agent",
            "recaptcha-token",
            {"status": 200, "headers": {}, "text": "success"},
        ]
        mock_playwright = _mk_playwright(mock_page)

        stack, click_mock = _patch_chrome_env(mock_playwright)
        with stack:
            resp = await main.fetch_lmarena_stream_via_chrome(
                "POST", "https://lmarena.ai/api", {"p": 1}, "token"
            )
            
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp._text, "success")
        self.assertGreaterEqual(mock_page.title.call_count, 3)
        self.assertGreaterEqual(click_mock.call_count, 2)

    async def test_fetch_via_chrome_sends_payload_recaptcha_token_in_headers(self):
        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"

        async def eval_side_effect(script, arg=None):
            if script == "() => navigator.userAgent":
                return "user-agent"
            if isinstance(arg, dict) and "method" in arg and "extraHeaders" in arg:
                extra = (arg or {}).get("extraHeaders") or {}
                self.assertEqual(extra.get("X-Recaptcha-Token"), "payload-token")
                self.assertEqual(extra.get("X-Recaptcha-Action"), "action")
                return {"status": 200, "headers": {}, "text": "success"}
            raise AssertionError(f"Unexpected evaluate script: {str(script)[:80]}")

        mock_page.evaluate.side_effect = eval_side_effect
        mock_playwright = _mk_playwright(mock_page)

        stack, _ = _patch_chrome_env(mock_playwright)
        with stack:
            resp = await main.fetch_lmarena_stream_via_chrome(
                "POST",
                "https://lmarena.ai/api",
                {"p": 1, "recaptchaV3Token": "payload-token"},
                "token",
            )

            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 200)
            # If we already have a token in payload, we shouldn't try to mint a new one.
            mock_page.wait_for_function.assert_not_awaited()

    async def test_fetch_via_chrome_recaptcha_validation_failed_uses_v2_fallback(self):
        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"

        fetch_bodies: list[str] = []
        fetch_calls = 0

        async def eval_side_effect(script, arg=None):
            nonlocal fetch_calls
            if script == "() => navigator.userAgent":
                return "user-agent"
            if isinstance(arg, dict) and "method" in arg:
                fetch_calls += 1
                body = arg.get("body") or ""
                fetch_bodies.append(str(body))
                if fetch_calls == 1:
                    return {
                        "status": 403,
                        "headers": {},
                        "text": "{\"error\":\"recaptcha validation failed\"}",
                    }
                return {"status": 200, "headers": {}, "text": "success"}
            if isinstance(arg, dict) and "action" in arg:
                return "v3-token"
            if isinstance(arg, dict) and "timeoutMs" in arg:
                return "v2-token"
            raise AssertionError(f"Unexpected evaluate script: {str(script)[:80]}")

        mock_page.evaluate.side_effect = eval_side_effect

        click_mock = AsyncMock(return_value=True)
        mock_playwright = _mk_playwright(mock_page)
        stack, _ = _patch_chrome_env(mock_playwright, click=click_mock)
        with stack:
            resp = await main.fetch_lmarena_stream_via_chrome(
                "POST",
                "https://lmarena.ai/api",
                {"p": 1},
                "token",
                max_recaptcha_attempts=2,
            )

        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp._text, "success")
        self.assertGreaterEqual(len(fetch_bodies), 2)

        self.assertIn('"recaptchaV3Token"', fetch_bodies[0])
        self.assertNotIn('"recaptchaV2Token"', fetch_bodies[0])
        self.assertIn('"recaptchaV2Token"', fetch_bodies[1])
        self.assertNotIn('"recaptchaV3Token"', fetch_bodies[1])
        click_mock.assert_not_awaited()

if __name__ == "__main__":
    unittest.main()
