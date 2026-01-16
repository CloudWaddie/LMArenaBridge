import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio
from http import HTTPStatus

class TestChromeFetchRobustness(unittest.IsolatedAsyncioTestCase):
    async def test_fetch_via_chrome_retries_cloudflare(self):
        from src import main
        
        # Mock playwright
        mock_page = AsyncMock()
        mock_page.title.side_effect = [
            "Just a moment...", 
            "Just a moment...", 
            "LMArena"
        ]
        # Mock fetch result
        mock_page.evaluate.side_effect = [
            "user-agent", # for UA check (initial)
            "recaptcha-token", # for _mint_recaptcha_v3_token
            {"status": 200, "headers": {}, "text": "success"} # for fetch script
        ]
        
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []
        
        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch_persistent_context.return_value = mock_context
        mock_playwright.__aenter__.return_value = mock_playwright

        with patch("playwright.async_api.async_playwright", return_value=mock_playwright), \
             patch("src.main.find_chrome_executable", return_value="/path/to/chrome"), \
             patch("src.main.get_config", return_value={}), \
             patch("src.main.get_recaptcha_settings", return_value=("key", "action")), \
             patch("src.main.click_turnstile", AsyncMock(return_value=True)) as mock_click, \
             patch("src.main.asyncio.sleep", AsyncMock()):
            
            resp = await main.fetch_lmarena_stream_via_chrome(
                "POST", "https://lmarena.ai/api", {"p": 1}, "token"
            )
            
            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp._text, "success")
            
            # Should have called title multiple times
            self.assertGreaterEqual(mock_page.title.call_count, 3)
            # Should have called click_turnstile
            self.assertGreaterEqual(mock_click.call_count, 2)

    async def test_fetch_via_chrome_sends_payload_recaptcha_token_in_headers(self):
        from src import main

        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"

        async def eval_side_effect(script, arg=None):
            if script == "() => navigator.userAgent":
                return "user-agent"
            if isinstance(script, str) and script.lstrip().startswith("async ({url, method, body, extraHeaders"):
                extra = (arg or {}).get("extraHeaders") or {}
                self.assertEqual(extra.get("X-Recaptcha-Token"), "payload-token")
                self.assertEqual(extra.get("X-Recaptcha-Action"), "action")
                return {"status": 200, "headers": {}, "text": "success"}
            raise AssertionError(f"Unexpected evaluate script: {str(script)[:80]}")

        mock_page.evaluate.side_effect = eval_side_effect

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch_persistent_context.return_value = mock_context
        mock_playwright.__aenter__.return_value = mock_playwright

        with patch("playwright.async_api.async_playwright", return_value=mock_playwright), patch(
            "src.main.find_chrome_executable", return_value="/path/to/chrome"
        ), patch("src.main.get_config", return_value={}), patch(
            "src.main.get_recaptcha_settings", return_value=("key", "action")
        ), patch(
            "src.main.click_turnstile", AsyncMock(return_value=True)
        ), patch(
            "src.main.asyncio.sleep", AsyncMock()
        ):
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

if __name__ == "__main__":
    unittest.main()
