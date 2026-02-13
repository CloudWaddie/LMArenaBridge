from unittest.mock import AsyncMock, patch

from tests._stream_test_utils import BaseBridgeTest


class TestUserscriptProxyUrlNormalization(BaseBridgeTest):
    def test_normalizes_lmarena_urls_to_paths(self) -> None:
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("https://lmarena.ai/nextjs-api/stream/create-evaluation"),
            "/nextjs-api/stream/create-evaluation",
        )
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("https://arena.ai/nextjs-api/sign-up?x=1"),
            "/nextjs-api/sign-up?x=1",
        )
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("/nextjs-api/stream/create-evaluation"),
            "/nextjs-api/stream/create-evaluation",
        )
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("https://example.com/foo"),
            "https://example.com/foo",
        )

    async def test_chrome_fetch_keeps_absolute_non_arena_urls_absolute(self) -> None:
        fetch_urls: list[str] = []

        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"

        async def eval_side_effect(script, arg=None):  # noqa: ANN001
            if script == "() => navigator.userAgent":
                return "ua"
            if isinstance(script, str) and script.lstrip().startswith("async ({url, method, body, extraHeaders"):
                fetch_urls.append((arg or {}).get("url"))
                return {"status": 200, "headers": {}, "text": "ok"}
            raise AssertionError(f"Unexpected evaluate script: {str(script)[:120]}")

        mock_page.evaluate.side_effect = eval_side_effect

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch_persistent_context.return_value = mock_context
        mock_playwright.__aenter__.return_value = mock_playwright

        with (
            patch("playwright.async_api.async_playwright", return_value=mock_playwright),
            patch.object(self.main, "find_chrome_executable", return_value="C:/chrome.exe"),
            patch.object(self.main, "get_recaptcha_settings", return_value=("sitekey", "action")),
            patch.object(self.main, "_get_arena_context_cookies", AsyncMock(return_value=[])),
            patch.object(self.main, "_upsert_browser_session_into_config", return_value=False),
            patch.object(self.main, "_maybe_apply_camoufox_window_mode", AsyncMock()),
            patch.object(self.main, "click_turnstile", AsyncMock(return_value=True)),
            patch.object(self.main.asyncio, "sleep", AsyncMock()),
        ):
            resp = await self.main.fetch_lmarena_stream_via_chrome(
                "POST",
                "https://example.com/foo?x=1",
                {"recaptchaV3Token": "token"},
                "auth-token",
            )

        self.assertIsNotNone(resp)
        self.assertEqual(fetch_urls, ["https://example.com/foo?x=1"])

    async def test_camoufox_fetch_keeps_absolute_non_arena_urls_absolute(self) -> None:
        fetch_urls: list[str] = []

        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"

        async def eval_side_effect(script, arg=None):  # noqa: ANN001
            if script == "() => navigator.userAgent":
                return "ua"
            if isinstance(script, str) and script.lstrip().startswith("async ({url, method, body, extraHeaders"):
                fetch_urls.append((arg or {}).get("url"))
                return {"status": 200, "headers": {}, "text": "ok"}
            raise AssertionError(f"Unexpected evaluate script: {str(script)[:120]}")

        mock_page.evaluate.side_effect = eval_side_effect

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.__aenter__.return_value = mock_browser

        with (
            patch.object(self.main, "AsyncCamoufox", return_value=mock_browser),
            patch.object(self.main, "get_recaptcha_settings", return_value=("sitekey", "action")),
            patch.object(self.main, "_get_arena_context_cookies", AsyncMock(return_value=[])),
            patch.object(self.main, "_upsert_browser_session_into_config", return_value=False),
            patch.object(self.main, "_maybe_apply_camoufox_window_mode", AsyncMock()),
            patch.object(self.main, "click_turnstile", AsyncMock(return_value=True)),
            patch.object(self.main.asyncio, "sleep", AsyncMock()),
        ):
            resp = await self.main.fetch_lmarena_stream_via_camoufox(
                "POST",
                "https://example.com/foo?x=1",
                {"recaptchaV3Token": "token"},
                "auth-token",
            )

        self.assertIsNotNone(resp)
        self.assertEqual(fetch_urls, ["https://example.com/foo?x=1"])

