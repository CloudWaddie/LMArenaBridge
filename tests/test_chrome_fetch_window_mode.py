from unittest.mock import AsyncMock, patch

from tests._stream_test_utils import BaseBridgeTest


class TestChromeFetchWindowMode(BaseBridgeTest):
    async def test_chrome_fetch_applies_window_mode_helper(self) -> None:
        mock_page = AsyncMock()
        mock_page.title.return_value = "LMArena"
        mock_page.evaluate.side_effect = [
            "user-agent",
            "recaptcha-token",
            {"status": 200, "headers": {}, "text": "success"},
        ]

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch_persistent_context.return_value = mock_context
        mock_playwright.__aenter__.return_value = mock_playwright

        window_mode_mock = AsyncMock()

        with (
            patch("playwright.async_api.async_playwright", return_value=mock_playwright),
            patch.object(self.main, "find_chrome_executable", return_value="C:/chrome.exe"),
            patch.object(self.main, "get_recaptcha_settings", return_value=("key", "action")),
            patch.object(self.main, "click_turnstile", AsyncMock(return_value=True)),
            patch.object(self.main.asyncio, "sleep", AsyncMock()),
            patch.object(self.main, "_maybe_apply_camoufox_window_mode", window_mode_mock),
        ):
            resp = await self.main.fetch_lmarena_stream_via_chrome(
                "POST",
                "https://lmarena.ai/api",
                {"p": 1},
                "token",
            )

        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        window_mode_mock.assert_awaited()
        self.assertEqual(window_mode_mock.await_args.kwargs.get("mode_key"), "chrome_fetch_window_mode")


if __name__ == "__main__":
    import unittest

    unittest.main()
