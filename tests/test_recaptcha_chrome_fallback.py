import unittest
from unittest.mock import AsyncMock, patch


class TestRecaptchaChromeFallback(unittest.IsolatedAsyncioTestCase):
    async def test_get_recaptcha_token_uses_chrome_provider_when_available(self) -> None:
        from src import main

        main.DEBUG = False

        chrome_mock = AsyncMock(return_value="token-123")

        with patch.object(main, "get_config", return_value={}), patch.object(
            main, "get_recaptcha_v3_token_with_chrome", chrome_mock
        ), patch.object(main, "AsyncCamoufox") as camoufox_mock:
            token = await main.get_recaptcha_v3_token()

        self.assertEqual(token, "token-123")
        chrome_mock.assert_awaited()
        camoufox_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

