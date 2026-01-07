import json
import unittest

from tests._stream_test_utils import BaseBridgeTest


class TestAuthTokenFallbackFromBrowserCookies(BaseBridgeTest):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.setup_config(
            {
                "auth_token": "",
                "auth_tokens": [],
                "persist_arena_auth_cookie": True,
                "browser_cookies": {"arena-auth-prod-v1": "cookie-token-1"},
            }
        )

    def test_get_next_auth_token_uses_browser_cookie_when_pool_empty(self) -> None:
        token = self.main.get_next_auth_token()
        self.assertEqual(token, "cookie-token-1")

        saved = json.loads(self._config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved.get("auth_tokens"), ["cookie-token-1"])


if __name__ == "__main__":
    unittest.main()
