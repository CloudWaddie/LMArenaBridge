import json
import tempfile
import unittest
from pathlib import Path


class TestAuthTokenFallbackFromBrowserCookies(unittest.TestCase):
    def setUp(self) -> None:
        from src import main

        self.main = main
        self._orig_debug = self.main.DEBUG
        self.main.DEBUG = False
        self._orig_config_file = self.main.CONFIG_FILE
        self._orig_token_index = self.main.current_token_index
        self.main.current_token_index = 0

        self._temp_dir = tempfile.TemporaryDirectory()
        self._config_path = Path(self._temp_dir.name) / "config.json"
        self._config_path.write_text(
            json.dumps(
                {
                    "password": "admin",
                    "auth_token": "",
                    "auth_tokens": [],
                    "persist_arena_auth_cookie": True,
                    "browser_cookies": {"arena-auth-prod-v1": "cookie-token-1"},
                    "api_keys": [{"name": "Test Key", "key": "test-key", "rpm": 999}],
                }
            ),
            encoding="utf-8",
        )
        self.main.CONFIG_FILE = str(self._config_path)

    def tearDown(self) -> None:
        self.main.DEBUG = self._orig_debug
        self.main.CONFIG_FILE = self._orig_config_file
        self.main.current_token_index = self._orig_token_index
        self._temp_dir.cleanup()

    def test_get_next_auth_token_uses_browser_cookie_when_pool_empty(self) -> None:
        token = self.main.get_next_auth_token()
        self.assertEqual(token, "cookie-token-1")

        saved = json.loads(self._config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved.get("auth_tokens"), ["cookie-token-1"])


if __name__ == "__main__":
    unittest.main()
