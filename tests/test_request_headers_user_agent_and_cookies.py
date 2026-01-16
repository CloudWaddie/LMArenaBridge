import json
import tempfile
import unittest
from pathlib import Path


class TestRequestHeadersUserAgentAndCookies(unittest.TestCase):
    def test_get_request_headers_with_token_includes_user_agent_and_cookies(self) -> None:
        from src import main

        temp_dir = tempfile.TemporaryDirectory()
        try:
            config_path = Path(temp_dir.name) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "password": "admin",
                        "cf_clearance": "cf",
                        "cf_bm": "bm",
                        "cfuvid": "uv",
                        "provisional_user_id": "pid",
                        "user_agent": "Mozilla/5.0 TestUA",
                        "auth_tokens": ["auth-token-1"],
                        "api_keys": [],
                    }
                ),
                encoding="utf-8",
            )

            orig_config_file = main.CONFIG_FILE
            main.CONFIG_FILE = str(config_path)
            try:
                headers = main.get_request_headers_with_token("auth-token-1")
            finally:
                main.CONFIG_FILE = orig_config_file

            self.assertEqual(headers.get("User-Agent"), "Mozilla/5.0 TestUA")

            cookie = headers.get("Cookie", "")
            self.assertIn("cf_clearance=cf", cookie)
            self.assertIn("__cf_bm=bm", cookie)
            self.assertIn("_cfuvid=uv", cookie)
            self.assertIn("provisional_user_id=pid", cookie)
            self.assertIn("arena-auth-prod-v1=auth-token-1", cookie)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
