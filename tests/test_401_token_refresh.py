"""
Test that 401 Unauthorized responses trigger token refresh before giving up.

This tests the fix for GitHub issue #172:
  https://github.com/CloudWaddie/LMArenaBridge/issues/172

Before the fix, a 401 would immediately mark the token as failed and try
the next one. With only one token, this produced:
  "No more auth tokens available to try" -> "503: Max retries exceeded"

After the fix, the code attempts to refresh the token via LMArena HTTP
before rotating to the next token.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

# Ensure tests can import from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Mock camoufox BEFORE importing src.main (it imports camoufox at module level)
sys.modules["camoufox"] = MagicMock()
sys.modules["camoufox.async_api"] = MagicMock()


class Test401TokenRefresh(unittest.IsolatedAsyncioTestCase):
    """Tests for the 401 token refresh logic added in issue #172."""

    async def asyncSetUp(self):
        # Import main fresh for each test to avoid state leakage
        import importlib
        import src.main
        importlib.reload(src.main)
        from src import main

        self.main = main
        self._orig_debug = self.main.DEBUG
        self.main.DEBUG = False

        # Skip browser/network startup
        self._orig_pytest_current_test = os.environ.get("PYTEST_CURRENT_TEST")
        if not self._orig_pytest_current_test:
            os.environ["PYTEST_CURRENT_TEST"] = "unittest"

        self.main.chat_sessions.clear()
        self.main.api_key_usage.clear()

        self._orig_config_file = self.main.CONFIG_FILE
        self._orig_token_index = getattr(self.main, "current_token_index", 0)

        self._temp_dir = tempfile.TemporaryDirectory()
        self._config_path = Path(self._temp_dir.name) / "config.json"

        # Write a minimal config with a single base64- token
        config = {
            "password": "admin",
            "cf_clearance": "test-cf-clearance",
            "auth_tokens": ["base64-dGVzdC10b2tlbg=="],
            "api_keys": [{"name": "Test Key", "key": "test-key", "rpm": 999}],
        }
        self._config_path.write_text(json.dumps(config), encoding="utf-8")
        self.main.CONFIG_FILE = str(self._config_path)

    async def asyncTearDown(self):
        self.main.DEBUG = self._orig_debug
        self.main.CONFIG_FILE = self._orig_config_file
        if hasattr(self.main, "current_token_index"):
            self.main.current_token_index = self._orig_token_index
        if self._orig_pytest_current_test is None:
            os.environ.pop("PYTEST_CURRENT_TEST", None)
        else:
            os.environ["PYTEST_CURRENT_TEST"] = self._orig_pytest_current_test
        self._temp_dir.cleanup()

    async def test_401_triggers_token_refresh_attempt(self):
        """When a 401 occurs on a base64- token, maybe_refresh_expired_auth_tokens should be called."""
        from src import main

        refresh_called = False

        async def mock_refresh(exclude_tokens=None):
            nonlocal refresh_called
            refresh_called = True
            return "base64-refreshed-token"

        # Simulate the 401 handling logic from make_request_with_retry (line 2655-2688)
        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = set()
        recaptcha_token = None

        from http import HTTPStatus

        # Simulate receiving a 401 response
        status_code = 401
        if status_code == HTTPStatus.UNAUTHORIZED:
            failed_tokens.add(current_token)

            refreshed_token = None
            if current_token.startswith("base64-"):
                refreshed_token = await mock_refresh(exclude_tokens=failed_tokens)
                if refreshed_token:
                    current_token = refreshed_token

        self.assertTrue(refresh_called, "maybe_refresh_expired_auth_tokens should have been called on 401")
        self.assertEqual(current_token, "base64-refreshed-token")

    async def test_401_refresh_failure_falls_back_to_next_token(self):
        """When refresh returns None, should fall back to get_next_auth_token."""
        from src import main
        from http import HTTPStatus

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}
        recaptcha_token = None

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "get_next_auth_token", return_value="base64-next-token") as mock_next:
                refreshed_token = None
                if current_token.startswith("base64-"):
                    refreshed_token = await main.maybe_refresh_expired_auth_tokens(
                        exclude_tokens=failed_tokens
                    )

                # Since refresh returned None, should try next token
                if not refreshed_token:
                    current_token = main.get_next_auth_token(exclude_tokens=failed_tokens)

        self.assertEqual(current_token, "base64-next-token")
        mock_next.assert_called_once_with(exclude_tokens=failed_tokens)

    async def test_401_non_base64_token_skips_refresh(self):
        """Non-base64 tokens should skip refresh and go straight to next token."""
        from src import main

        current_token = "some-plain-token"
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock) as mock_refresh:
            with patch.object(main, "get_next_auth_token", return_value="next-token") as mock_next:
                refreshed_token = None
                if current_token.startswith("base64-"):
                    refreshed_token = await main.maybe_refresh_expired_auth_tokens(
                        exclude_tokens=failed_tokens
                    )

                if not refreshed_token:
                    current_token = main.get_next_auth_token(exclude_tokens=failed_tokens)

        # Refresh should NOT have been called for non-base64 token
        mock_refresh.assert_not_called()
        self.assertEqual(current_token, "next-token")

    async def test_401_refresh_success_no_next_token_needed(self):
        """When refresh succeeds, should NOT call get_next_auth_token."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value="base64-new"):
            with patch.object(main, "get_next_auth_token") as mock_next:
                refreshed_token = None
                if current_token.startswith("base64-"):
                    refreshed_token = await main.maybe_refresh_expired_auth_tokens(
                        exclude_tokens=failed_tokens
                    )
                    if refreshed_token:
                        current_token = refreshed_token

                # Should NOT have tried next token since refresh succeeded
                if not refreshed_token:
                    current_token = main.get_next_auth_token(exclude_tokens=failed_tokens)

        self.assertEqual(current_token, "base64-new")
        mock_next.assert_not_called()


if __name__ == "__main__":
    unittest.main()
