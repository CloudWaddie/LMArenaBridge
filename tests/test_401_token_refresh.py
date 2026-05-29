"""
Test that 401 Unauthorized responses trigger token refresh before giving up.

Tests the fix for GitHub issue #172 via the try_refresh_arena_auth_token helper,
which uses multiple refresh strategies:
  1) maybe_refresh_expired_auth_tokens (handles already-expired tokens in the pool)
  2) Direct LMArena HTTP refresh via refresh_arena_auth_token_via_lmarena_http
  3) Fall back to next token in rotation
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure tests can import from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Mock camoufox BEFORE importing src.main (it imports camoufox at module level)
sys.modules["camoufox"] = MagicMock()
sys.modules["camoufox.async_api"] = MagicMock()


class TestTryRefreshArenaAuthToken(unittest.IsolatedAsyncioTestCase):
    """Tests for the try_refresh_arena_auth_token helper function."""

    async def asyncSetUp(self):
        import importlib
        import src.main
        importlib.reload(src.main)
        from src import main

        self.main = main
        self._orig_debug = self.main.DEBUG
        self.main.DEBUG = False

        self._orig_pytest_current_test = os.environ.get("PYTEST_CURRENT_TEST")
        if not self._orig_pytest_current_test:
            os.environ["PYTEST_CURRENT_TEST"] = "unittest"

        self.main.chat_sessions.clear()
        self.main.api_key_usage.clear()

        self._orig_config_file = self.main.CONFIG_FILE
        self._temp_dir = tempfile.TemporaryDirectory()
        self._config_path = Path(self._temp_dir.name) / "config.json"

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
        if self._orig_pytest_current_test is None:
            os.environ.pop("PYTEST_CURRENT_TEST", None)
        else:
            os.environ["PYTEST_CURRENT_TEST"] = self._orig_pytest_current_test
        self._temp_dir.cleanup()

    async def test_pool_refresh_succeeds_does_not_call_direct(self):
        """Strategy 1: maybe_refresh_expired_auth_tokens returns a token, direct refresh skipped."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value="base64-pool-refreshed"):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock) as mock_direct:
                result = await main.try_refresh_arena_auth_token(current_token, failed_tokens)

        self.assertEqual(result, "base64-pool-refreshed")
        mock_direct.assert_not_called()

    async def test_pool_fails_direct_succeeds(self):
        """Strategy 2: Pool refresh returns None, direct LMArena HTTP refresh succeeds."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, return_value="base64-direct-refreshed") as mock_direct:
                result = await main.try_refresh_arena_auth_token(current_token, failed_tokens)

        self.assertEqual(result, "base64-direct-refreshed")
        mock_direct.assert_called_once_with("base64-dGVzdC10b2tlbg==")

    async def test_both_strategies_fail_returns_none(self):
        """Both refresh strategies fail, function returns None."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, return_value=None):
                result = await main.try_refresh_arena_auth_token(current_token, failed_tokens)

        self.assertIsNone(result)

    async def test_non_base64_token_returns_none_immediately(self):
        """Non-base64 tokens skip refresh entirely and return None."""
        from src import main

        current_token = "some-plain-token"
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock) as mock_pool:
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock) as mock_direct:
                result = await main.try_refresh_arena_auth_token(current_token, failed_tokens)

        self.assertIsNone(result)
        mock_pool.assert_not_called()
        mock_direct.assert_not_called()

    async def test_empty_token_returns_none(self):
        """Empty or falsy token returns None immediately."""
        from src import main

        result = await main.try_refresh_arena_auth_token("", {"some-token"})
        self.assertIsNone(result)

        result = await main.try_refresh_arena_auth_token(None, {"some-token"})
        self.assertIsNone(result)

    async def test_pool_refresh_exception_falls_through_to_direct(self):
        """If maybe_refresh_expired_auth_tokens raises, it should be caught and fall through to direct refresh."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, side_effect=RuntimeError("pool error")):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, return_value="base64-direct-refreshed"):
                result = await main.try_refresh_arena_auth_token(current_token, failed_tokens)

        self.assertEqual(result, "base64-direct-refreshed")

    async def test_direct_refresh_exception_returns_none(self):
        """If both strategies raise, function returns None."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, side_effect=RuntimeError("direct error")):
                result = await main.try_refresh_arena_auth_token(current_token, failed_tokens)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
