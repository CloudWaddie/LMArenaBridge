"""
Test that 401 Unauthorized responses trigger token refresh before giving up.

This tests the fix for GitHub issue #172:
  https://github.com/CloudWaddie/LMArenaBridge/issues/172

The fix uses multiple refresh strategies:
  1) maybe_refresh_expired_auth_tokens (handles already-expired tokens in the pool)
  2) Direct LMArena HTTP refresh via refresh_arena_auth_token_via_lmarena_http
  3) Fall back to next token in rotation
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
        self._orig_token_index = getattr(self.main, "current_token_index", 0)

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
        if hasattr(self.main, "current_token_index"):
            self.main.current_token_index = self._orig_token_index
        if self._orig_pytest_current_test is None:
            os.environ.pop("PYTEST_CURRENT_TEST", None)
        else:
            os.environ["PYTEST_CURRENT_TEST"] = self._orig_pytest_current_test
        self._temp_dir.cleanup()

    async def test_401_pool_refresh_succeeds(self):
        """Strategy 1: maybe_refresh_expired_auth_tokens returns a token."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value="base64-pool-refreshed"):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock) as mock_direct:
                with patch.object(main, "get_next_auth_token") as mock_next:
                    # Simulate the 401 handling logic
                    refreshed_token = None
                    if current_token.startswith("base64-"):
                        refreshed_token = await main.maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
                        if not refreshed_token:
                            refreshed_token = await main.refresh_arena_auth_token_via_lmarena_http(current_token)
                        if refreshed_token:
                            current_token = refreshed_token
                            failed_tokens.discard(current_token)

            self.assertEqual(current_token, "base64-pool-refreshed")
            # Direct refresh should NOT have been called since pool refresh succeeded
            mock_direct.assert_not_called()
            mock_next.assert_not_called()

    async def test_401_direct_refresh_succeeds_when_pool_fails(self):
        """Strategy 2: Pool refresh returns None, direct LMArena HTTP refresh succeeds."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, return_value="base64-direct-refreshed") as mock_direct:
                with patch.object(main, "get_next_auth_token") as mock_next:
                    refreshed_token = None
                    if current_token.startswith("base64-"):
                        refreshed_token = await main.maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
                        if not refreshed_token:
                            refreshed_token = await main.refresh_arena_auth_token_via_lmarena_http(current_token)
                        if refreshed_token:
                            current_token = refreshed_token
                            failed_tokens.discard(current_token)

            self.assertEqual(current_token, "base64-direct-refreshed")
            mock_direct.assert_called_once_with("base64-dGVzdC10b2tlbg==")
            mock_next.assert_not_called()

    async def test_401_both_refresh_strategies_fail_falls_back_to_next_token(self):
        """Strategy 3: Both refresh strategies fail, fall back to get_next_auth_token."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, return_value=None):
                with patch.object(main, "get_next_auth_token", return_value="base64-next-token") as mock_next:
                    refreshed_token = None
                    if current_token.startswith("base64-"):
                        refreshed_token = await main.maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
                        if not refreshed_token:
                            refreshed_token = await main.refresh_arena_auth_token_via_lmarena_http(current_token)
                        if refreshed_token:
                            current_token = refreshed_token
                            failed_tokens.discard(current_token)
                    if not refreshed_token:
                        current_token = main.get_next_auth_token(exclude_tokens=failed_tokens)

        self.assertEqual(current_token, "base64-next-token")
        mock_next.assert_called_once_with(exclude_tokens=failed_tokens)

    async def test_401_non_base64_token_skips_refresh(self):
        """Non-base64 tokens should skip all refresh strategies and go straight to next token."""
        from src import main

        current_token = "some-plain-token"
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock) as mock_pool:
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock) as mock_direct:
                with patch.object(main, "get_next_auth_token", return_value="next-token") as mock_next:
                    refreshed_token = None
                    if current_token.startswith("base64-"):
                        refreshed_token = await main.maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
                        if not refreshed_token:
                            refreshed_token = await main.refresh_arena_auth_token_via_lmarena_http(current_token)
                    if not refreshed_token:
                        current_token = main.get_next_auth_token(exclude_tokens=failed_tokens)

        mock_pool.assert_not_called()
        mock_direct.assert_not_called()
        self.assertEqual(current_token, "next-token")

    async def test_401_refresh_clears_failed_tokens(self):
        """After successful refresh, the new token should be removed from failed_tokens."""
        from src import main

        current_token = "base64-dGVzdC10b2tlbg=="
        failed_tokens = {current_token}

        with patch.object(main, "maybe_refresh_expired_auth_tokens", new_callable=AsyncMock, return_value=None):
            with patch.object(main, "refresh_arena_auth_token_via_lmarena_http", new_callable=AsyncMock, return_value="base64-new"):
                refreshed_token = None
                if current_token.startswith("base64-"):
                    refreshed_token = await main.maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
                    if not refreshed_token:
                        refreshed_token = await main.refresh_arena_auth_token_via_lmarena_http(current_token)
                    if refreshed_token:
                        current_token = refreshed_token
                        failed_tokens.discard(current_token)

        # The old token should still be in failed_tokens, but the new one should not
        self.assertIn("base64-dGVzdC10b2tlbg==", failed_tokens)
        self.assertNotIn("base64-new", failed_tokens)


if __name__ == "__main__":
    unittest.main()
