import base64
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from src.account_recovery import (
    _extract_arena_auth_from_cookies,
    extract_arena_verification_url,
    is_anonymous_arena_auth_token,
    is_signed_in_arena_auth_token,
)
from src.auth import _combine_split_arena_auth_cookies, _upsert_browser_session_into_config


def _make_session_token(expires_at: int, *, is_anonymous: bool) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"exp": expires_at}).encode()).decode().rstrip("=")
    jwt_tok = f"{header}.{payload}.sig"
    session = {
        "access_token": jwt_tok,
        "refresh_token": "rt-test",
        "expires_at": expires_at,
        "user": {"is_anonymous": is_anonymous, "email": "" if is_anonymous else "user@gmail.com"},
    }
    raw = json.dumps(session, separators=(",", ":")).encode("utf-8")
    return "base64-" + base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


class TestAccountRecoveryHelpers(unittest.TestCase):
    def test_combine_split_cookies_handles_empty_base_and_three_chunks(self) -> None:
        cookies = [
            {"name": "arena-auth-prod-v1", "value": ""},
            {"name": "arena-auth-prod-v1.1", "value": "PART1"},
            {"name": "arena-auth-prod-v1.0", "value": "PART0"},
            {"name": "arena-auth-prod-v1.2", "value": "PART2"},
        ]
        self.assertEqual(_combine_split_arena_auth_cookies(cookies), "PART0PART1PART2")
        self.assertEqual(_extract_arena_auth_from_cookies(cookies), "PART0PART1PART2")

    def test_upsert_does_not_clobber_auth_cookie_with_empty_value(self) -> None:
        cfg = {"browser_cookies": {"arena-auth-prod-v1": "existing-token"}}
        changed = _upsert_browser_session_into_config(
            cfg,
            [{"name": "arena-auth-prod-v1", "value": ""}],
        )
        self.assertFalse(changed)
        self.assertEqual(cfg["browser_cookies"]["arena-auth-prod-v1"], "existing-token")

    def test_anonymous_vs_signed_in_token_detection(self) -> None:
        now = int(time.time())
        anon = _make_session_token(now + 3600, is_anonymous=True)
        signed = _make_session_token(now + 3600, is_anonymous=False)
        expired = _make_session_token(now - 60, is_anonymous=False)

        self.assertTrue(is_anonymous_arena_auth_token(anon))
        self.assertFalse(is_signed_in_arena_auth_token(anon))

        self.assertFalse(is_anonymous_arena_auth_token(signed))
        self.assertTrue(is_signed_in_arena_auth_token(signed))

        self.assertFalse(is_signed_in_arena_auth_token(expired))

    def test_extract_arena_verification_url(self) -> None:
        html_body = (
            '<p>Welcome!</p>'
            '<a href="https://arena.ai/nextjs-api/callback/email?token=pkce_abc&amp;type=email&amp;signup_intent_id=2">Verify</a>'
        )
        url = extract_arena_verification_url("", html_body)
        self.assertEqual(
            url,
            "https://arena.ai/nextjs-api/callback/email?token=pkce_abc&type=email&signup_intent_id=2",
        )


class TestAccountRecoveryPersistence(unittest.IsolatedAsyncioTestCase):
    async def test_signup_recovery_persists_managed_account_and_token(self) -> None:
        from src import account_recovery, main

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps({"auth_tokens": ["expired", "added-on-disk"]}))
            token = _make_session_token(int(time.time()) + 3600, is_anonymous=False)
            signup = AsyncMock(return_value=(token, "test-account-password"))
            env = {
                "LM_ALLOW_RECOVERY_IN_TESTS": "1",
                "LM_ARENA_EMAIL": "",
                "LM_ARENA_PASSWORD": "",
                "LM_IMAP_HOST": "imap.example.com",
                "LM_IMAP_USER": "mailbox@example.com",
                "LM_IMAP_PASSWORD": "test-mailbox-password",
                "LM_IMAP_PORT": "993",
                "LM_SIGNUP_EMAIL": "arena@example.com",
            }
            with (
                patch.object(main, "CONFIG_FILE", str(config_path)),
                patch.object(main, "EPHEMERAL_ARENA_AUTH_TOKEN", ""),
                patch.dict(os.environ, env, clear=False),
                patch.object(account_recovery, "signup_arena_email_account", signup),
            ):
                recovered = await account_recovery.recover_arena_auth_session(
                    old_token="expired", config={"auth_tokens": ["expired"]}
                )

            signup.assert_awaited_once()
            self.assertEqual(recovered, token)
            saved = json.loads(config_path.read_text())
            self.assertEqual(saved["auth_tokens"], [token, "added-on-disk"])
            self.assertEqual(saved["managed_account"]["address"], "arena@example.com")
            self.assertEqual(saved["managed_account"]["password"], "test-account-password")


class TestCamoufoxNotInstalledWorkerExit(unittest.IsolatedAsyncioTestCase):
    async def test_camoufox_proxy_worker_exits_and_marks_inactive_when_not_installed(self) -> None:
        from unittest.mock import patch
        from src import main, transport

        class CamoufoxNotInstalled(Exception):
            pass

        class FakeCM:
            async def __aenter__(self):
                raise CamoufoxNotInstalled("official/stable is not installed")

            async def __aexit__(self, exc_type, exc, tb):
                return False

        main.last_userscript_poll = time.time()
        main.USERSCRIPT_PROXY_LAST_POLL_AT = main.last_userscript_poll

        with patch.object(main, "AsyncCamoufox", return_value=FakeCM()):
            await transport.camoufox_proxy_worker()

        self.assertEqual(main.last_userscript_poll, 0.0)
        self.assertEqual(main.USERSCRIPT_PROXY_LAST_POLL_AT, 0.0)
