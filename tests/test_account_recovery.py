import base64
import json
import time
import unittest

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
