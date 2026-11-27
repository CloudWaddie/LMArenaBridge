import base64
from contextlib import ExitStack
import json
import time
from unittest.mock import AsyncMock, patch

import cloudscraper
import httpx
import requests

from tests._stream_test_utils import BaseBridgeTest, FakeStreamResponse


def _make_base64_session_token(expires_at: int, *, urlsafe: bool = False, tag: str = "a") -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": expires_at, "iss": "https://example.supabase.co/auth/v1", "sub": tag}).encode()
    ).decode().rstrip("=")
    session = {"access_token": f"{header}.{payload}.sig_{tag}", "refresh_token": f"rt-{tag}", "expires_at": expires_at}
    if urlsafe:
        session["pad"] = ">>>???"
    raw = json.dumps(session, separators=(",", ":")).encode("utf-8")
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return "base64-" + enc(raw).decode("utf-8").rstrip("=")


def _make_requests_response(status_code: int, body: str) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = body.encode("utf-8")
    resp.url = "https://arena.ai/nextjs-api/stream/create-evaluation"
    return resp


class TestNonStream401TokenRefresh(BaseBridgeTest):
    def _configure(self, token: str) -> None:
        self.setup_config(
            {
                "password": "admin",
                "cf_clearance": "",
                "auth_tokens": [token],
                "api_keys": [{"name": "Test Key", "key": "test-key", "rpm": 999}],
            }
        )

    async def _post_non_stream(self, token: str, *, model: str = "test-model", patches: list = ()):
        self._configure(token)
        models = [{
            "id": "m-1",
            "publicName": model,
            "organization": "test-org",
            "capabilities": {"inputCapabilities": {"text": True}, "outputCapabilities": {"text": True}},
        }]
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.main, "get_models", return_value=models))
            stack.enter_context(patch.object(self.main, "refresh_recaptcha_token", new=AsyncMock(return_value="rc-tok")))
            stack.enter_context(patch.object(self.main, "get_cached_recaptcha_token", return_value="rc-tok"))
            for p in patches:
                stack.enter_context(p)
            transport = httpx.ASGITransport(app=self.main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.post(
                    "/api/v1/chat/completions",
                    headers={"Authorization": "Bearer test-key"},
                    json={"model": model, "messages": [{"role": "user", "content": "hi"}], "stream": False},
                )

    async def test_non_stream_401_refreshes_via_lmarena_http_and_succeeds(self) -> None:
        now = int(time.time())
        old_tok, new_tok = _make_base64_session_token(now + 3600, tag="old"), _make_base64_session_token(now + 7200, tag="new")
        seen_cookies: list[str] = []

        class FakeScraper:
            def post(self, url, json=None, headers=None, timeout=None):  # noqa: A002
                cookie = (headers or {}).get("Cookie", "")
                seen_cookies.append(cookie)
                if new_tok in cookie:
                    return _make_requests_response(200, 'a0:"Hello from refreshed session!"\nad:{"finishReason":"stop"}\n')
                return _make_requests_response(401, '{"error":"Unauthorized"}')

        m_refresh = AsyncMock(return_value=new_tok)
        res = await self._post_non_stream(
            old_tok,
            patches=[
                patch.object(self.main, "refresh_arena_auth_token_via_lmarena_http", new=m_refresh),
                patch.object(cloudscraper, "create_scraper", return_value=FakeScraper()),
            ],
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertNotIn("error", data)
        self.assertEqual(data["choices"][0]["message"]["content"], "Hello from refreshed session!")
        m_refresh.assert_awaited_once()
        self.assertEqual(len(seen_cookies), 2)
        self.assertIn(old_tok, seen_cookies[0])
        self.assertIn(new_tok, seen_cookies[1])
        saved_cfg = self.main.get_config()
        self.assertIn(new_tok, saved_cfg["auth_tokens"])
        self.assertNotIn(old_tok, saved_cfg["auth_tokens"])

    async def test_non_stream_401_falls_back_to_supabase_refresh(self) -> None:
        now = int(time.time())
        old_tok, new_tok = _make_base64_session_token(now + 3600, tag="old2"), _make_base64_session_token(now + 7200, tag="supa")

        class FakeScraper:
            def post(self, url, json=None, headers=None, timeout=None):  # noqa: A002
                if new_tok in (headers or {}).get("Cookie", ""):
                    return _make_requests_response(200, 'a0:"Supabase refresh worked"\nad:{"finishReason":"stop"}\n')
                return _make_requests_response(401, '{"error":"Unauthorized"}')

        m_supa = AsyncMock(return_value=new_tok)
        res = await self._post_non_stream(
            old_tok,
            patches=[
                patch.object(self.main, "refresh_arena_auth_token_via_lmarena_http", new=AsyncMock(return_value=None)),
                patch.object(self.main, "refresh_arena_auth_token_via_supabase", new=m_supa),
                patch.object(cloudscraper, "create_scraper", return_value=FakeScraper()),
            ],
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["choices"][0]["message"]["content"], "Supabase refresh worked")
        m_supa.assert_awaited_once()

    async def test_non_stream_401_exhausted_returns_authentication_error_not_503(self) -> None:
        old_tok = _make_base64_session_token(int(time.time()) + 3600, tag="dead")

        class FakeScraper:
            def post(self, url, json=None, headers=None, timeout=None):  # noqa: A002
                return _make_requests_response(401, '{"error":"Login required","code":"LOGIN_GATE"}')

        res = await self._post_non_stream(
            old_tok,
            patches=[
                patch.object(self.main, "refresh_arena_auth_token_via_lmarena_http", new=AsyncMock(return_value=None)),
                patch.object(self.main, "refresh_arena_auth_token_via_supabase", new=AsyncMock(return_value=None)),
                patch.object(cloudscraper, "create_scraper", return_value=FakeScraper()),
            ],
        )
        self.assertEqual(res.status_code, 200)
        err = res.json()["error"]
        self.assertEqual(err["type"], "authentication_error")
        self.assertEqual(err["code"], "http_401")
        self.assertIn("Login required", err["message"])
        self.assertNotIn("503", err["message"])
        self.assertNotIn("Max retries exceeded", err["message"])

    async def test_non_stream_chrome_fetch_401_refreshes_and_retries(self) -> None:
        now = int(time.time())
        old_tok, new_tok = _make_base64_session_token(now + 3600, tag="strict_old"), _make_base64_session_token(now + 7200, tag="strict_new")
        strict_model = next(iter(self.main.STRICT_CHROME_FETCH_MODELS))

        async def fake_chrome_fetch(*, http_method, url, payload, auth_token, timeout_seconds):
            if auth_token == new_tok:
                return FakeStreamResponse(200, text='a0:"Strict refreshed OK"\nad:{"finishReason":"stop"}\n')
            return FakeStreamResponse(401, text='{"error":"Unauthorized"}')

        res = await self._post_non_stream(
            old_tok,
            model=strict_model,
            patches=[
                patch.object(self.main, "fetch_lmarena_stream_via_chrome", side_effect=fake_chrome_fetch),
                patch.object(self.main, "refresh_arena_auth_token_via_lmarena_http", new=AsyncMock(return_value=new_tok)),
            ],
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["choices"][0]["message"]["content"], "Strict refreshed OK")

    async def test_decode_urlsafe_base64_and_skew_window_refresh(self) -> None:
        now = int(time.time())
        urlsafe_tok = _make_base64_session_token(now + 10, urlsafe=True, tag="skew")
        self.assertTrue("-" in urlsafe_tok[7:] or "_" in urlsafe_tok[7:])
        decoded = self.main._decode_arena_auth_session_token(urlsafe_tok)
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded["refresh_token"], "rt-skew")
        self.assertFalse(self.main.is_probably_valid_arena_auth_token(urlsafe_tok))

        refreshed_tok = _make_base64_session_token(now + 3600, tag="fresh")
        self._configure(urlsafe_tok)
        with patch.object(
            self.main, "refresh_arena_auth_token_via_lmarena_http", new=AsyncMock(return_value=refreshed_tok)
        ) as m_ref:
            got = await self.main.maybe_refresh_expired_auth_tokens()
        self.assertEqual(got, refreshed_tok)
        m_ref.assert_awaited_once()
