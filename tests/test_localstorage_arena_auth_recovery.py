from tests._stream_test_utils import BaseBridgeTest


class _FakeContext:
    def __init__(self) -> None:
        self.added: list[dict] | None = None

    async def add_cookies(self, cookies):  # noqa: ANN001
        self.added = list(cookies or [])


class _FakePage:
    def __init__(self, store: dict) -> None:
        self._store = store

    async def evaluate(self, script, arg=None):  # noqa: ANN001,ARG002
        return self._store


class TestLocalStorageArenaAuthRecovery(BaseBridgeTest):
    async def test_injects_arena_auth_cookie_from_localstorage_session(self) -> None:
        session_json = '{"access_token":"a","refresh_token":"b","expires_at":9999999999}'
        page = _FakePage({"sb-test-auth-token": session_json})
        context = _FakeContext()

        injected = await self.main._maybe_inject_arena_auth_cookie_from_localstorage(page, context)

        self.assertIsInstance(injected, str)
        self.assertTrue(injected.startswith("base64-"))
        self.assertIsInstance(context.added, list)
        self.assertTrue(context.added)
        self.assertEqual(len(context.added), 2)
        urls = {str(c.get("url") or "") for c in context.added if c.get("url")}
        self.assertIn("https://lmarena.ai", urls)
        self.assertIn("https://arena.ai", urls)
        for cookie in context.added:
            self.assertEqual(cookie.get("name"), "arena-auth-prod-v1")
            self.assertEqual(cookie.get("value"), injected)

