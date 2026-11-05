import unittest

from src import main, transport


class _FakePage:
    """A page whose in-page fetch cannot report chunks back to Python.

    The in-page script then returns the whole body in its result instead of
    streaming, which is the branch that used to be thrown away.
    """

    body = 'a0:"Hello"\na0:" three"\na0:" words."\nad:{"finishReason":"stop"}'

    def __init__(self) -> None:
        self.evaluate_calls = 0

    async def expose_binding(self, name, fn):  # noqa: ARG002
        return None

    async def evaluate(self, script, arg=None):  # noqa: ARG002
        self.evaluate_calls += 1
        return {"status": 200, "headers": {"content-type": "text/plain"}, "text": self.body}

    async def goto(self, url, wait_until=None, timeout=None):  # noqa: ARG002
        return None

    async def title(self):
        return "Chat with Multiple Frontier AI Models"


class _FakeContext:
    def __init__(self, page) -> None:
        self._page = page

    async def add_init_script(self, script):  # noqa: ARG002
        return None

    async def add_cookies(self, cookies):  # noqa: ARG002
        return None

    async def new_page(self):
        return self._page

    async def close(self):
        return None


class _FakeBrowser:
    def __init__(self, page) -> None:
        self._page = page

    async def new_context(self, **kwargs):  # noqa: ARG002
        return _FakeContext(self._page)

    async def close(self):
        return None


class _FakeCamoufox:
    def __init__(self, page) -> None:
        self._page = page

    async def __aenter__(self):
        return _FakeBrowser(self._page)

    async def __aexit__(self, *exc):
        return False


class TestCamoufoxFetchBufferedBody(unittest.IsolatedAsyncioTestCase):
    async def test_buffered_body_is_returned_when_chunks_cannot_be_reported(self) -> None:
        page = _FakePage()

        async def _noop(*args, **kwargs):
            return None

        async def _cookies(context, page_url=""):  # noqa: ARG001
            return [{"name": "arena-auth-prod-v1", "value": "cookie"}]

        original = {
            "AsyncCamoufox": main.AsyncCamoufox,
            "_get_arena_context_cookies": main._get_arena_context_cookies,
            "_maybe_apply_camoufox_window_mode": main._maybe_apply_camoufox_window_mode,
            "click_turnstile": main.click_turnstile,
            "get_config": main.get_config,
            "get_recaptcha_settings": main.get_recaptcha_settings,
        }
        main.AsyncCamoufox = lambda **kw: _FakeCamoufox(page)  # noqa: ARG005
        main._get_arena_context_cookies = _cookies
        main._maybe_apply_camoufox_window_mode = _noop
        main.click_turnstile = _noop
        main.get_config = lambda: {
            "cf_clearance": "",
            "browser_cookies": {},
            "user_agent": "",
            "camoufox_fetch_headless": True,
        }
        main.get_recaptcha_settings = lambda cfg: ("sitekey", "chat_submit")  # noqa: ARG005
        try:
            response = await transport.fetch_lmarena_stream_via_camoufox(
                http_method="POST",
                url="https://arena.ai/nextjs-api/stream/create-evaluation",
                payload={"userMessage": {"content": "hi"}},
                auth_token="cookie",
                timeout_seconds=5,
            )
        finally:
            for name, value in original.items():
                setattr(main, name, value)

        self.assertIsNotNone(response, "transport must not return None when the fetch succeeded")
        self.assertEqual(response.status_code, 200)
        body = (await response.aread()).decode("utf-8", "replace")
        self.assertIn('a0:"Hello"', body)
        self.assertIn('ad:{"finishReason":"stop"}', body)


if __name__ == "__main__":
    unittest.main()
