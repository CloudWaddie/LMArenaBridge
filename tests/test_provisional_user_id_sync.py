from unittest.mock import AsyncMock

from tests._stream_test_utils import BaseBridgeTest


class _FakeContext:
    def __init__(self) -> None:
        self.added: list[dict] | None = None

    async def add_cookies(self, cookies):  # noqa: ANN001
        self.added = list(cookies or [])


class _FakePage:
    def __init__(self) -> None:
        self.evaluate = AsyncMock(return_value=True)


class TestProvisionalUserIdSync(BaseBridgeTest):
    async def test_sets_cookie_and_localstorage(self) -> None:
        page = _FakePage()
        context = _FakeContext()

        await self.main._set_provisional_user_id_in_browser(page, context, provisional_user_id="prov-1")

        self.assertIsInstance(context.added, list)
        self.assertTrue(context.added)
        self.assertEqual(len(context.added), 4)
        values = {c.get("value") for c in context.added}
        self.assertEqual(values, {"prov-1"})
        names = {c.get("name") for c in context.added}
        self.assertEqual(names, {"provisional_user_id"})
        urls = {str(c.get("url") or "") for c in context.added if c.get("url")}
        domains = {str(c.get("domain") or "") for c in context.added if c.get("domain")}
        self.assertIn("https://lmarena.ai", urls)
        self.assertIn("https://arena.ai", urls)
        self.assertIn(".lmarena.ai", domains)
        self.assertIn(".arena.ai", domains)

        page.evaluate.assert_awaited()
        script_arg, value_arg = page.evaluate.call_args.args
        self.assertIn("localStorage.setItem", str(script_arg))
        self.assertEqual(value_arg, "prov-1")
