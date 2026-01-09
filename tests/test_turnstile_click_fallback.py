from tests._stream_test_utils import BaseBridgeTest


class _FakeMouse:
    def __init__(self) -> None:
        self.clicks: list[tuple[float, float]] = []

    async def click(self, x, y):  # noqa: ANN001
        self.clicks.append((float(x), float(y)))


class _FakeElement:
    def __init__(self) -> None:
        self.clicked = 0

    async def content_frame(self):
        return None

    async def bounding_box(self):
        return None

    async def click(self, force=False):  # noqa: FBT002
        self.clicked += 1
        return None


class _FakePage:
    def __init__(self, element: _FakeElement) -> None:
        self._element = element
        self.mouse = _FakeMouse()

    async def query_selector_all(self, selector: str):
        return [self._element] if selector == "#cf-turnstile" else []


class TestTurnstileClickFallback(BaseBridgeTest):
    async def test_click_turnstile_uses_element_click_when_no_bounding_box(self) -> None:
        el = _FakeElement()
        page = _FakePage(el)

        ok = await self.main.click_turnstile(page)

        self.assertTrue(ok)
        self.assertEqual(el.clicked, 1)
        self.assertEqual(page.mouse.clicks, [])

