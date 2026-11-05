import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


class _FakePage:
    def __init__(self) -> None:
        self.evaluate_calls = 0
        self.wait_calls = 0

    async def evaluate(self, script: str):  # noqa: ARG002
        self.evaluate_calls += 1
        if self.evaluate_calls == 1:
            raise RuntimeError(
                "Page.evaluate: Execution context was destroyed, most likely because of a navigation."
            )
        return "ok"

    async def wait_for_load_state(self, state: str):  # noqa: ARG002
        self.wait_calls += 1


class TestSafePageEvaluate(unittest.IsolatedAsyncioTestCase):
    async def test_safe_page_evaluate_retries_on_execution_context_destroyed(self) -> None:
        from src import main

        page = _FakePage()
        sleep_mock = AsyncMock()

        with patch("src.main.asyncio.sleep", sleep_mock):
            result = await main.safe_page_evaluate(page, "mw:() => true", retries=3)

        self.assertEqual(result, "ok")
        self.assertEqual(page.evaluate_calls, 2)
        self.assertGreaterEqual(page.wait_calls, 1)
        sleep_mock.assert_awaited()

    async def test_safe_page_evaluate_forwards_argument_to_page_evaluate(self) -> None:
        from src import main

        seen: list = []

        class _ArgPage:
            async def evaluate(self, script, arg=None):  # noqa: ARG002
                seen.append(arg)
                return "ok"

        result = await main.safe_page_evaluate(
            _ArgPage(),
            "(sitekey) => sitekey",
            arg="recaptcha-sitekey",
        )

        self.assertEqual(result, "ok")
        self.assertEqual(seen, ["recaptcha-sitekey"])

    async def test_safe_page_evaluate_without_argument_uses_single_arg_evaluate(self) -> None:
        from src import main

        calls: list = []

        class _SingleArgPage:
            async def evaluate(self, script):  # noqa: ARG002
                calls.append(script)
                return "ok"

        result = await main.safe_page_evaluate(_SingleArgPage(), "() => true")

        self.assertEqual(result, "ok")
        self.assertEqual(calls, ["() => true"])

    async def test_recaptcha_script_injection_passes_sitekey_as_argument(self) -> None:
        """Regression: recaptcha.py used to pass an unsupported `recaptcha_sitekey=` kwarg."""
        from src import recaptcha

        source = Path(recaptcha.__file__).read_text(encoding="utf-8")
        self.assertNotIn("recaptcha_sitekey=recaptcha_sitekey,", source)
        self.assertIn("arg=recaptcha_sitekey", source)


if __name__ == "__main__":
    unittest.main()

