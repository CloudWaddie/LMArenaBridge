import unittest
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


class _ArgForwardingPage:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def evaluate(self, script: str, arg=None):
        self.calls.append((script, arg))
        return f"arg={arg}"


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

    async def test_safe_page_evaluate_forwards_optional_arg(self) -> None:
        from src import main

        page = _ArgForwardingPage()
        result = await main.safe_page_evaluate(page, "(k) => k", "sitekey-123")

        self.assertEqual(result, "arg=sitekey-123")
        self.assertEqual(page.calls, [("(k) => k", "sitekey-123")])

    async def test_get_recaptcha_v3_token_script_injection_passes_sitekey_arg(self) -> None:
        from src import main

        captured_evals: list[tuple] = []

        class _InjectPage:
            def __init__(self):
                self.mouse = AsyncMock()

            async def goto(self, *args, **kwargs):
                return None

            async def title(self):
                return "LMArena"

            async def wait_for_load_state(self, *args, **kwargs):
                return None

            async def evaluate(self, script: str, *args):
                captured_evals.append((script, args))
                if len(captured_evals) <= 2:
                    return False  # enterprise and basic grecaptcha missing
                if len(captured_evals) == 3:
                    return True  # script injection call
                if len(captured_evals) == 4:
                    return True  # library ready after injection
                return "x" * 200  # minted token

        class _FakeCamoufoxCtx:
            async def __aenter__(self):
                class _Context:
                    async def add_cookies(self, cookies):
                        return None

                    async def new_page(self):
                        return _InjectPage()

                class _Browser:
                    async def new_context(self):
                        return _Context()

                return _Browser()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        with patch("src.main.get_recaptcha_v3_token_with_chrome", AsyncMock(return_value=None)), \
             patch("src.main.get_config", return_value={"recaptcha_sitekey": "6Ltest_sitekey_123"}), \
             patch("src.main.AsyncCamoufox", return_value=_FakeCamoufoxCtx()), \
             patch("src.recaptcha.asyncio.sleep", AsyncMock()), \
             patch("src.main.asyncio.sleep", AsyncMock()):
            token = await main.get_recaptcha_v3_token()

        self.assertEqual(token, "x" * 200)
        inject_script, inject_args = captured_evals[2]
        self.assertIn("(recaptcha_sitekey) =>", inject_script)
        self.assertEqual(inject_args, ("6Ltest_sitekey_123",))


if __name__ == "__main__":
    unittest.main()

