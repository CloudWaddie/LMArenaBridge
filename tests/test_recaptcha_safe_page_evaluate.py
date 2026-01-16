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


if __name__ == "__main__":
    unittest.main()

