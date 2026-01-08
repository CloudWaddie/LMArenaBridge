from tests._stream_test_utils import BaseBridgeTest


class _FakePage:
    def __init__(self) -> None:
        self.evaluate_calls: list[tuple[tuple, dict]] = []

    async def evaluate(self, *args, **kwargs):  # noqa: ANN001, D401
        self.evaluate_calls.append((args, kwargs))
        return None


class TestCamoufoxWindowMode(BaseBridgeTest):
    async def test_camoufox_proxy_window_mode_hide_calls_win32_helper(self) -> None:
        from unittest.mock import patch

        page = _FakePage()
        config = self.main.get_config()
        config["camoufox_proxy_window_mode"] = "hide"

        with (
            patch.object(self.main, "_is_windows", return_value=True),
            patch.object(self.main, "_windows_apply_window_mode_by_title_substring", return_value=True) as hide,
        ):
            await self.main._maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="camoufox_proxy_window_mode",
                marker="TEST_TITLE",
                headless=False,
            )

            self.assertTrue(page.evaluate_calls, "Expected page.evaluate to be called to set the title marker")
            args, _kwargs = page.evaluate_calls[0]
            self.assertIn("document.title", str(args[0]))
            self.assertEqual("TEST_TITLE", args[1])
            hide.assert_called_with("TEST_TITLE", "hide")

    async def test_camoufox_proxy_window_mode_visible_is_noop(self) -> None:
        from unittest.mock import patch

        page = _FakePage()
        config = self.main.get_config()
        config["camoufox_proxy_window_mode"] = "visible"

        with (
            patch.object(self.main, "_is_windows", return_value=True),
            patch.object(self.main, "_windows_apply_window_mode_by_title_substring", return_value=True) as hide,
        ):
            await self.main._maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="camoufox_proxy_window_mode",
                marker="TEST_TITLE",
                headless=False,
            )

            self.assertEqual(page.evaluate_calls, [])
            hide.assert_not_called()

    async def test_camoufox_proxy_window_mode_headless_is_noop(self) -> None:
        from unittest.mock import patch

        page = _FakePage()
        config = self.main.get_config()
        config["camoufox_proxy_window_mode"] = "hide"

        with (
            patch.object(self.main, "_is_windows", return_value=True),
            patch.object(self.main, "_windows_apply_window_mode_by_title_substring", return_value=True) as hide,
        ):
            await self.main._maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="camoufox_proxy_window_mode",
                marker="TEST_TITLE",
                headless=True,
            )

            self.assertEqual(page.evaluate_calls, [])
            hide.assert_not_called()

