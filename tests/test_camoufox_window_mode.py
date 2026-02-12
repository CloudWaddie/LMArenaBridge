from tests._stream_test_utils import BaseBridgeTest


class _FakePage:
    def __init__(self) -> None:
        self.evaluate_calls: list[tuple[tuple, dict]] = []

    async def evaluate(self, *args, **kwargs):  # noqa: ANN001, D401
        self.evaluate_calls.append((args, kwargs))
        return None


class TestCamoufoxWindowMode(BaseBridgeTest):
    async def test_get_config_defaults_camoufox_window_modes_hide(self) -> None:
        config = self.main.get_config()
        self.assertEqual("hide", config.get("camoufox_proxy_window_mode"))
        self.assertEqual("hide", config.get("camoufox_fetch_window_mode"))

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

    async def test_windows_hide_mode_removes_taskbar_and_moves_offscreen(self) -> None:
        import ctypes
        import os
        from ctypes import wintypes

        if not self.main._is_windows():
            self.skipTest("Windows-only window-style test")

        user32 = ctypes.WinDLL("user32", use_last_error=True)

        WS_OVERLAPPEDWINDOW = 0x00CF0000
        WS_VISIBLE = 0x10000000
        WS_EX_TOOLWINDOW = 0x00000080
        WS_EX_APPWINDOW = 0x00040000
        GWL_EXSTYLE = -20

        CreateWindowExW = user32.CreateWindowExW
        CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        CreateWindowExW.restype = wintypes.HWND

        if hasattr(user32, "GetWindowLongPtrW"):
            GetWindowLongPtr = user32.GetWindowLongPtrW
            GetWindowLongPtr.restype = ctypes.c_ssize_t
        else:
            GetWindowLongPtr = user32.GetWindowLongW
            GetWindowLongPtr.restype = ctypes.c_long
        GetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int]

        class RECT(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        GetWindowRect = user32.GetWindowRect
        GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
        GetWindowRect.restype = wintypes.BOOL

        DestroyWindow = user32.DestroyWindow
        DestroyWindow.argtypes = [wintypes.HWND]
        DestroyWindow.restype = wintypes.BOOL

        marker = f"LMArenaBridge Camoufox Hide Test PID {os.getpid()}"
        hwnd = CreateWindowExW(
            WS_EX_APPWINDOW,
            "STATIC",
            marker,
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            100,
            100,
            260,
            180,
            0,
            0,
            0,
            None,
        )
        self.assertTrue(hwnd, f"CreateWindowExW failed with Win32 error {ctypes.get_last_error()}")

        try:
            matched = self.main._windows_apply_window_mode_by_title_substring(marker, "hide")
            self.assertTrue(matched, "Expected hide helper to find and process dummy window")

            exstyle = int(GetWindowLongPtr(hwnd, GWL_EXSTYLE) or 0) & 0xFFFFFFFF
            self.assertTrue(exstyle & WS_EX_TOOLWINDOW, f"Expected WS_EX_TOOLWINDOW in exstyle: 0x{exstyle:08x}")
            self.assertFalse(exstyle & WS_EX_APPWINDOW, f"Expected WS_EX_APPWINDOW cleared in exstyle: 0x{exstyle:08x}")

            rect = RECT()
            self.assertTrue(GetWindowRect(hwnd, ctypes.byref(rect)), "GetWindowRect failed")
            self.assertLessEqual(rect.left, -30000)
            self.assertLessEqual(rect.top, -30000)
        finally:
            DestroyWindow(hwnd)

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

