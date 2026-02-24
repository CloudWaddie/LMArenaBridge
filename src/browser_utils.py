"""
Browser and OS window utility functions for LMArenaBridge.

Handles:
- Windows OS window hiding/minimizing (ctypes, no extra deps)
- Camoufox/Playwright page window mode application
- Cloudflare Turnstile clicking
- Safe page evaluation with retry logic
- Async task lifecycle helpers
"""

import asyncio
import os
import sys
from typing import Optional


def _is_windows() -> bool:
    return os.name == "nt" or sys.platform == "win32"


def _normalize_camoufox_window_mode(value: object) -> str:
    mode = str(value or "").strip().lower()
    if mode in ("hide", "hidden"):
        return "hide"
    if mode in ("minimize", "minimized"):
        return "minimize"
    if mode in ("offscreen", "off-screen", "moveoffscreen", "move-offscreen"):
        return "offscreen"
    return "visible"


def _windows_apply_window_mode_by_title_substring(title_substring: str, mode: str) -> bool:
    """
    Best-effort: hide/minimize/move-offscreen top-level windows whose title contains `title_substring`.

    Intended for Windows only. Avoids new dependencies (pywin32/psutil) by using ctypes.
    """
    if not _is_windows():
        return False
    if not isinstance(title_substring, str) or not title_substring.strip():
        return False
    normalized_mode = _normalize_camoufox_window_mode(mode)
    if normalized_mode == "visible":
        return False

    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return False

    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
    except Exception:
        return False

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    EnumWindows = user32.EnumWindows
    EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    EnumWindows.restype = wintypes.BOOL

    IsWindowVisible = user32.IsWindowVisible
    IsWindowVisible.argtypes = [wintypes.HWND]
    IsWindowVisible.restype = wintypes.BOOL

    GetWindowTextLengthW = user32.GetWindowTextLengthW
    GetWindowTextLengthW.argtypes = [wintypes.HWND]
    GetWindowTextLengthW.restype = ctypes.c_int

    GetWindowTextW = user32.GetWindowTextW
    GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    GetWindowTextW.restype = ctypes.c_int

    ShowWindow = user32.ShowWindow
    ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    ShowWindow.restype = wintypes.BOOL

    long_ptr_t = ctypes.c_ssize_t
    if hasattr(user32, "GetWindowLongPtrW") and hasattr(user32, "SetWindowLongPtrW"):
        GetWindowLongPtr = user32.GetWindowLongPtrW
        SetWindowLongPtr = user32.SetWindowLongPtrW
    else:
        GetWindowLongPtr = user32.GetWindowLongW
        SetWindowLongPtr = user32.SetWindowLongW
        long_ptr_t = ctypes.c_long

    GetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int]
    GetWindowLongPtr.restype = long_ptr_t

    SetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int, long_ptr_t]
    SetWindowLongPtr.restype = long_ptr_t

    SetWindowPos = user32.SetWindowPos
    SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    SetWindowPos.restype = wintypes.BOOL

    SW_MINIMIZE = 6
    GWL_EXSTYLE = -20
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_APPWINDOW = 0x00040000
    SWP_NOSIZE = 0x0001
    SWP_NOZORDER = 0x0004
    SWP_NOACTIVATE = 0x0010
    SWP_FRAMECHANGED = 0x0020

    needle = title_substring.casefold()
    matched = {"any": False}

    @WNDENUMPROC
    def _cb(hwnd, lparam):  # noqa: ANN001
        try:
            if not IsWindowVisible(hwnd):
                return True
            length = int(GetWindowTextLengthW(hwnd) or 0)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            if GetWindowTextW(hwnd, buf, length + 1) <= 0:
                return True
            title = str(buf.value or "")
            if needle not in title.casefold():
                return True
            matched["any"] = True

            if normalized_mode == "hide":
                # Avoid SW_HIDE: it can trigger occlusion/throttling behavior that breaks anti-bot challenges.
                # Remove taskbar/Alt-Tab presence (tool window, not app window), while keeping it headful.
                try:
                    current_exstyle = int(GetWindowLongPtr(hwnd, GWL_EXSTYLE) or 0)
                    desired_exstyle = (current_exstyle | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW
                    if desired_exstyle != current_exstyle:
                        SetWindowLongPtr(hwnd, GWL_EXSTYLE, long_ptr_t(desired_exstyle))
                except Exception as ex:
                    from . import main as _main  # late import to avoid circularity
                    try:
                        _main.debug_print(f"Windows hide mode exstyle update failed: {ex}")
                    except Exception:
                        pass
                SetWindowPos(
                    hwnd,
                    0,
                    -32000,
                    -32000,
                    0,
                    0,
                    SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                )
            elif normalized_mode == "minimize":
                ShowWindow(hwnd, SW_MINIMIZE)
            elif normalized_mode == "offscreen":
                SetWindowPos(hwnd, 0, -32000, -32000, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
        except Exception:
            return True
        return True

    try:
        EnumWindows(_cb, 0)
    except Exception:
        return False
    return bool(matched["any"])


async def _maybe_apply_camoufox_window_mode(
    page,
    config: dict,
    *,
    mode_key: str,
    marker: str,
    headless: bool,
) -> None:
    """
    Best-effort: keep browser headed (for bot-score reliability) while hiding the actual OS window on Windows.

    Calls _is_windows and _windows_apply_window_mode_by_title_substring via main module so that
    tests patching main.X still work correctly.
    """
    # Late import so tests can patch main._is_windows / main._windows_apply_window_mode_by_title_substring
    from . import main as _main

    if headless:
        return
    if not _main._is_windows():
        return
    cfg = config or {}
    mode = _normalize_camoufox_window_mode(cfg.get(mode_key))
    if mode == "visible":
        return

    marker_str = str(marker)

    # The OS window title reflects the *active tab*. In persistent contexts, a new page may not
    # become active immediately; set the title marker across all known pages best-effort.
    pages_to_mark: list = []
    try:
        pages_to_mark.append(page)
    except Exception:
        pages_to_mark = []
    try:
        ctx = getattr(page, "context", None)
        if callable(ctx):
            ctx = ctx()
        ctx_pages = getattr(ctx, "pages", None) if ctx is not None else None
        if callable(ctx_pages):
            ctx_pages = ctx_pages()
        if isinstance(ctx_pages, list) and ctx_pages:
            pages_to_mark.extend(ctx_pages)
    except Exception:
        pass

    seen: set[int] = set()
    unique_pages: list = []
    for p in pages_to_mark:
        try:
            pid = id(p)
        except Exception:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        unique_pages.append(p)

    for p in unique_pages:
        try:
            await p.evaluate("t => { document.title = t; }", marker_str)
        except Exception:
            continue

    # Try a short synchronous window-scan first; if it races window creation, continue in background.
    for _ in range(20):  # ~2s worst-case
        if _main._windows_apply_window_mode_by_title_substring(marker_str, mode):
            return
        await asyncio.sleep(0.1)

    async def _late_apply() -> None:
        for _ in range(180):  # ~18s best-effort
            if _main._windows_apply_window_mode_by_title_substring(marker_str, mode):
                return
            await asyncio.sleep(0.1)

    try:
        asyncio.create_task(_late_apply())
    except Exception:
        return


async def click_turnstile(page) -> bool:
    """
    Attempts to locate and click the Cloudflare Turnstile widget.
    Based on gpt4free logic.
    """
    from . import main as _main  # late import to avoid circularity
    _main.debug_print("  🖱️  Attempting to click Cloudflare Turnstile...")
    try:
        # Common selectors used by LMArena's Turnstile implementation
        selectors = [
            '#lm-bridge-turnstile',
            '#lm-bridge-turnstile iframe',
            '#cf-turnstile',
            'iframe[src*="challenges.cloudflare.com"]',
            '[style*="display: grid"] iframe'  # The grid style often wraps the checkbox
        ]

        for selector in selectors:
            try:
                # Playwright pages support `query_selector_all`, but our unit-test stubs may only implement
                # `query_selector`. Support both for robustness.
                query_all = getattr(page, "query_selector_all", None)
                if callable(query_all):
                    elements = await query_all(selector)
                else:
                    one = await page.query_selector(selector)
                    elements = [one] if one else []
            except Exception:
                try:
                    one = await page.query_selector(selector)
                    elements = [one] if one else []
                except Exception:
                    elements = []
            for element in elements or []:
                # If this is a Turnstile iframe, try clicking within the frame first.
                try:
                    frame = await element.content_frame()
                except Exception:
                    frame = None

                if frame is not None:
                    inner_selectors = [
                        "input[type='checkbox']",
                        "div[role='checkbox']",
                        "label",
                    ]
                    for inner_sel in inner_selectors:
                        try:
                            inner = await frame.query_selector(inner_sel)
                            if inner:
                                try:
                                    await inner.click(force=True)
                                except TypeError:
                                    await inner.click()
                                await asyncio.sleep(2)
                                return True
                        except Exception:
                            continue

                # If the OS window is hidden/occluded, Playwright may return no bounding box even when the element is
                # present. Try a direct element click first (force) before relying on geometry.
                try:
                    try:
                        await element.click(force=True)
                    except TypeError:
                        await element.click()
                    await asyncio.sleep(2)
                    return True
                except Exception:
                    pass

                # Get bounding box to click specific coordinates if needed
                try:
                    box = await element.bounding_box()
                except Exception:
                    box = None
                if box:
                    x = box['x'] + (box['width'] / 2)
                    y = box['y'] + (box['height'] / 2)
                    _main.debug_print(f"  🎯 Found widget at {x},{y}. Clicking...")
                    await page.mouse.click(x, y)
                    await asyncio.sleep(2)
                    return True
        return False
    except Exception as e:
        _main.debug_print(f"  ⚠️ Error clicking turnstile: {e}")
        return False


def is_execution_context_destroyed_error(exc: BaseException) -> bool:
    message = str(exc)
    return "Execution context was destroyed" in message


async def safe_page_evaluate(page, script: str, retries: int = 3):
    retries = max(1, min(int(retries), 5))
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            return await page.evaluate(script)
        except Exception as e:
            last_exc = e
            if is_execution_context_destroyed_error(e) and attempt < retries - 1:
                try:
                    await page.wait_for_load_state("domcontentloaded")
                except Exception:
                    pass
                await asyncio.sleep(0.25)
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Page.evaluate failed")


def _consume_background_task_exception(task: "asyncio.Task") -> None:
    try:
        task.exception()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


async def _cancel_background_task(task: Optional["asyncio.Task"], *, timeout_seconds: float = 1.0) -> None:
    if task is None:
        return
    if task.done():
        _consume_background_task_exception(task)
        return

    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=float(timeout_seconds))
    except Exception:
        pass

    if task.done():
        _consume_background_task_exception(task)
    else:
        try:
            task.add_done_callback(_consume_background_task_exception)
        except Exception:
            pass
