import asyncio
import os
import sys
import shutil
import json
import time
import re
import uuid
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import httpx
from camoufox.async_api import AsyncCamoufox

try:
    from . import globals
    from . import config
    from . import auth
    from . import models
    from . import proxy
    from .utils import debug_print, get_rate_limit_sleep_seconds, HTTPStatus, BrowserFetchStreamResponse
except ImportError:
    import globals
    import config
    import auth
    import models
    import proxy
    from utils import debug_print, get_rate_limit_sleep_seconds, HTTPStatus, BrowserFetchStreamResponse

# Models that should always use the in-browser (Chrome fetch) transport for streaming.
# These are especially sensitive to reCAPTCHA / bot scoring and are much more reliable when executed in-page.
STRICT_CHROME_FETCH_MODELS = {
    "gemini-3-pro-grounding",
    "gemini-exp-1206",
}

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
    SWP_NOSIZE = 0x0001
    SWP_NOZORDER = 0x0004
    SWP_NOACTIVATE = 0x0010

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
                # "Hide" behaves like "offscreen" on Windows for better reliability.
                SetWindowPos(hwnd, 0, -32000, -32000, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
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
    cfg: dict,
    *,
    mode_key: str,
    marker: str,
    headless: bool,
) -> None:
    """
    Best-effort: keep Camoufox headed (for bot-score reliability) while hiding the actual OS window on Windows.
    """
    if headless:
        return
    if not _is_windows():
        return
    cfg = cfg or {}
    mode = _normalize_camoufox_window_mode(cfg.get(mode_key))
    if mode == "visible":
        return
    try:
        await page.evaluate("t => { document.title = t; }", str(marker))
    except Exception:
        pass
    for _ in range(20):  # ~2s worst-case
        if _windows_apply_window_mode_by_title_substring(str(marker), mode):
            return
        await asyncio.sleep(0.1)


async def click_turnstile(page):
    """
    Attempts to locate and click the Cloudflare Turnstile widget.
    Based on gpt4free logic.
    """
    debug_print("  🖱️  Attempting to click Cloudflare Turnstile...")
    try:
        # Common selectors used by LMArena's Turnstile implementation
        selectors = [
            '#lm-bridge-turnstile',
            '#lm-bridge-turnstile iframe',
            '#cf-turnstile',
            'iframe[src*="challenges.cloudflare.com"]',
            '[style*="display: grid"] iframe' # The grid style often wraps the checkbox
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
                    debug_print(f"  🎯 Found widget at {x},{y}. Clicking...")
                    await page.mouse.click(x, y)
                    await asyncio.sleep(2)
                    return True
        return False
    except Exception as e:
        debug_print(f"  ⚠️ Error clicking turnstile: {e}")
        return False

def find_chrome_executable() -> Optional[str]:
    configured = str(os.environ.get("CHROME_PATH") or "").strip()
    if configured and Path(configured).exists():
        return configured

    candidates = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        / "Google"
        / "Chrome"
        / "Application"
        / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
        / "Google"
        / "Chrome"
        / "Application"
        / "chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Google"
        / "Chrome"
        / "Application"
        / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    for name in ("google-chrome", "chrome", "chromium", "chromium-browser", "msedge"):
        resolved = shutil.which(name)
        if resolved:
            return resolved

    return None

async def get_recaptcha_v3_token_with_chrome(cfg: dict) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return None

    chrome_path = find_chrome_executable()
    if not chrome_path:
        return None

    profile_dir = Path(globals.CONFIG_FILE).with_name("chrome_grecaptcha")

    cf_clearance = str(cfg.get("cf_clearance") or "").strip()
    cf_bm = str(cfg.get("cf_bm") or "").strip()
    cfuvid = str(cfg.get("cfuvid") or "").strip()
    provisional_user_id = str(cfg.get("provisional_user_id") or "").strip()
    user_agent = auth.normalize_user_agent_value(cfg.get("user_agent"))
    recaptcha_sitekey, recaptcha_action = auth.get_recaptcha_settings(cfg)

    cookies = []
    if cf_clearance:
        cookies.append({"name": "cf_clearance", "value": cf_clearance, "domain": ".lmarena.ai", "path": "/"})
    if cf_bm:
        cookies.append({"name": "__cf_bm", "value": cf_bm, "domain": ".lmarena.ai", "path": "/"})
    if cfuvid:
        cookies.append({"name": "_cfuvid", "value": cfuvid, "domain": ".lmarena.ai", "path": "/"})
    if provisional_user_id:
        cookies.append(
            {"name": "provisional_user_id", "value": provisional_user_id, "domain": ".lmarena.ai", "path": "/"}
        )

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            executable_path=chrome_path,
            headless=False,  # Headful for better reCAPTCHA score/warmup
            user_agent=user_agent or None,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )
        try:
            # Small stealth tweak: reduces bot-detection surface for reCAPTCHA v3 scoring.
            try:
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
            except Exception:
                pass

            if cookies:
                try:
                    existing_names: set[str] = set()
                    try:
                        existing = await context.cookies("https://lmarena.ai")
                        for c in existing or []:
                            name = c.get("name")
                            if name:
                                existing_names.add(str(name))
                    except Exception:
                        existing_names = set()

                    cookies_to_add: list[dict] = []
                    for c in cookies:
                        name = str(c.get("name") or "")
                        if not name:
                            continue
                        # Always ensure the auth cookie matches the selected upstream token.
                        if name == "arena-auth-prod-v1":
                            cookies_to_add.append(c)
                            continue

                        # Do NOT overwrite/inject Cloudflare or reCAPTCHA cookies in the persistent profile.
                        # The profile manages these itself; injecting stale ones from config causes 403s.
                        if name in ("cf_clearance", "__cf_bm", "_GRECAPTCHA"):
                            continue

                        # Avoid overwriting existing Cloudflare/session cookies in the persistent profile.
                        if name in existing_names:
                            continue
                        cookies_to_add.append(c)

                    if cookies_to_add:
                        await context.add_cookies(cookies_to_add)
                except Exception:
                    pass

            page = await context.new_page()
            await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)

            # Best-effort: if we land on a Cloudflare challenge page, try clicking Turnstile.
            try:
                for _ in range(5):
                    title = await page.title()
                    if "Just a moment" not in title:
                        break
                    await click_turnstile(page)
                    await asyncio.sleep(2)
            except Exception:
                pass

            # Light warm-up (often improves reCAPTCHA v3 score vs firing immediately).
            try:
                await page.mouse.move(100, 100)
                await page.mouse.wheel(0, 200)
                await asyncio.sleep(1)
                await page.mouse.move(200, 300)
                await page.mouse.wheel(0, 300)
                await asyncio.sleep(3) # Increased "Human" pause
            except Exception:
                pass

            # Persist updated cookies/UA from this real browser context (often refreshes arena-auth-prod-v1).
            try:
                fresh_cookies = await context.cookies("https://lmarena.ai")
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if config._upsert_browser_session_into_config(cfg, fresh_cookies, user_agent=ua_now):
                    config.save_config(cfg)
            except Exception:
                pass

            await page.wait_for_function(
                "window.grecaptcha && ("
                "(window.grecaptcha.enterprise && typeof window.grecaptcha.enterprise.execute === 'function') || "
                "typeof window.grecaptcha.execute === 'function'"
                ")",
                timeout=60000,
            )

            token = await page.evaluate(
                """({sitekey, action}) => new Promise((resolve, reject) => {
                  const g = (window.grecaptcha?.enterprise && typeof window.grecaptcha.enterprise.execute === 'function')
                    ? window.grecaptcha.enterprise
                    : window.grecaptcha;
                  if (!g || typeof g.execute !== 'function') return reject('NO_GRECAPTCHA');
                  try {
                    g.execute(sitekey, { action }).then(resolve).catch((err) => reject(String(err)));
                  } catch (e) { reject(String(e)); }
                })""",
                {"sitekey": recaptcha_sitekey, "action": recaptcha_action},
            )
            if isinstance(token, str) and token:
                return token
            return None
        except Exception as e:
            debug_print(f"⚠️ Chrome reCAPTCHA retrieval failed: {e}")
            return None
        finally:
            await context.close()

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

async def fetch_lmarena_stream_via_chrome(
    http_method: str,
    url: str,
    payload: dict,
    auth_token: str,
    timeout_seconds: int = 120,
    headless: bool = False, # Default to Headful for better reliability
    max_recaptcha_attempts: int = 3,
) -> Optional[BrowserFetchStreamResponse]:
    """
    Fallback transport: perform the stream request via in-browser fetch (Chrome/Edge via Playwright).
    This tends to align cookies/UA/TLS with what LMArena expects and can reduce reCAPTCHA flakiness.
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return None

    chrome_path = find_chrome_executable()
    if not chrome_path:
        return None

    cfg = config.get_config()
    recaptcha_sitekey, recaptcha_action = auth.get_recaptcha_settings(cfg)

    cookie_store = cfg.get("browser_cookies")
    cookie_map: dict[str, str] = {}
    if isinstance(cookie_store, dict):
        for name, value in cookie_store.items():
            if not name or not value:
                continue
            cookie_map[str(name)] = str(value)

    # Prefer the Chrome persistent profile's own Cloudflare/BM cookies when present.
    # We only inject missing cookies to avoid overwriting a valid cf_clearance/__cf_bm with stale values
    # coming from a different browser fingerprint.
    cf_clearance = str(cfg.get("cf_clearance") or cookie_map.get("cf_clearance") or "").strip()
    cf_bm = str(cfg.get("cf_bm") or cookie_map.get("__cf_bm") or "").strip()
    cfuvid = str(cfg.get("cfuvid") or cookie_map.get("_cfuvid") or "").strip()
    provisional_user_id = str(cfg.get("provisional_user_id") or cookie_map.get("provisional_user_id") or "").strip()
    grecaptcha_cookie = str(cookie_map.get("_GRECAPTCHA") or "").strip()

    desired_cookies: list[dict] = []
    if cf_clearance:
        desired_cookies.append({"name": "cf_clearance", "value": cf_clearance, "domain": ".lmarena.ai", "path": "/"})
    if cf_bm:
        desired_cookies.append({"name": "__cf_bm", "value": cf_bm, "domain": ".lmarena.ai", "path": "/"})
    if cfuvid:
        desired_cookies.append({"name": "_cfuvid", "value": cfuvid, "domain": ".lmarena.ai", "path": "/"})
    if provisional_user_id:
        desired_cookies.append(
            {"name": "provisional_user_id", "value": provisional_user_id, "domain": ".lmarena.ai", "path": "/"}
        )
    if grecaptcha_cookie:
        desired_cookies.append({"name": "_GRECAPTCHA", "value": grecaptcha_cookie, "domain": ".lmarena.ai", "path": "/"})
    if auth_token:
        # arena-auth-prod-v1 is commonly stored as a host-only cookie on `lmarena.ai` (no leading dot).
        desired_cookies.append({"name": "arena-auth-prod-v1", "value": auth_token, "domain": "lmarena.ai", "path": "/"})

    user_agent = auth.normalize_user_agent_value(cfg.get("user_agent"))

    fetch_url = url
    if fetch_url.startswith("https://lmarena.ai"):
        fetch_url = fetch_url[len("https://lmarena.ai") :]
    if not fetch_url.startswith("/"):
        fetch_url = "/" + fetch_url

    def _is_recaptcha_validation_failed(status: int, text: object) -> bool:
        if int(status or 0) != HTTPStatus.FORBIDDEN:
            return False
        if not isinstance(text, str) or not text:
            return False
        try:
            body = json.loads(text)
        except Exception:
            return False
        return isinstance(body, dict) and body.get("error") == "recaptcha validation failed"

    max_recaptcha_attempts = max(1, min(int(max_recaptcha_attempts), 10))

    profile_dir = Path(globals.CONFIG_FILE).with_name("chrome_grecaptcha")
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            executable_path=chrome_path,
            headless=bool(headless),
            user_agent=user_agent or None,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )
        try:
            # Small stealth tweak: reduces bot-detection surface for reCAPTCHA v3 scoring.
            try:
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
            except Exception:
                pass

            if desired_cookies:
                try:
                    existing_names: set[str] = set()
                    try:
                        existing = await context.cookies("https://lmarena.ai")
                        for c in existing or []:
                            name = c.get("name")
                            if name:
                                existing_names.add(str(name))
                    except Exception:
                        existing_names = set()

                    cookies_to_add: list[dict] = []
                    for c in desired_cookies:
                        name = str(c.get("name") or "")
                        if not name:
                            continue
                        # Always ensure the auth cookie matches the selected upstream token.
                        if name == "arena-auth-prod-v1":
                            cookies_to_add.append(c)
                            continue

                        # Do NOT overwrite/inject Cloudflare or reCAPTCHA cookies in the persistent profile.
                        # The profile manages these itself; injecting stale ones from config causes 403s.
                        if name in ("cf_clearance", "__cf_bm", "_GRECAPTCHA"):
                            continue

                        # Avoid overwriting existing Cloudflare/session cookies in the persistent profile.
                        if name in existing_names:
                            continue
                        cookies_to_add.append(c)

                    if cookies_to_add:
                        await context.add_cookies(cookies_to_add)
                except Exception:
                    pass

            page = await context.new_page()
            await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)

            # Best-effort: if we land on a Cloudflare challenge page, try clicking Turnstile before minting tokens.
            try:
                for i in range(10): # Up to 30 seconds
                    title = await page.title()
                    if "Just a moment" not in title:
                        break
                    debug_print(f"  ⏳ Waiting for Cloudflare challenge in Chrome... (attempt {i+1}/10)")
                    await click_turnstile(page)
                    await asyncio.sleep(3)
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=15000)
                except Exception:
                    pass
            except Exception:
                pass

            # Light warm-up (often improves reCAPTCHA v3 score vs firing immediately).
            try:
                await page.mouse.move(100, 100)
                await asyncio.sleep(0.5)
                await page.mouse.wheel(0, 200)
                await asyncio.sleep(1)
                await page.mouse.move(200, 300)
                await asyncio.sleep(0.5)
                await page.mouse.wheel(0, 300)
                await asyncio.sleep(2) # Reduced "Human" pause for faster response
            except Exception:
                pass

            # Persist updated cookies/UA from this browser context (helps keep auth + cf cookies fresh).
            try:
                fresh_cookies = await context.cookies("https://lmarena.ai")
                auth._capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if config._upsert_browser_session_into_config(cfg, fresh_cookies, user_agent=ua_now):
                    config.save_config(cfg)
            except Exception:
                pass

            async def _mint_recaptcha_v3_token() -> Optional[str]:
                await page.wait_for_function(
                    "window.grecaptcha && ("
                    "(window.grecaptcha.enterprise && typeof window.grecaptcha.enterprise.execute === 'function') || "
                    "typeof window.grecaptcha.execute === 'function'"
                    ")",
                    timeout=60000,
                )
                token = await page.evaluate(
                    """({sitekey, action}) => new Promise((resolve, reject) => {
                      const g = (window.grecaptcha?.enterprise && typeof window.grecaptcha.enterprise.execute === 'function')
                        ? window.grecaptcha.enterprise
                        : window.grecaptcha;
                      if (!g || typeof g.execute !== 'function') return reject('NO_GRECAPTCHA');
                      try {
                        g.execute(sitekey, { action }).then(resolve).catch((err) => reject(String(err)));
                      } catch (e) { reject(String(e)); }
                    })""",
                    {"sitekey": recaptcha_sitekey, "action": recaptcha_action},
                )
                if isinstance(token, str) and token:
                    return token
                return None

            async def _mint_recaptcha_v2_token() -> Optional[str]:
                """
                Best-effort: try to obtain a reCAPTCHA Enterprise v2 token (checkbox/invisible).
                LMArena falls back to v2 when v3 scoring is rejected.
                """
                try:
                    await page.wait_for_function(
                        "window.grecaptcha && window.grecaptcha.enterprise && typeof window.grecaptcha.enterprise.render === 'function'",
                        timeout=60000,
                    )
                except Exception:
                    return None

                token = await page.evaluate(
                    """({sitekey, timeoutMs}) => new Promise((resolve, reject) => {
                      const g = window.grecaptcha?.enterprise;
                      if (!g || typeof g.render !== 'function') return reject('NO_GRECAPTCHA_V2');
                      let settled = false;
                      const done = (fn, arg) => {
                        if (settled) return;
                        settled = true;
                        fn(arg);
                      };
                      try {
                        const el = document.createElement('div');
                        el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;';
                        document.body.appendChild(el);
                        const timer = setTimeout(() => done(reject, 'V2_TIMEOUT'), timeoutMs || 60000);
                        const wid = g.render(el, {
                          sitekey,
                          size: 'invisible',
                          callback: (tok) => { clearTimeout(timer); done(resolve, tok); },
                          'error-callback': () => { clearTimeout(timer); done(reject, 'V2_ERROR'); },
                        });
                        try {
                          if (typeof g.execute === 'function') g.execute(wid);
                        } catch (e) {}
                      } catch (e) {
                        done(reject, String(e));
                      }
                    })""",
                    {"sitekey": auth.RECAPTCHA_V2_SITEKEY, "timeoutMs": 60000},
                )
                if isinstance(token, str) and token:
                    return token
                return None

            lines_queue: asyncio.Queue = asyncio.Queue()
            done_event: asyncio.Event = asyncio.Event()

            # Buffer for splitlines handling in browser
            async def _report_chunk(source, line: str):
                if line and line.strip():
                    await lines_queue.put(line)

            await page.expose_binding("reportChunk", _report_chunk)

            fetch_script = """async ({url, method, body, extraHeaders, timeoutMs}) => {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
              try {
                const res = await fetch(url, {
                  method,
                  headers: {
                    'content-type': 'text/plain;charset=UTF-8',
                    ...extraHeaders
                  },
                  body,
                  credentials: 'include',
                  signal: controller.signal,
                });
                const headers = {};
                try {
                  if (res.headers && typeof res.headers.forEach === 'function') {
                    res.headers.forEach((value, key) => { headers[key] = value; });
                  }
                } catch (e) {}

                // Send initial status and headers
                if (window.reportChunk) {
                    await window.reportChunk(JSON.stringify({ __type: 'meta', status: res.status, headers }));
                }

                if (res.body) {
                  const reader = res.body.getReader();
                  const decoder = new TextDecoder();
                  let buffer = '';
                  while (true) {
                    const { value, done } = await reader.read();
                    if (value) buffer += decoder.decode(value, { stream: true });
                    if (done) buffer += decoder.decode();

                    const parts = buffer.split(/\\r?\\n/);
                    buffer = parts.pop() || '';
                    for (const line of parts) {
                        if (line.trim() && window.reportChunk) {
                            await window.reportChunk(line);
                        }
                    }
                    if (done) break;
                  }
                  if (buffer.trim() && window.reportChunk) {
                      await window.reportChunk(buffer);
                  }
                } else {
                  const text = await res.text();
                  if (window.reportChunk) await window.reportChunk(text);
                }
                return { __streaming: true };
              } catch (e) {
                return { status: 502, headers: {}, text: 'FETCH_ERROR:' + String(e) };
              } finally {
                clearTimeout(timer);
              }
            }"""

            result: dict = {"status": 0, "headers": {}, "text": ""}
            for attempt in range(max_recaptcha_attempts):
                # Clear queue for each attempt
                while not lines_queue.empty():
                    lines_queue.get_nowait()
                done_event.clear()

                current_recaptcha_token = ""
                # Mint a new token if not already present or if it's empty
                has_v2 = isinstance(payload, dict) and bool(payload.get("recaptchaV2Token"))
                has_v3 = isinstance(payload, dict) and bool(payload.get("recaptchaV3Token"))

                if isinstance(payload, dict) and not has_v2 and (attempt > 0 or not has_v3):
                    current_recaptcha_token = await _mint_recaptcha_v3_token()
                    if current_recaptcha_token:
                        payload["recaptchaV3Token"] = current_recaptcha_token

                extra_headers = {}
                token_for_headers = current_recaptcha_token
                if not token_for_headers and isinstance(payload, dict):
                    token_for_headers = str(payload.get("recaptchaV3Token") or "").strip()
                if token_for_headers:
                    extra_headers["X-Recaptcha-Token"] = token_for_headers
                    extra_headers["X-Recaptcha-Action"] = recaptcha_action

                body = json.dumps(payload) if payload is not None else ""

                # Start fetch task
                fetch_task = asyncio.create_task(page.evaluate(
                    fetch_script,
                    {
                        "url": fetch_url,
                        "method": http_method,
                        "body": body,
                        "extraHeaders": extra_headers,
                        "timeoutMs": int(timeout_seconds * 1000),
                    },
                ))

                # Wait for initial meta (status/headers) OR task completion
                meta = None
                while not fetch_task.done():
                    try:
                        # Peek at queue for meta
                        item = await asyncio.wait_for(lines_queue.get(), timeout=0.1)
                        if isinstance(item, str) and item.startswith('{"__type":"meta"'):
                            meta = json.loads(item)
                            break
                        else:
                            # Not meta, put it back (though it shouldn't happen before meta)
                            # Actually, LMArena might send data immediately.
                            # If it's not meta, it's likely already content.
                            # For safety, let's assume if it doesn't look like meta, status is 200.
                            if not item.startswith('{"__type":"meta"'):
                                await lines_queue.put(item)
                                meta = {"status": 200, "headers": {}}
                                break
                    except asyncio.TimeoutError:
                        continue

                if fetch_task.done() and meta is None:
                    try:
                        res = fetch_task.result()
                        if isinstance(res, dict) and not res.get("__streaming"):
                            result = res
                        else:
                            result = {"status": 502, "text": "FETCH_DONE_WITHOUT_META"}
                    except Exception as e:
                        result = {"status": 502, "text": f"FETCH_EXCEPTION: {e}"}
                elif meta:
                    result = meta

                status_code = int(result.get("status") or 0)

                # If upstream rate limits us, wait and retry inside the same browser session to avoid hammering.
                if status_code == HTTPStatus.TOO_MANY_REQUESTS and attempt < max_recaptcha_attempts - 1:
                    retry_after = None
                    if isinstance(result, dict) and isinstance(result.get("headers"), dict):
                        headers_map = result.get("headers") or {}
                        retry_after = headers_map.get("retry-after") or headers_map.get("Retry-After")
                    sleep_seconds = get_rate_limit_sleep_seconds(
                        str(retry_after) if retry_after is not None else None,
                        attempt,
                    )
                    await asyncio.sleep(sleep_seconds)
                    continue

                if not _is_recaptcha_validation_failed(status_code, result.get("text")):
                    # Success or non-recaptcha error.
                    # If success, start a task to wait for fetch_task to finish and set done_event.
                    if status_code < 400:
                        # If the in-page script returned a buffered body (e.g. in unit tests/mocks where
                        # `reportChunk` isn't exercised), fall back to a plain buffered response.
                        body_text = ""
                        try:
                            candidate_body = result.get("text") if isinstance(result, dict) else None
                        except Exception:
                            candidate_body = None
                        if isinstance(candidate_body, str) and candidate_body:
                            return BrowserFetchStreamResponse(
                                status_code=status_code,
                                headers=result.get("headers", {}) if isinstance(result, dict) else {},
                                text=candidate_body,
                                method=http_method,
                                url=url,
                            )

                        async def _wait_for_finish():
                            try:
                                await fetch_task
                            finally:
                                done_event.set()
                        asyncio.create_task(_wait_for_finish())

                        return BrowserFetchStreamResponse(
                            status_code=status_code,
                            headers=result.get("headers", {}),
                            method=http_method,
                            url=url,
                            lines_queue=lines_queue,
                            done_event=done_event
                        )
                    break

                if attempt < max_recaptcha_attempts - 1:
                    # ... retry logic ...
                    if isinstance(payload, dict) and not bool(payload.get("recaptchaV2Token")):
                        try:
                            v2_token = await _mint_recaptcha_v2_token()
                        except Exception:
                            v2_token = None
                        if v2_token:
                            payload["recaptchaV2Token"] = v2_token
                            payload.pop("recaptchaV3Token", None)
                            await asyncio.sleep(0.5)
                            continue

                    try:
                        await click_turnstile(page)
                    except Exception:
                        pass

                    try:
                        await page.mouse.move(120 + (attempt * 10), 120 + (attempt * 10))
                        await page.mouse.wheel(0, 250)
                    except Exception:
                        pass
                    await asyncio.sleep(min(2.0 * (2**attempt), 15.0))

            response = BrowserFetchStreamResponse(
                int(result.get("status") or 0),
                result.get("headers") if isinstance(result, dict) else {},
                result.get("text") if isinstance(result, dict) else "",
                method=http_method,
                url=url,
            )
            return response
        except Exception as e:
            debug_print(f"??? Chrome fetch transport failed: {e}")
            return None
        finally:
            await context.close()


async def fetch_lmarena_stream_via_camoufox(
    http_method: str,
    url: str,
    payload: dict,
    auth_token: str,
    timeout_seconds: int = 120,
    max_recaptcha_attempts: int = 3,
) -> Optional[BrowserFetchStreamResponse]:
    """
    Fallback transport: fetch via Camoufox (Firefox) in-page fetch.
    Uses 'window.wrappedJSObject' for reCAPTCHA access when Chrome is blocked.
    """
    debug_print("🦊 Attempting Camoufox fetch transport...")

    cfg = config.get_config()
    recaptcha_sitekey, recaptcha_action = auth.get_recaptcha_settings(cfg)

    cookie_store = cfg.get("browser_cookies")
    cookie_map: dict[str, str] = {}
    if isinstance(cookie_store, dict):
        for name, value in cookie_store.items():
            if not name or not value:
                continue
            cookie_map[str(name)] = str(value)

    cf_clearance = str(cfg.get("cf_clearance") or cookie_map.get("cf_clearance") or "").strip()
    cf_bm = str(cfg.get("cf_bm") or cookie_map.get("__cf_bm") or "").strip()
    cfuvid = str(cfg.get("cfuvid") or cookie_map.get("_cfuvid") or "").strip()
    provisional_user_id = str(cfg.get("provisional_user_id") or cookie_map.get("provisional_user_id") or "").strip()
    grecaptcha_cookie = str(cookie_map.get("_GRECAPTCHA") or "").strip()

    desired_cookies: list[dict] = []
    if cf_clearance:
        desired_cookies.append({"name": "cf_clearance", "value": cf_clearance, "domain": ".lmarena.ai", "path": "/"})
    if cf_bm:
        desired_cookies.append({"name": "__cf_bm", "value": cf_bm, "domain": ".lmarena.ai", "path": "/"})
    if cfuvid:
        desired_cookies.append({"name": "_cfuvid", "value": cfuvid, "domain": ".lmarena.ai", "path": "/"})
    if provisional_user_id:
        desired_cookies.append(
            {"name": "provisional_user_id", "value": provisional_user_id, "domain": ".lmarena.ai", "path": "/"}
        )
    if grecaptcha_cookie:
        desired_cookies.append({"name": "_GRECAPTCHA", "value": grecaptcha_cookie, "domain": ".lmarena.ai", "path": "/"})
    if auth_token:
        # arena-auth-prod-v1 is commonly stored as a host-only cookie on `lmarena.ai` (no leading dot).
        desired_cookies.append({"name": "arena-auth-prod-v1", "value": auth_token, "domain": "lmarena.ai", "path": "/"})

    user_agent = auth.normalize_user_agent_value(cfg.get("user_agent"))

    fetch_url = url
    if fetch_url.startswith("https://lmarena.ai"):
        fetch_url = fetch_url[len("https://lmarena.ai") :]
    if not fetch_url.startswith("/"):
        fetch_url = "/" + fetch_url

    def _is_recaptcha_validation_failed(status: int, text: object) -> bool:
        if int(status or 0) != HTTPStatus.FORBIDDEN:
            return False
        if not isinstance(text, str) or not text:
            return False
        try:
            body = json.loads(text)
        except Exception:
            return False
        return isinstance(body, dict) and body.get("error") == "recaptcha validation failed"

    try:
        # Default to headful for better Turnstile/reCAPTCHA reliability; allow override via config.
        try:
            headless_value = cfg.get("camoufox_fetch_headless", None)
            headless = bool(headless_value) if headless_value is not None else False
        except Exception:
            headless = False

        async with AsyncCamoufox(headless=headless, main_world_eval=True) as browser:
            context = await browser.new_context(user_agent=user_agent or None)
            # Small stealth tweak: reduces bot-detection surface for reCAPTCHA v3 scoring.
            try:
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
            except Exception:
                pass
            if desired_cookies:
                try:
                    await context.add_cookies(desired_cookies)
                except Exception:
                    pass

            page = await context.new_page()
            await _maybe_apply_camoufox_window_mode(
                page,
                cfg,
                mode_key="camoufox_fetch_window_mode",
                marker="LMArenaBridge Camoufox Fetch",
                headless=headless,
            )

            debug_print(f"  🦊 Navigating to lmarena.ai...")
            try:
                await asyncio.wait_for(
                    page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=60000),
                    timeout=70.0,
                )
            except Exception:
                pass

            # Try to handle Cloudflare Turnstile if present
            try:
                for _ in range(5):
                    title = await page.title()
                    if "Just a moment" not in title:
                        break
                    await click_turnstile(page)
                    await asyncio.sleep(2)
            except Exception:
                pass

            # Persist cookies
            try:
                fresh_cookies = await context.cookies("https://lmarena.ai")
                auth._capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if config._upsert_browser_session_into_config(cfg, fresh_cookies, user_agent=ua_now):
                    config.save_config(cfg)
            except Exception:
                pass

            async def _mint_recaptcha_v3_token() -> Optional[str]:
                # Wait for grecaptcha using wrappedJSObject
                await page.wait_for_function(
                    "() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && ((w.grecaptcha.enterprise && typeof w.grecaptcha.enterprise.execute === 'function') || typeof w.grecaptcha.execute === 'function')); }",
                    timeout=60000,
                )

                # SIDE-CHANNEL MINTING:
                # 1. Setup result variable
                await safe_page_evaluate(page, "() => { (window.wrappedJSObject || window).__token_result = 'PENDING'; }")

                # 2. Trigger execution (fire and forget from Python's perspective)
                trigger_script = f"""() => {{
                    const w = window.wrappedJSObject || window;
                    const sitekey = {json.dumps(recaptcha_sitekey)};
                    const action = {json.dumps(recaptcha_action)};
                    try {{
                        const raw = w.grecaptcha;
                        const g = (raw?.enterprise && typeof raw.enterprise.execute === 'function')
                            ? raw.enterprise
                            : raw;
                        if (!g || typeof g.execute !== 'function') {{
                            w.__token_result = 'ERROR: NO_GRECAPTCHA';
                            return;
                        }}
                        const readyFn = (typeof g.ready === 'function')
                            ? g.ready.bind(g)
                            : (raw && typeof raw.ready === 'function')
                              ? raw.ready.bind(raw)
                              : null;
                        const run = () => {{
                            try {{
                                Promise.resolve(g.execute(sitekey, {{ action }}))
                                    .then(token => {{ w.__token_result = token; }})
                                    .catch(err => {{ w.__token_result = 'ERROR: ' + String(err); }});
                            }} catch (e) {{
                                w.__token_result = 'SYNC_ERROR: ' + String(e);
                            }}
                        }};
                        try {{
                            if (readyFn) readyFn(run);
                            else run();
                        }} catch (e) {{
                            run();
                        }}
                    }} catch (e) {{
                        w.__token_result = 'SYNC_ERROR: ' + String(e);
                    }}
                }}"""
                await safe_page_evaluate(page, trigger_script)

                # 3. Poll for result
                for _ in range(40): # 20 seconds max (0.5s interval)
                    val = await safe_page_evaluate(page, "() => (window.wrappedJSObject || window).__token_result")
                    if val != 'PENDING':
                        if isinstance(val, str) and (val.startswith('ERROR') or val.startswith('SYNC_ERROR')):
                            debug_print(f"  ⚠️ Camoufox token mint error: {val}")
                            return None
                        return val
                    await asyncio.sleep(0.5)

                debug_print("  ⚠️ Camoufox token mint timed out.")
                return None

            async def _mint_recaptcha_v2_token() -> Optional[str]:
                """
                Best-effort: try to obtain a reCAPTCHA Enterprise v2 token (checkbox/invisible).
                """
                try:
                    await page.wait_for_function(
                        "() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && w.grecaptcha.enterprise && typeof w.grecaptcha.enterprise.render === 'function'); }",
                        timeout=60000,
                    )
                except Exception:
                    return None

                v2_script = f"""() => new Promise((resolve, reject) => {{
                    const w = window.wrappedJSObject || window;
                    const g = w.grecaptcha?.enterprise;
                    if (!g || typeof g.render !== 'function') return reject('NO_GRECAPTCHA_V2');
                    let settled = false;
                    const done = (fn, arg) => {{ if (settled) return; settled = true; fn(arg); }};
                    try {{
                        const el = w.document.createElement('div');
                        el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;';
                        w.document.body.appendChild(el);
                        const timer = w.setTimeout(() => done(reject, 'V2_TIMEOUT'), 60000);
                        const wid = g.render(el, {{
                            sitekey: {json.dumps(auth.RECAPTCHA_V2_SITEKEY)},
                            size: 'invisible',
                            callback: (tok) => {{ w.clearTimeout(timer); done(resolve, tok); }},
                            'error-callback': () => {{ w.clearTimeout(timer); done(reject, 'V2_ERROR'); }},
                        }});
                        try {{ if (typeof g.execute === 'function') g.execute(wid); }} catch (e) {{}}
                    }} catch (e) {{
                        done(reject, String(e));
                    }}
                }})"""
                try:
                    token = await safe_page_evaluate(page, v2_script)
                except Exception:
                    return None
                if isinstance(token, str) and token:
                    return token
                return None

            lines_queue: asyncio.Queue = asyncio.Queue()
            done_event: asyncio.Event = asyncio.Event()

            async def _report_chunk(source, line: str):
                if line and line.strip():
                    await lines_queue.put(line)

            await page.expose_binding("reportChunk", _report_chunk)

            fetch_script = """async ({url, method, body, extraHeaders, timeoutMs}) => {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
              try {
                const res = await fetch(url, {
                  method,
                  headers: {
                    'content-type': 'text/plain;charset=UTF-8',
                    ...extraHeaders
                  },
                  body,
                  credentials: 'include',
                  signal: controller.signal,
                });
                const headers = {};
                try {
                  if (res.headers && typeof res.headers.forEach === 'function') {
                    res.headers.forEach((value, key) => { headers[key] = value; });
                  }
                } catch (e) {}

                // Send initial status and headers
                if (window.reportChunk) {
                    await window.reportChunk(JSON.stringify({ __type: 'meta', status: res.status, headers }));
                }

                if (res.body) {
                  const reader = res.body.getReader();
                  const decoder = new TextDecoder();
                  let buffer = '';
                  while (true) {
                    const { value, done } = await reader.read();
                    if (value) buffer += decoder.decode(value, { stream: true });
                    if (done) buffer += decoder.decode();

                    const parts = buffer.split(/\\r?\\n/);
                    buffer = parts.pop() || '';
                    for (const line of parts) {
                        if (line.trim() && window.reportChunk) {
                            await window.reportChunk(line);
                        }
                    }
                    if (done) break;
                  }
                  if (buffer.trim() && window.reportChunk) {
                      await window.reportChunk(buffer);
                  }
                } else {
                  const text = await res.text();
                  if (window.reportChunk) await window.reportChunk(text);
                }
                return { __streaming: true };
              } catch (e) {
                return { status: 502, headers: {}, text: 'FETCH_ERROR:' + String(e) };
              } finally {
                clearTimeout(timer);
              }
            }"""

            result: dict = {"status": 0, "headers": {}, "text": ""}
            for attempt in range(max_recaptcha_attempts):
                # Clear queue for each attempt
                while not lines_queue.empty():
                    lines_queue.get_nowait()
                done_event.clear()

                current_recaptcha_token = ""
                has_v2 = isinstance(payload, dict) and bool(payload.get("recaptchaV2Token"))
                has_v3 = isinstance(payload, dict) and bool(payload.get("recaptchaV3Token"))

                if isinstance(payload, dict) and not has_v2 and (attempt > 0 or not has_v3):
                    try:
                        current_recaptcha_token = await _mint_recaptcha_v3_token()
                        if current_recaptcha_token:
                            payload["recaptchaV3Token"] = current_recaptcha_token
                    except Exception as e:
                        debug_print(f"  ⚠️ Error minting token in Camoufox: {e}")

                extra_headers = {}
                token_for_headers = current_recaptcha_token
                if not token_for_headers and isinstance(payload, dict):
                    token_for_headers = str(payload.get("recaptchaV3Token") or "").strip()
                if token_for_headers:
                    extra_headers["X-Recaptcha-Token"] = token_for_headers
                    extra_headers["X-Recaptcha-Action"] = recaptcha_action

                body = json.dumps(payload) if payload is not None else ""

                # Execute fetch
                fetch_task = asyncio.create_task(page.evaluate(
                    fetch_script,
                    {
                        "url": fetch_url,
                        "method": http_method,
                        "body": body,
                        "extraHeaders": extra_headers,
                        "timeoutMs": int(timeout_seconds * 1000),
                    },
                ))

                # Wait for initial meta (status/headers) OR task completion
                meta = None
                while not fetch_task.done():
                    try:
                        item = await asyncio.wait_for(lines_queue.get(), timeout=0.1)
                        if isinstance(item, str) and item.startswith('{"__type":"meta"'):
                            meta = json.loads(item)
                            break
                        else:
                            if not item.startswith('{"__type":"meta"'):
                                await lines_queue.put(item)
                                meta = {"status": 200, "headers": {}}
                                break
                    except asyncio.TimeoutError:
                        continue

                if fetch_task.done() and meta is None:
                    try:
                        res = fetch_task.result()
                        if isinstance(res, dict) and not res.get("__streaming"):
                            result = res
                        else:
                            result = {"status": 502, "text": "FETCH_DONE_WITHOUT_META"}
                    except Exception as e:
                        result = {"status": 502, "text": f"FETCH_EXCEPTION: {e}"}
                elif meta:
                    result = meta

                status_code = int(result.get("status") or 0)

                if status_code == HTTPStatus.TOO_MANY_REQUESTS and attempt < max_recaptcha_attempts - 1:
                    await asyncio.sleep(5)
                    continue

                if not _is_recaptcha_validation_failed(status_code, result.get("text")):
                    if status_code < 400:
                        async def _wait_for_finish():
                            try:
                                await fetch_task
                            finally:
                                done_event.set()
                        asyncio.create_task(_wait_for_finish())

                        return BrowserFetchStreamResponse(
                            status_code=status_code,
                            headers=result.get("headers", {}),
                            method=http_method,
                            url=url,
                            lines_queue=lines_queue,
                            done_event=done_event
                        )
                    break

                if attempt < max_recaptcha_attempts - 1 and isinstance(payload, dict) and not bool(payload.get("recaptchaV2Token")):
                    try:
                        v2_token = await _mint_recaptcha_v2_token()
                    except Exception:
                        v2_token = None
                    if v2_token:
                        payload["recaptchaV2Token"] = v2_token
                        payload.pop("recaptchaV3Token", None)
                        await asyncio.sleep(0.5)
                        continue

                await asyncio.sleep(2)

            return BrowserFetchStreamResponse(
                int(result.get("status") or 0),
                result.get("headers") if isinstance(result, dict) else {},
                result.get("text") if isinstance(result, dict) else "",
                method=http_method,
                url=url,
            )

    except Exception as e:
        debug_print(f"❌ Camoufox fetch transport failed: {e}")
        return None

async def get_recaptcha_v3_token() -> Optional[str]:
    """
    Retrieves reCAPTCHA v3 token using a 'Side-Channel' approach.
    We write the token to a global window variable and poll for it,
    bypassing Promise serialization issues in the Main World bridge.
    """
    debug_print("🔐 Starting reCAPTCHA v3 token retrieval (Side-Channel Mode)...")

    cfg = config.get_config()
    cf_clearance = cfg.get("cf_clearance", "")
    recaptcha_sitekey, recaptcha_action = auth.get_recaptcha_settings(cfg)

    try:
        chrome_token = await get_recaptcha_v3_token_with_chrome(cfg)
        if chrome_token:
            globals.RECAPTCHA_TOKEN = chrome_token
            globals.RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
            return chrome_token

        # Use isolated world (main_world_eval=False) to avoid execution context destruction issues.
        # We will access the main world objects via window.wrappedJSObject.
        # Ensure headless=False as per INFO.md for stability
        async with AsyncCamoufox(headless=False, main_world_eval=False) as browser:
            context = await browser.new_context()
            if cf_clearance:
                await context.add_cookies([{
                    "name": "cf_clearance",
                    "value": cf_clearance,
                    "domain": ".lmarena.ai",
                    "path": "/"
                }])

            page = await context.new_page()

            debug_print("  🌐 Navigating to lmarena.ai...")
            await page.goto("https://lmarena.ai/", wait_until="domcontentloaded")

            # --- NEW: Cloudflare/Turnstile Pass-Through ---
            debug_print("  🛡️  Checking for Cloudflare Turnstile...")

            # Allow time for the widget to render if it's going to
            try:
                # Check for challenge title or widget presence
                for _ in range(5):
                    title = await page.title()
                    if "Just a moment" in title:
                        debug_print("  🔒 Cloudflare challenge active. Attempting to click...")
                        clicked = await click_turnstile(page)
                        if clicked:
                            debug_print("  ✅ Clicked Turnstile.")
                            # Give it time to verify
                            await asyncio.sleep(3)
                    else:
                        # If title is normal, we might still have a widget on the page
                        await click_turnstile(page)
                        break
                    await asyncio.sleep(1)

                # Wait for the page to actually settle into the main app
                await page.wait_for_load_state("domcontentloaded")
            except Exception as e:
                debug_print(f"  ⚠️ Error handling Turnstile: {e}")
            # ----------------------------------------------

            # 1. Wake up the page (Humanize)
            debug_print("  🖱️  Waking up page...")
            await page.mouse.move(100, 100)
            await page.mouse.wheel(0, 200)
            await asyncio.sleep(2) # Vital "Human" pause

            # 2. Check for Library
            debug_print("  ⏳ Checking for library...")
            # Use wrappedJSObject to check for grecaptcha in the main world
            lib_ready = await safe_page_evaluate(
                page,
                "() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && w.grecaptcha.enterprise); }",
            )
            if not lib_ready:
                debug_print("  ⚠️ Library not found immediately. Waiting...")
                await asyncio.sleep(3)
                lib_ready = await safe_page_evaluate(
                    page,
                    "() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && w.grecaptcha.enterprise); }",
                )
                if not lib_ready:
                    debug_print("❌ reCAPTCHA library never loaded.")
                    return None

            # 3. SETUP: Initialize our global result variable
            # We use a unique name to avoid conflicts
            await safe_page_evaluate(page, "() => { (window.wrappedJSObject || window).__token_result = 'PENDING'; }")

            # 4. TRIGGER: Execute reCAPTCHA and write to the variable
            # We do NOT await the result here. We just fire the process.
            debug_print("  🚀 Triggering reCAPTCHA execution...")
            trigger_script = f"""() => {{
                const w = window.wrappedJSObject || window;
                try {{
                    w.grecaptcha.enterprise.execute('{recaptcha_sitekey}', {{ action: '{recaptcha_action}' }})
                    .then(token => {{
                        w.__token_result = token;
                    }})
                    .catch(err => {{
                        w.__token_result = 'ERROR: ' + err.toString();
                    }});
                }} catch (e) {{
                    w.__token_result = 'SYNC_ERROR: ' + e.toString();
                }}
            }}"""

            await safe_page_evaluate(page, trigger_script)

            # 5. POLL: Watch the variable for changes
            debug_print("  👀 Polling for result...")
            token = None

            for i in range(20): # Wait up to 20 seconds
                # Read the global variable
                result = await safe_page_evaluate(page, "() => (window.wrappedJSObject || window).__token_result", retries=2)

                if result != 'PENDING':
                    if result and result.startswith('ERROR'):
                        debug_print(f"❌ JS Execution Error: {result}")
                        return None
                    elif result and result.startswith('SYNC_ERROR'):
                        debug_print(f"❌ JS Sync Error: {result}")
                        return None
                    else:
                        token = result
                        debug_print(f"✅ Token captured! ({len(token)} chars)")
                        break

                if i % 2 == 0:
                    debug_print(f"    ... waiting ({i}s)")
                await asyncio.sleep(1)

            if token:
                globals.RECAPTCHA_TOKEN = token
                globals.RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
                return token
            else:
                debug_print("❌ Timed out waiting for token variable to update.")
                return None

    except Exception as e:
        debug_print(f"❌ Unexpected error: {e}")
        return None

async def refresh_recaptcha_token(force_new: bool = False):
    """Checks if the global reCAPTCHA token is expired and refreshes it if necessary."""
    current_time = datetime.now(timezone.utc)
    if force_new:
        globals.RECAPTCHA_TOKEN = None
        globals.RECAPTCHA_EXPIRY = current_time - timedelta(days=365)
    # Unit tests should never launch real browser automation. Tests that need a token patch
    # `refresh_recaptcha_token` / `get_recaptcha_v3_token` explicitly.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return get_cached_recaptcha_token() or None
    # Check if token is expired (set a refresh margin of 10 seconds)
    if globals.RECAPTCHA_TOKEN is None or current_time > globals.RECAPTCHA_EXPIRY - timedelta(seconds=10):
        debug_print("🔄 Recaptcha token expired or missing. Refreshing...")
        new_token = await get_recaptcha_v3_token()
        if new_token:
            globals.RECAPTCHA_TOKEN = new_token
            # reCAPTCHA v3 tokens typically last 120 seconds (2 minutes)
            globals.RECAPTCHA_EXPIRY = current_time + timedelta(seconds=120)
            debug_print(f"✅ Recaptcha token refreshed, expires at {globals.RECAPTCHA_EXPIRY.isoformat()}")
            return new_token
        else:
            debug_print("❌ Failed to refresh recaptcha token.")
            # Set a short retry delay if refresh fails
            globals.RECAPTCHA_EXPIRY = current_time + timedelta(seconds=10)
            return None

    return globals.RECAPTCHA_TOKEN

def get_cached_recaptcha_token() -> str:
    """Return the current reCAPTCHA v3 token if it's still valid, without refreshing."""
    token = globals.RECAPTCHA_TOKEN
    if not token:
        return ""
    current_time = datetime.now(timezone.utc)
    if current_time > globals.RECAPTCHA_EXPIRY - timedelta(seconds=10):
        return ""
    return str(token)

async def get_initial_data():
    debug_print("Starting initial data retrieval...")
    try:
        async with AsyncCamoufox(headless=True, main_world_eval=True) as browser:
            page = await browser.new_page()

            # Set up route interceptor BEFORE navigating
            debug_print("  🎯 Setting up route interceptor for JS chunks...")
            captured_responses = []

            async def capture_js_route(route):
                """Intercept and capture JS chunk responses"""
                url = route.request.url
                if '/_next/static/chunks/' in url and '.js' in url:
                    try:
                        # Fetch the original response
                        response = await route.fetch()
                        # Get the response body
                        body = await response.body()
                        text = body.decode('utf-8')

                        # debug_print(f"    📥 Captured JS chunk: {url.split('/')[-1][:50]}...")
                        captured_responses.append({'url': url, 'text': text})

                        # Continue with the original response (don't modify)
                        await route.fulfill(response=response, body=body)
                    except Exception as e:
                        debug_print(f"    ⚠️  Error capturing response: {e}")
                        # If something fails, just continue normally
                        await route.continue_()
                else:
                    # Not a JS chunk, just continue normally
                    await route.continue_()

            # Register the route interceptor
            await page.route('**/*', capture_js_route)

            debug_print("Navigating to lmarena.ai...")
            await page.goto("https://lmarena.ai/", wait_until="domcontentloaded")

            debug_print("Waiting for Cloudflare challenge to complete...")
            challenge_passed = False
            for i in range(12): # Up to 120 seconds
                try:
                    title = await page.title()
                except Exception:
                    title = ""

                if "Just a moment" not in title:
                    challenge_passed = True
                    break

                debug_print(f"  ⏳ Waiting for Cloudflare challenge... (attempt {i+1}/12)")
                await click_turnstile(page)

                try:
                    await page.wait_for_function(
                        "() => document.title.indexOf('Just a moment...') === -1",
                        timeout=10000
                    )
                    challenge_passed = True
                    break
                except Exception:
                    pass

            if challenge_passed:
                debug_print("✅ Cloudflare challenge passed.")
            else:
                debug_print("❌ Cloudflare challenge took too long or failed.")
                # Even if the challenge didn't clear, persist any cookies we did get.
                # Sometimes Cloudflare/BM cookies are still set and can help subsequent attempts.
                try:
                    cookies = await page.context.cookies()
                    auth._capture_ephemeral_arena_auth_token_from_cookies(cookies)
                    try:
                        user_agent = await page.evaluate("() => navigator.userAgent")
                    except Exception:
                        user_agent = None

                    cfg = config.get_config()
                    ua_for_config = None
                    if not auth.normalize_user_agent_value(cfg.get("user_agent")):
                        ua_for_config = user_agent
                    if config._upsert_browser_session_into_config(cfg, cookies, user_agent=ua_for_config):
                        config.save_config(cfg)
                except Exception:
                    pass
                return

            # Give it time to capture all JS responses
            await asyncio.sleep(5)

            # Persist cookies + UA for downstream httpx/chrome-fetch alignment.
            cookies = await page.context.cookies()
            auth._capture_ephemeral_arena_auth_token_from_cookies(cookies)
            try:
                user_agent = await page.evaluate("() => navigator.userAgent")
            except Exception:
                user_agent = None

            cfg = config.get_config()
            # Prefer keeping an existing UA (often set by Chrome contexts) instead of overwriting with Camoufox UA.
            ua_for_config = None
            if not auth.normalize_user_agent_value(cfg.get("user_agent")):
                ua_for_config = user_agent
            if config._upsert_browser_session_into_config(cfg, cookies, user_agent=ua_for_config):
                config.save_config(cfg)

            if str(cfg.get("cf_clearance") or "").strip():
                debug_print(f"✅ Saved cf_clearance token: {str(cfg.get('cf_clearance'))[:20]}...")
            else:
                debug_print("⚠️ Could not find cf_clearance cookie.")

            page_body = ""

            # Extract models
            debug_print("Extracting models from page...")
            try:
                page_body = await page.content()
                match = re.search(r'{\\\\"initialModels\\\\":(\[.*?\]),\\\\"initialModel[A-Z]Id', page_body, re.DOTALL)
                if match:
                    models_json = match.group(1).encode().decode('unicode_escape')
                    model_list = json.loads(models_json)
                    models.save_models(model_list)
                    debug_print(f"✅ Saved {len(model_list)} models")
                else:
                    debug_print("⚠️ Could not find models in page")
            except Exception as e:
                debug_print(f"❌ Error extracting models: {e}")

            # Extract Next-Action IDs from captured JavaScript responses
            debug_print(f"\nExtracting Next-Action IDs from {len(captured_responses)} captured JS responses...")
            try:
                upload_action_id = None
                signed_url_action_id = None

                if not captured_responses:
                    debug_print("  ⚠️  No JavaScript responses were captured")
                else:
                    debug_print(f"  📦 Processing {len(captured_responses)} JavaScript chunk files")

                    for item in captured_responses:
                        url = item['url']
                        text = item['text']

                        try:
                            # debug_print(f"  🔎 Checking: {url.split('/')[-1][:50]}...")

                            # Look for getSignedUrl action ID (ID captured in group 1)
                            signed_url_matches = re.findall(
                                r'\(0,[a-zA-Z].createServerReference\)\(\"([\w\d]*?)\",[a-zA-Z_$][\w$]*\.callServer,void 0,[a-zA-Z_$][\w$]*\.findSourceMapURL,["\']getSignedUrl["\']\)',
                                text
                            )

                            # Look for generateUploadUrl action ID (ID captured in group 1)
                            upload_matches = re.findall(
                                r'\(0,[a-zA-Z].createServerReference\)\(\"([\w\d]*?)\",[a-zA-Z_$][\w$]*\.callServer,void 0,[a-zA-Z_$][\w$]*\.findSourceMapURL,["\']generateUploadUrl["\']\)',
                                text
                            )

                            # Process matches
                            if signed_url_matches and not signed_url_action_id:
                                signed_url_action_id = signed_url_matches[0]
                                debug_print(f"    📥 Found getSignedUrl action ID: {signed_url_action_id[:20]}...")

                            if upload_matches and not upload_action_id:
                                upload_action_id = upload_matches[0]
                                debug_print(f"    📤 Found generateUploadUrl action ID: {upload_action_id[:20]}...")

                            if upload_action_id and signed_url_action_id:
                                debug_print(f"  ✅ Found both action IDs, stopping search")
                                break

                        except Exception as e:
                            debug_print(f"    ⚠️  Error parsing response from {url}: {e}")
                            continue

                # Save the action IDs to config
                if upload_action_id:
                    cfg["next_action_upload"] = upload_action_id
                if signed_url_action_id:
                    cfg["next_action_signed_url"] = signed_url_action_id

                if upload_action_id and signed_url_action_id:
                    config.save_config(cfg)
                    debug_print(f"\n✅ Saved both Next-Action IDs to config")
                    debug_print(f"   Upload: {upload_action_id}")
                    debug_print(f"   Signed URL: {signed_url_action_id}")
                elif upload_action_id or signed_url_action_id:
                    config.save_config(cfg)
                    debug_print(f"\n⚠️ Saved partial Next-Action IDs:")
                    if upload_action_id:
                        debug_print(f"   Upload: {upload_action_id}")
                    if signed_url_action_id:
                        debug_print(f"   Signed URL: {signed_url_action_id}")
                else:
                    debug_print(f"\n⚠️ Could not extract Next-Action IDs from JavaScript chunks")
                    debug_print(f"   This is optional - image upload may not work without them")

            except Exception as e:
                debug_print(f"❌ Error extracting Next-Action IDs: {e}")
                debug_print(f"   This is optional - continuing without them")

            # Extract reCAPTCHA sitekey/action from captured JS responses
            debug_print(f"\nExtracting reCAPTCHA params from {len(captured_responses)} captured JS responses...")
            try:
                discovered_sitekey: Optional[str] = None
                discovered_action: Optional[str] = None

                for item in captured_responses or []:
                    if not isinstance(item, dict):
                        continue
                    text = item.get("text")
                    if not isinstance(text, str) or not text:
                        continue
                    sitekey, action = auth.extract_recaptcha_params_from_text(text)
                    if sitekey and not discovered_sitekey:
                        discovered_sitekey = sitekey
                    if action and not discovered_action:
                        discovered_action = action
                    if discovered_sitekey and discovered_action:
                        break

                # Fallback: try the HTML we already captured.
                if (not discovered_sitekey or not discovered_action) and page_body:
                    sitekey, action = auth.extract_recaptcha_params_from_text(page_body)
                    if sitekey and not discovered_sitekey:
                        discovered_sitekey = sitekey
                    if action and not discovered_action:
                        discovered_action = action

                if discovered_sitekey:
                    cfg["recaptcha_sitekey"] = discovered_sitekey
                if discovered_action:
                    cfg["recaptcha_action"] = discovered_action

                if discovered_sitekey or discovered_action:
                    config.save_config(cfg)
                    debug_print("✅ Saved reCAPTCHA params to config")
                    if discovered_sitekey:
                        debug_print(f"   Sitekey: {discovered_sitekey[:20]}...")
                    if discovered_action:
                        debug_print(f"   Action: {discovered_action}")
                else:
                    debug_print("⚠️ Could not extract reCAPTCHA params; using defaults")
            except Exception as e:
                debug_print(f"❌ Error extracting reCAPTCHA params: {e}")
                debug_print("   This is optional - continuing without them")

            # Extract Supabase anon key
            try:
                if not str(globals.SUPABASE_ANON_KEY or "").strip():
                    discovered_key: Optional[str] = None
                    for item in captured_responses or []:
                        if not isinstance(item, dict):
                            continue
                        text = item.get("text")
                        if not isinstance(text, str) or not text:
                            continue
                        discovered_key = auth.extract_supabase_anon_key_from_text(text)
                        if discovered_key:
                            break
                    if (not discovered_key) and page_body:
                        discovered_key = auth.extract_supabase_anon_key_from_text(page_body)
                    if discovered_key:
                        globals.SUPABASE_ANON_KEY = discovered_key
                        debug_print(f"✅ Discovered Supabase anon key: {discovered_key[:16]}...")
            except Exception:
                pass

            debug_print("✅ Initial data retrieval complete")
    except Exception as e:
        debug_print(f"❌ An error occurred during initial data retrieval: {e}")

async def camoufox_proxy_worker():
    """
    Internal Userscript-Proxy client backed by Camoufox.
    Maintains a SINGLE persistent browser instance to avoid crash loops and resource exhaustion.
    """
    # Mark the proxy as alive immediately
    proxy._touch_userscript_poll()
    debug_print("🦊 Camoufox proxy worker started (Singleton Mode).")

    browser_cm = None
    browser = None
    context = None
    page = None

    proxy_recaptcha_sitekey = auth.RECAPTCHA_SITEKEY
    proxy_recaptcha_action = auth.RECAPTCHA_ACTION
    last_signup_attempt_at: float = 0.0

    queue = proxy._get_userscript_proxy_queue()

    while True:
        try:
            proxy._touch_userscript_poll()

            # --- 1. HEALTH CHECK & LAUNCH ---
            needs_launch = False
            if browser is None or context is None or page is None:
                needs_launch = True
            else:
                try:
                    if page.is_closed():
                        debug_print("⚠️ Camoufox proxy page closed. Relaunching...")
                        needs_launch = True
                    elif not context.pages:
                        debug_print("⚠️ Camoufox proxy context has no pages. Relaunching...")
                        needs_launch = True
                except Exception:
                    needs_launch = True

            if needs_launch:
                # Cleanup existing if any
                if browser_cm:
                    try:
                        await browser_cm.__aexit__(None, None, None)
                    except Exception:
                        pass
                browser_cm = None
                browser = None
                context = None
                page = None

                cfg = config.get_config()
                recaptcha_sitekey, recaptcha_action = auth.get_recaptcha_settings(cfg)
                proxy_recaptcha_sitekey = recaptcha_sitekey
                proxy_recaptcha_action = recaptcha_action
                user_agent = auth.normalize_user_agent_value(cfg.get("user_agent"))

                headless_value = cfg.get("camoufox_proxy_headless", None)
                headless = bool(headless_value) if headless_value is not None else False
                launch_timeout = float(cfg.get("camoufox_proxy_launch_timeout_seconds", 90))
                launch_timeout = max(20.0, min(launch_timeout, 300.0))

                debug_print(f"🦊 Camoufox proxy: launching browser (headless={headless})...")

                profile_dir = None
                try:
                    profile_dir_value = cfg.get("camoufox_proxy_user_data_dir")
                    if profile_dir_value:
                        profile_dir = Path(str(profile_dir_value)).expanduser()
                except Exception:
                    pass
                if profile_dir is None:
                    try:
                        profile_dir = Path(globals.CONFIG_FILE).with_name("grecaptcha")
                    except Exception:
                        pass

                persistent_pref = cfg.get("camoufox_proxy_persistent_context", None)
                want_persistent = bool(persistent_pref) if persistent_pref is not None else False

                persistent_context_enabled = False
                if want_persistent and isinstance(profile_dir, Path) and profile_dir.exists():
                    persistent_context_enabled = True
                    browser_cm = AsyncCamoufox(
                        headless=headless,
                        main_world_eval=True,
                        persistent_context=True,
                        user_data_dir=str(profile_dir),
                    )
                else:
                    browser_cm = AsyncCamoufox(headless=headless, main_world_eval=True)

                try:
                    browser = await asyncio.wait_for(browser_cm.__aenter__(), timeout=launch_timeout)
                except Exception as e:
                    debug_print(f"⚠️ Camoufox launch failed ({type(e).__name__}): {e}")
                    if persistent_context_enabled:
                        debug_print("⚠️ Retrying without persistence...")
                        try:
                            await browser_cm.__aexit__(None, None, None)
                        except Exception:
                            pass
                        persistent_context_enabled = False
                        browser_cm = AsyncCamoufox(headless=headless, main_world_eval=True)
                        browser = await asyncio.wait_for(browser_cm.__aenter__(), timeout=launch_timeout)
                    else:
                        raise

                if persistent_context_enabled:
                    context = browser
                else:
                    context = await browser.new_context(user_agent=user_agent or None)

                try:
                    await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
                except Exception:
                    pass

                # Inject only a minimal set of cookies (do not overwrite browser-managed state).
                cookie_store = cfg.get("browser_cookies")
                cookie_map: dict[str, str] = {}
                if isinstance(cookie_store, dict):
                    for name, value in cookie_store.items():
                        if not name or not value:
                            continue
                        cookie_map[str(name)] = str(value)

                cf_clearance = str(cfg.get("cf_clearance") or cookie_map.get("cf_clearance") or "").strip()
                cf_bm = str(cfg.get("cf_bm") or cookie_map.get("__cf_bm") or "").strip()
                cfuvid = str(cfg.get("cfuvid") or cookie_map.get("_cfuvid") or "").strip()
                provisional_user_id = str(cfg.get("provisional_user_id") or cookie_map.get("provisional_user_id") or "").strip()

                desired_cookies: list[dict] = []
                if cf_clearance:
                    desired_cookies.append({"name": "cf_clearance", "value": cf_clearance, "domain": ".lmarena.ai", "path": "/"})
                if cf_bm:
                    desired_cookies.append({"name": "__cf_bm", "value": cf_bm, "domain": ".lmarena.ai", "path": "/"})
                if cfuvid:
                    desired_cookies.append({"name": "_cfuvid", "value": cfuvid, "domain": ".lmarena.ai", "path": "/"})
                if provisional_user_id:
                    desired_cookies.append(
                        {"name": "provisional_user_id", "value": provisional_user_id, "domain": ".lmarena.ai", "path": "/"}
                    )

                if desired_cookies:
                    try:
                        existing_names: set[str] = set()
                        try:
                            existing = await context.cookies("https://lmarena.ai")
                            for c in existing or []:
                                name = c.get("name")
                                if name:
                                    existing_names.add(str(name))
                        except Exception:
                            existing_names = set()

                        cookies_to_add: list[dict] = []
                        for c in desired_cookies:
                            name = str(c.get("name") or "")
                            if not name:
                                continue
                            if name in existing_names:
                                continue
                            cookies_to_add.append(c)
                        if cookies_to_add:
                            await context.add_cookies(cookies_to_add)
                    except Exception:
                        pass

                # Best-effort: seed the browser context with a usable `arena-auth-prod-v1` session cookie.
                # Prefer a non-expired base64 session from config, and avoid clobbering a fresh browser-managed cookie.
                try:
                    existing_auth = ""
                    try:
                        existing = await context.cookies("https://lmarena.ai")
                    except Exception:
                        existing = []
                    for c in existing or []:
                        try:
                            if str(c.get("name") or "") == "arena-auth-prod-v1":
                                existing_auth = str(c.get("value") or "").strip()
                                break
                        except Exception:
                            continue
                    has_fresh_existing = False
                    if existing_auth:
                        try:
                            has_fresh_existing = not auth.is_arena_auth_token_expired(existing_auth, skew_seconds=0)
                        except Exception:
                            has_fresh_existing = True

                    if not has_fresh_existing:
                        candidate = ""
                        try:
                            if globals.EPHEMERAL_ARENA_AUTH_TOKEN and not auth.is_arena_auth_token_expired(
                                globals.EPHEMERAL_ARENA_AUTH_TOKEN, skew_seconds=0
                            ):
                                candidate = str(globals.EPHEMERAL_ARENA_AUTH_TOKEN).strip()
                        except Exception:
                            candidate = ""

                        if not candidate:
                            cfg_tokens = cfg.get("auth_tokens", [])
                            if not isinstance(cfg_tokens, list):
                                cfg_tokens = []
                            # Prefer a clearly non-expired session.
                            for t in cfg_tokens:
                                t = str(t or "").strip()
                                if not t:
                                    continue
                                try:
                                    if auth.is_probably_valid_arena_auth_token(t) and not auth.is_arena_auth_token_expired(
                                        t, skew_seconds=0
                                    ):
                                        candidate = t
                                        break
                                except Exception:
                                    continue
                            # Fallback: seed with any base64 session (even if expired; in-page refresh may work).
                            if not candidate:
                                for t in cfg_tokens:
                                    t = str(t or "").strip()
                                    if t.startswith("base64-"):
                                        candidate = t
                                        break

                        if candidate:
                            await context.add_cookies(
                                [{"name": "arena-auth-prod-v1", "value": candidate, "domain": "lmarena.ai", "path": "/"}]
                            )
                except Exception:
                    pass

                page = await context.new_page()
                await _maybe_apply_camoufox_window_mode(
                    page,
                    cfg,
                    mode_key="camoufox_proxy_window_mode",
                    marker="LMArenaBridge Camoufox Proxy",
                    headless=headless,
                )

                try:
                    debug_print("🦊 Camoufox proxy: navigating to https://lmarena.ai/?mode=direct ...")
                    await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)
                    debug_print("🦊 Camoufox proxy: navigation complete.")
                except Exception as e:
                    debug_print(f"⚠️ Navigation warning: {e}")

                # Attach console listener
                def _on_console(message) -> None:
                    try:
                        attr = getattr(message, "text", None)
                        text = attr() if callable(attr) else attr
                    except Exception:
                        return
                    if not isinstance(text, str):
                        return
                    if not text.startswith("LM_BRIDGE_PROXY|"):
                        return
                    try:
                        _, jid, payload_json = text.split("|", 2)
                    except ValueError:
                        return
                    try:
                        payload = json.loads(payload_json)
                    except Exception:
                        payload = {"error": "proxy console payload decode error", "done": True}
                    try:
                        asyncio.create_task(proxy.push_proxy_chunk(str(jid), payload))
                    except Exception:
                        return

                try:
                    page.on("console", _on_console)
                except Exception:
                    pass

                # Check for "Just a moment" (Cloudflare) and click if needed
                try:
                    title = await page.title()
                    if "Just a moment" in title:
                        debug_print("🦊 Cloudflare challenge detected.")
                        await click_turnstile(page)
                        await asyncio.sleep(2)
                except Exception:
                    pass

                # Pre-warm
                try:
                    await page.mouse.move(100, 100)
                except Exception:
                    pass

            async def _get_auth_cookie_value() -> str:
                nonlocal context
                if context is None:
                    return ""
                try:
                    cookies = await context.cookies("https://lmarena.ai")
                except Exception:
                    return ""
                try:
                    auth._capture_ephemeral_arena_auth_token_from_cookies(cookies or [])
                except Exception:
                    pass
                candidates: list[str] = []
                for c in cookies or []:
                    try:
                        if str(c.get("name") or "") != "arena-auth-prod-v1":
                            continue
                        value = str(c.get("value") or "").strip()
                        if value:
                            candidates.append(value)
                    except Exception:
                        continue
                for value in candidates:
                    try:
                        if not auth.is_arena_auth_token_expired(value, skew_seconds=0):
                            return value
                    except Exception:
                        return value
                if candidates:
                    return candidates[0]
                return ""

            async def _attempt_anonymous_signup(*, min_interval_seconds: float = 20.0) -> None:
                nonlocal last_signup_attempt_at, page, context
                if page is None or context is None:
                    return
                now = time.time()
                if (now - float(last_signup_attempt_at or 0.0)) < float(min_interval_seconds):
                    return
                last_signup_attempt_at = now

                # First, give LMArena a chance to create an anonymous user itself (it already ships a
                # Turnstile-backed sign-up flow in the app). We just wait/poll for the auth cookie.
                try:
                    for _ in range(20):
                        cur = await _get_auth_cookie_value()
                        if cur and not auth.is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        try:
                            await click_turnstile(page)
                        except Exception:
                            pass
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

                try:
                    cfg_now = config.get_config()
                except Exception:
                    cfg_now = {}
                cookie_store = cfg_now.get("browser_cookies") if isinstance(cfg_now, dict) else None
                provisional_user_id = ""
                if isinstance(cfg_now, dict):
                    provisional_user_id = str(cfg_now.get("provisional_user_id") or "").strip()
                if (not provisional_user_id) and isinstance(cookie_store, dict):
                    provisional_user_id = str(cookie_store.get("provisional_user_id") or "").strip()
                if not provisional_user_id:
                    provisional_user_id = str(uuid.uuid4())

                # Try to force a fresh anonymous signup by rotating the provisional ID and clearing any stale auth.
                try:
                    fresh_provisional = str(uuid.uuid4())
                    await context.add_cookies(
                        [{"name": "provisional_user_id", "value": fresh_provisional, "domain": ".lmarena.ai", "path": "/"}]
                    )
                    provisional_user_id = fresh_provisional
                except Exception:
                    pass
                try:
                    await context.add_cookies(
                        [
                            {
                                "name": "arena-auth-prod-v1",
                                "value": "",
                                "domain": "lmarena.ai",
                                "path": "/",
                                "expires": 1,
                            }
                        ]
                    )
                except Exception:
                    pass
                try:
                    await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)
                except Exception:
                    pass
                try:
                    for _ in range(30):
                        cur = await _get_auth_cookie_value()
                        if cur and not auth.is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        try:
                            await click_turnstile(page)
                        except Exception:
                            pass
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

                # Turnstile token minting:
                # Avoid long-running `page.evaluate` promises (they can hang if the page reloads). Render once, then poll
                # `turnstile.getResponse(widgetId)` from Python and click the widget if it becomes interactive.
                render_turnstile_js = """async ({ sitekey }) => {
                  const w = (window.wrappedJSObject || window);
                  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
                  const key = String(sitekey || '');
                  const out = { ok: false, widgetId: null, stage: 'start', error: '' };
                  if (!key) { out.stage = 'no_sitekey'; return out; }

                  try {
                    const prev = w.__LM_BRIDGE_TURNSTILE_WIDGET_ID;
                    if (prev != null && w.turnstile && typeof w.turnstile.remove === 'function') {
                      try { w.turnstile.remove(prev); } catch (e) {}
                    }
                  } catch (e) {}
                  try {
                    const old = w.document.getElementById('lm-bridge-turnstile');
                    if (old) old.remove();
                  } catch (e) {}

                  async function ensureLoaded() {
                    if (w.turnstile && typeof w.turnstile.render === 'function') return true;
                    try {
                      const h = w.document?.head;
                      if (!h) return false;
                      if (!w.__LM_BRIDGE_TURNSTILE_INJECTED) {
                        w.__LM_BRIDGE_TURNSTILE_INJECTED = true;
                        out.stage = 'inject_script';
                        await Promise.race([
                          new Promise((resolve) => {
                            const s = w.document.createElement('script');
                            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
                            s.async = true;
                            s.defer = true;
                            s.onload = () => resolve(true);
                            s.onerror = () => resolve(false);
                            h.appendChild(s);
                          }),
                          sleep(12000).then(() => false),
                        ]);
                      }
                    } catch (e) { out.error = String(e); }
                    const start = Date.now();
                    while ((Date.now() - start) < 15000) {
                      if (w.turnstile && typeof w.turnstile.render === 'function') return true;
                      await sleep(250);
                    }
                    return false;
                  }

                  const ok = await ensureLoaded();
                  if (!ok || !(w.turnstile && typeof w.turnstile.render === 'function')) { out.stage = 'not_loaded'; return out; }

                  out.stage = 'render';
                  try {
                    const el = w.document.createElement('div');
                    el.id = 'lm-bridge-turnstile';
                    el.style.cssText = 'position:fixed;left:20px;top:20px;z-index:2147483647;';
                    (w.document.body || w.document.documentElement).appendChild(el);
                    const params = new w.Object();
                    params.sitekey = key;
                    // Match LMArena's own anonymous sign-up widget settings.
                    // `size: normal` + `appearance: interaction-only` tends to be accepted more reliably than
                    // forcing an invisible execute flow.
                    params.size = 'normal';
                    params.appearance = 'interaction-only';
                    params.callback = (tok) => { try { w.__LM_BRIDGE_TURNSTILE_TOKEN = String(tok || ''); } catch (e) {} };
                    params['error-callback'] = () => { try { w.__LM_BRIDGE_TURNSTILE_TOKEN = ''; } catch (e) {} };
                    params['expired-callback'] = () => { try { w.__LM_BRIDGE_TURNSTILE_TOKEN = ''; } catch (e) {} };
                    const widgetId = w.turnstile.render(el, params);
                    w.__LM_BRIDGE_TURNSTILE_WIDGET_ID = widgetId;
                    out.ok = true;
                    out.widgetId = widgetId;
                    return out;
                  } catch (e) {
                    out.error = String(e);
                    out.stage = 'render_error';
                    return out;
                  }
                }"""

                poll_turnstile_js = """({ widgetId }) => {
                  const w = (window.wrappedJSObject || window);
                  try {
                    const tok = w.__LM_BRIDGE_TURNSTILE_TOKEN;
                    if (tok && String(tok).trim()) return String(tok);
                    if (!w.turnstile || typeof w.turnstile.getResponse !== 'function') return '';
                    return String(w.turnstile.getResponse(widgetId) || '');
                  } catch (e) {
                    return '';
                  }
                }"""

                cleanup_turnstile_js = """({ widgetId }) => {
                  const w = (window.wrappedJSObject || window);
                  try { if (w.turnstile && typeof w.turnstile.remove === 'function') w.turnstile.remove(widgetId); } catch (e) {}
                  try {
                    const el = w.document.getElementById('lm-bridge-turnstile');
                    if (el) el.remove();
                  } catch (e) {}
                  try { delete w.__LM_BRIDGE_TURNSTILE_WIDGET_ID; } catch (e) {}
                  try { delete w.__LM_BRIDGE_TURNSTILE_TOKEN; } catch (e) {}
                  return true;
                }"""

                token_value = ""
                widget_id = None
                stage = ""
                err = ""
                try:
                    mint_info = await asyncio.wait_for(
                        page.evaluate(render_turnstile_js, {"sitekey": auth.TURNSTILE_SITEKEY}),
                        timeout=30.0,
                    )
                except Exception as e:
                    mint_info = {"ok": False, "stage": "evaluate_error", "error": str(e)}
                if isinstance(mint_info, dict):
                    try:
                        widget_id = mint_info.get("widgetId")
                    except Exception:
                        widget_id = None
                    try:
                        stage = str(mint_info.get("stage") or "")
                    except Exception:
                        stage = ""
                    try:
                        err = str(mint_info.get("error") or "")
                    except Exception:
                        err = ""
                if widget_id is None:
                    debug_print(f"⚠️ Camoufox proxy: Turnstile render failed (stage={stage} err={err[:120]})")
                    return

                started = time.monotonic()
                try:
                    while (time.monotonic() - started) < 130.0:
                        try:
                            cur = await asyncio.wait_for(
                                page.evaluate(poll_turnstile_js, {"widgetId": widget_id}),
                                timeout=5.0,
                            )
                        except Exception:
                            cur = ""
                        token_value = str(cur or "").strip()
                        if token_value:
                            break
                        try:
                            await click_turnstile(page)
                        except Exception:
                            pass
                        await asyncio.sleep(1.0)
                finally:
                    try:
                        await page.evaluate(cleanup_turnstile_js, {"widgetId": widget_id})
                    except Exception:
                        pass

                if not token_value:
                    debug_print("⚠️ Camoufox proxy: Turnstile mint failed (timeout).")
                    return

                sign_up_js = """async ({ turnstileToken, provisionalUserId }) => {
                  const w = (window.wrappedJSObject || window);
                  const opts = new w.Object();
                  opts.method = 'POST';
                  opts.credentials = 'include';
                  opts.headers = new w.Object();
                  opts.headers['Content-Type'] = 'application/json';
                  opts.body = JSON.stringify({ turnstileToken: String(turnstileToken || ''), provisionalUserId: String(provisionalUserId || '') });
                  const res = await w.fetch('/nextjs-api/sign-up', opts);
                  let text = '';
                  try { text = await res.text(); } catch (e) { text = ''; }
                  return { status: Number(res.status || 0), ok: !!res.ok, body: String(text || '') };
                }"""

                try:
                    resp = await asyncio.wait_for(
                        page.evaluate(
                            sign_up_js,
                            {"turnstileToken": token_value, "provisionalUserId": provisional_user_id},
                        ),
                        timeout=20.0,
                    )
                except Exception:
                    resp = None

                status = 0
                try:
                    status = int((resp or {}).get("status") or 0) if isinstance(resp, dict) else 0
                except Exception:
                    status = 0
                debug_print(f"🦊 Camoufox proxy: /nextjs-api/sign-up status {status}")

                # Some sign-up responses return the Supabase session JSON in the body instead of setting a cookie.
                # When that happens, encode it into the `arena-auth-prod-v1` cookie format and inject it.
                try:
                    body_text = str((resp or {}).get("body") or "") if isinstance(resp, dict) else ""
                except Exception:
                    body_text = ""
                try:
                    derived_cookie = auth.maybe_build_arena_auth_cookie_from_signup_response_body(body_text)
                except Exception:
                    derived_cookie = None
                if derived_cookie:
                    try:
                        if not auth.is_arena_auth_token_expired(derived_cookie, skew_seconds=0):
                            await context.add_cookies(
                                [
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": derived_cookie,
                                        "domain": "lmarena.ai",
                                        "path": "/",
                                    }
                                ]
                            )
                            auth._capture_ephemeral_arena_auth_token_from_cookies(
                                [{"name": "arena-auth-prod-v1", "value": derived_cookie}]
                            )
                            debug_print("🦊 Camoufox proxy: injected arena-auth cookie from sign-up response body.")
                    except Exception:
                        pass

                # Wait for the cookie to appear
                try:
                    for _ in range(10):
                        cookies = await context.cookies("https://lmarena.ai")
                        auth._capture_ephemeral_arena_auth_token_from_cookies(cookies or [])
                        found = False
                        for c in cookies or []:
                            if c.get("name") == "arena-auth-prod-v1":
                                val = str(c.get("value") or "").strip()
                                if val and not auth.is_arena_auth_token_expired(val, skew_seconds=0):
                                    found = True
                                    break
                        if found:
                            debug_print("🦊 Camoufox proxy: acquired arena-auth-prod-v1 cookie (anonymous user).")
                            break
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

            # --- 2. PROCESS JOBS ---
            try:
                job_id = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            job_id = str(job_id or "").strip()
            job = globals._USERSCRIPT_PROXY_JOBS.get(job_id)
            if not isinstance(job, dict):
                continue

            # Signal that a proxy worker picked up this job (used to avoid long hangs when no worker is running).
            try:
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
            except Exception:
                pass

            # In-page fetch script (streams newline-delimited chunks back through console.log).
            # Mints reCAPTCHA v3 tokens on demand when the request body includes `recaptchaV3Token`.
            fetch_script = """async ({ jid, payload, sitekey, action, sitekeyV2, grecaptchaTimeoutMs, grecaptchaPollMs, timeoutMs, debug }) => {
              const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
              const w = (window.wrappedJSObject || window);
              const emit = (obj) => { try { console.log('LM_BRIDGE_PROXY|' + jid + '|' + JSON.stringify(obj)); } catch (e) {} };
              const debugEnabled = !!debug;
              const dbg = (stage, extra) => { if (!debugEnabled && !String(stage).includes('error')) return; try { emit({ debug: { stage, ...(extra || {}) } }); } catch (e) {} };
              dbg('start', { hasPayload: !!payload, hasSitekey: !!sitekey, hasAction: !!action });

              const pickG = () => {
                const ent = w?.grecaptcha?.enterprise;
                if (ent && typeof ent.execute === 'function' && typeof ent.ready === 'function') return ent;
                const g = w?.grecaptcha;
                if (g && typeof g.execute === 'function' && typeof g.ready === 'function') return g;
                return null;
              };

              const waitForG = async () => {
                const start = Date.now();
                let injected = false;
                while ((Date.now() - start) < (grecaptchaTimeoutMs || 60000)) {
                  const g = pickG();
                  if (g) return g;
                  if (!injected && sitekey && typeof sitekey === 'string' && sitekey) {
                    injected = true;
                    try {
                      // LMArena may lazy-load grecaptcha only after interaction; inject v3-capable scripts.
                      dbg('inject_grecaptcha', {});
                      const key = String(sitekey || '');
                      const h = w.document?.head;
                      if (h) {
                        const s1 = w.document.createElement('script');
                        s1.src = 'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(key);
                        s1.async = true;
                        s1.defer = true;
                        h.appendChild(s1);
                        const s2 = w.document.createElement('script');
                        s2.src = 'https://www.google.com/recaptcha/enterprise.js?render=' + encodeURIComponent(key);
                        s2.async = true;
                        s2.defer = true;
                        h.appendChild(s2);
                      }
                    } catch (e) {}
                  }
                  await sleep(grecaptchaPollMs || 250);
                }
                throw new Error('grecaptcha not ready');
              };

              const mintV3 = async (act) => {
                const g = await waitForG();
                const finalAction = String(act || action || 'chat_submit');
                // `grecaptcha.ready()` can hang indefinitely on some pages; guard it with a short timeout.
                try {
                  await Promise.race([
                    new Promise((resolve) => { try { g.ready(resolve); } catch (e) { resolve(); } }),
                    sleep(5000).then(() => {}),
                  ]);
                } catch (e) {}
                const tok = await Promise.race([
                  Promise.resolve().then(() => {
                    // Firefox Xray wrappers: build params in the page compartment.
                    const params = new w.Object();
                    params.action = finalAction;
                    return g.execute(String(sitekey || ''), params);
                  }),
                  sleep(Math.max(1000, grecaptchaTimeoutMs || 60000)).then(() => { throw new Error('grecaptcha execute timeout'); }),
                ]);
                return (typeof tok === 'string') ? tok : '';
              };

              const waitForV2 = async () => {
                const start = Date.now();
                while ((Date.now() - start) < 60000) {
                  const ent = w?.grecaptcha?.enterprise;
                  if (ent && typeof ent.render === 'function') return ent;
                  await sleep(250);
                }
                throw new Error('grecaptcha v2 not ready');
              };

              const mintV2 = async () => {
                const ent = await waitForV2();
                const key2 = String(sitekeyV2 || '');
                if (!key2) throw new Error('no sitekeyV2');
                return await new Promise((resolve, reject) => {
                  let settled = false;
                  const done = (fn, arg) => { if (settled) return; settled = true; try { fn(arg); } catch (e) {} };
                  try {
                    const el = w.document.createElement('div');
                    el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;';
                    (w.document.body || w.document.documentElement).appendChild(el);
                    const timer = w.setTimeout(() => { try { el.remove(); } catch (e) {} done(reject, 'V2_TIMEOUT'); }, 60000);
                    // Firefox Xray wrappers: build params in the page compartment.
                    const params = new w.Object();
                    params.sitekey = key2;
                    params.size = 'invisible';
                    params.callback = (tok) => { w.clearTimeout(timer); try { el.remove(); } catch (e) {} done(resolve, String(tok || '')); };
                    params['error-callback'] = () => { w.clearTimeout(timer); try { el.remove(); } catch (e) {} done(reject, 'V2_ERROR'); };
                    const wid = ent.render(el, params);
                    try { if (typeof ent.execute === 'function') ent.execute(wid); } catch (e) {}
                  } catch (e) {
                    done(reject, String(e));
                  }
                });
              };

              try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort('timeout'), timeoutMs || 120000);
                try {
                  let bodyText = payload?.body || '';
                  let parsed = null;
                  try { parsed = JSON.parse(String(bodyText || '')); } catch (e) { parsed = null; }

                  let tokenForHeaders = '';
                  if (parsed && typeof parsed === 'object' && Object.prototype.hasOwnProperty.call(parsed, 'recaptchaV3Token')) {
                    try { tokenForHeaders = String(parsed.recaptchaV3Token || ''); } catch (e) { tokenForHeaders = ''; }
                    if (!tokenForHeaders || tokenForHeaders.length < 20) {
                      try {
                        dbg('mint_v3_start', {});
                        tokenForHeaders = await mintV3(action);
                        dbg('v3_minted', { len: (tokenForHeaders || '').length });
                        if (tokenForHeaders) parsed.recaptchaV3Token = tokenForHeaders;
                      } catch (e) {
                        dbg('v3_error', { error: String(e) });
                      }
                    }
                    try { bodyText = JSON.stringify(parsed); } catch (e) { bodyText = String(payload?.body || ''); }
                  }

                  const doFetch = async (body, token) => fetch(payload.url, {
                    method: payload.method || 'POST',
                    body,
                    headers: {
                      ...(payload.headers || { 'Content-Type': 'text/plain;charset=UTF-8' }),
                      ...(token ? { 'X-Recaptcha-Token': token, ...(action ? { 'X-Recaptcha-Action': action } : {}) } : {}),
                    },
                    credentials: 'include',
                    signal: controller.signal,
                  });

                  dbg('before_fetch', { tokenLen: (tokenForHeaders || '').length });
                  let res = await doFetch(bodyText, tokenForHeaders);
                  dbg('after_fetch', { status: Number(res?.status || 0) });
                  if (debugEnabled && res && Number(res.status || 0) >= 400) {
                    let p = '';
                    try { p = await res.clone().text(); } catch (e) { p = ''; }
                    dbg('http_error_preview', { status: Number(res.status || 0), preview: String(p || '').slice(0, 200) });
                  }
                  let headers = {};
                  try { if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k] = v; }); } catch (e) {}
                  emit({ status: res.status, headers });

                  // If we get a reCAPTCHA 403, retry once with a fresh token (keep streaming semantics).
                  if (res && res.status === 403 && parsed && typeof parsed === 'object' && Object.prototype.hasOwnProperty.call(parsed, 'recaptchaV3Token')) {
                    let preview = '';
                    try { preview = await res.clone().text(); } catch (e) { preview = ''; }
                    dbg('403_preview', { preview: String(preview || '').slice(0, 200) });
                    const lower = String(preview || '').toLowerCase();
                    if (lower.includes('recaptcha')) {
                      let tok2 = '';
                      try {
                        tok2 = await mintV3(action);
                        dbg('v3_retry_minted', { len: (tok2 || '').length });
                      } catch (e) {
                        dbg('v3_retry_error', { error: String(e) });
                        tok2 = '';
                      }
                      if (tok2) {
                        try { parsed.recaptchaV3Token = tok2; } catch (e) {}
                        try { bodyText = JSON.stringify(parsed); } catch (e) {}
                        tokenForHeaders = tok2;
                        res = await doFetch(bodyText, tokenForHeaders);
                        headers = {};
                        try { if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k] = v; }); } catch (e) {}
                        emit({ status: res.status, headers });
                      }
                      // If v3 retry still fails (or retry mint failed), attempt v2 fallback (matches LMArena's UI flow).
                      if (res && res.status === 403) {
                        try {
                          const v2tok = await mintV2();
                          dbg('v2_minted', { len: (v2tok || '').length });
                          if (v2tok) {
                            parsed.recaptchaV2Token = v2tok;
                            try { delete parsed.recaptchaV3Token; } catch (e) {}
                            bodyText = JSON.stringify(parsed);
                            tokenForHeaders = '';
                            res = await doFetch(bodyText, '');
                            headers = {};
                            try { if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k] = v; }); } catch (e) {}
                            emit({ status: res.status, headers });
                          }
                        } catch (e) {
                          dbg('v2_error', { error: String(e) });
                        }
                      }
                    }
                  }

                  const reader = res.body?.getReader?.();
                  const decoder = new TextDecoder();
                  if (!reader) {
                    const text = await res.text();
                    const lines = String(text || '').split(/\\r?\\n/).filter((x) => String(x || '').trim().length > 0);
                    if (lines.length) emit({ lines, done: false });
                    emit({ lines: [], done: true });
                    return;
                  }

                  let buffer = '';
                  while (true) {
                    const { value, done } = await reader.read();
                    if (value) buffer += decoder.decode(value, { stream: true });
                    if (done) buffer += decoder.decode();
                    const parts = buffer.split(/\\r?\\n/);
                    buffer = parts.pop() || '';
                    const lines = parts.filter((x) => String(x || '').trim().length > 0);
                    if (lines.length) emit({ lines, done: false });
                    if (done) break;
                  }
                  if (buffer.trim()) emit({ lines: [buffer], done: false });
                  emit({ lines: [], done: true });
                } finally {
                  clearTimeout(timer);
                }
              } catch (e) {
                emit({ error: String(e), done: true });
              }
            }"""

            debug_print(f"🦊 Camoufox proxy: running job {job_id[:8]}...")

            try:
                # Use existing browser cookie if valid, to avoid clobbering fresh anonymous sessions
                browser_auth_cookie = ""
                try:
                    browser_auth_cookie = await _get_auth_cookie_value()
                except Exception:
                    pass

                auth_token = str(job.get("arena_auth_token") or "").strip()

                use_job_token = False
                if auth_token:
                    # Only use the job's token if we don't have a valid one, or if the job's token is explicitly fresher (hard to tell, so prefer browser's if valid).
                    if not browser_auth_cookie:
                        use_job_token = True
                    else:
                        try:
                            if auth.is_arena_auth_token_expired(browser_auth_cookie, skew_seconds=60):
                                use_job_token = True
                        except Exception:
                            use_job_token = True

                if use_job_token:
                    await context.add_cookies(
                        [{"name": "arena-auth-prod-v1", "value": auth_token, "domain": "lmarena.ai", "path": "/"}]
                    )
                elif browser_auth_cookie and not use_job_token:
                    debug_print("🦊 Camoufox proxy: using valid browser auth cookie (job token is empty or invalid).")
            except Exception:
                pass

            # If the job did not provide a usable auth cookie, ensure the browser session has one.
            try:
                current_cookie = await _get_auth_cookie_value()
            except Exception:
                current_cookie = ""
            if current_cookie:
                try:
                    expired = auth.is_arena_auth_token_expired(current_cookie, skew_seconds=0)
                except Exception:
                    expired = False
                debug_print(f"🦊 Camoufox proxy: arena-auth cookie present (len={len(current_cookie)} expired={expired})")
            else:
                debug_print("🦊 Camoufox proxy: arena-auth cookie missing")
            try:
                needs_signup = (not current_cookie) or auth.is_arena_auth_token_expired(current_cookie, skew_seconds=0)
            except Exception:
                needs_signup = not bool(current_cookie)
            # Unit tests stub out the browser; avoid slow/interactive signup flows there.
            if needs_signup and not os.environ.get("PYTEST_CURRENT_TEST"):
                await _attempt_anonymous_signup(min_interval_seconds=20.0)

            try:
                await asyncio.wait_for(
                    page.evaluate(
                        fetch_script,
                        {
                            "jid": job_id,
                            "payload": job.get("payload") or {},
                            "sitekey": proxy_recaptcha_sitekey,
                            "action": proxy_recaptcha_action,
                            "sitekeyV2": auth.RECAPTCHA_V2_SITEKEY,
                            "grecaptchaTimeoutMs": 60000,
                            "grecaptchaPollMs": 250,
                            "timeoutMs": 180000,
                            "debug": bool(os.environ.get("LM_BRIDGE_PROXY_DEBUG")),
                        }
                    ),
                    timeout=200.0
                )
            except asyncio.TimeoutError:
                await proxy.push_proxy_chunk(job_id, {"error": "camoufox proxy evaluate timeout", "done": True})
            except Exception as e:
                await proxy.push_proxy_chunk(job_id, {"error": str(e), "done": True})

        except asyncio.CancelledError:
            debug_print("🦊 Camoufox proxy worker cancelled.")
            if browser_cm:
                try:
                    await browser_cm.__aexit__(None, None, None)
                except Exception:
                    pass
            return
        except Exception as e:
            debug_print(f"⚠️ Camoufox proxy worker exception: {e}")
            await asyncio.sleep(5.0)
            # Mark for relaunch
            browser = None
            page = None

async def periodic_refresh_task():
    """Background task to refresh cf_clearance and models every 30 minutes"""
    while True:
        try:
            # Wait 30 minutes (1800 seconds)
            await asyncio.sleep(1800)
            debug_print("\n" + "="*60)
            debug_print("🔄 Starting scheduled 30-minute refresh...")
            debug_print("="*60)
            await get_initial_data()
            debug_print("✅ Scheduled refresh completed")
            debug_print("="*60 + "\n")
        except Exception as e:
            debug_print(f"❌ Error in periodic refresh task: {e}")
            # Continue the loop even if there's an error
            continue
