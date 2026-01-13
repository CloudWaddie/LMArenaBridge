import asyncio
import os
import sys
import shutil
import re
import builtins as _builtins
from pathlib import Path
from typing import Optional, List, Dict, Callable, Any

try:
    import ctypes
    from ctypes import wintypes
except Exception:
    pass

# ============================================================ 
# LOGGING HELPER
# ============================================================ 
DEBUG = True

def _safe_print(*args, **kwargs) -> None:
    """
    Print without crashing on Windows console encoding issues.
    """
    try:
        _builtins.print(*args, **kwargs)
    except UnicodeEncodeError:
        file = kwargs.get("file") or sys.stdout
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        flush = bool(kwargs.get("flush", False))

        try:
            text = sep.join(str(a) for a in args) + end
            encoding = getattr(file, "encoding", None) or getattr(sys.stdout, "encoding", None) or "utf-8"
            safe_text = text.encode(encoding, errors="backslashreplace").decode(encoding, errors="ignore")
            file.write(safe_text)
            if flush:
                try:
                    file.flush()
                except Exception:
                    pass
        except Exception:
            return

def debug_print(*args, **kwargs):
    if DEBUG:
        _safe_print(*args, **kwargs)

# ============================================================ 
# CONSTANTS
# ============================================================ 
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"
RECAPTCHA_V2_SITEKEY = "6Ld7ePYrAAAAAB34ovoFoDau1fqCJ6IyOjFEQaMn"
TURNSTILE_SITEKEY = "0x4AAAAAAA65vWDmG-O_lPtT"

STRICT_CHROME_FETCH_MODELS = {
    "gemini-3-pro-grounding",
    "gemini-exp-1206",
}

# ============================================================ 
# HELPERS
# ============================================================ 

class TurnstileClickLimiter:
    """
    Simple click budget + cooldown limiter used to prevent aggressive Turnstile click loops.

    Uses monotonic time (caller provides `now_mono`).
    """

    def __init__(self, *, max_clicks: int = 12, cooldown_seconds: float = 5.0) -> None:
        try:
            self.max_clicks = max(0, int(max_clicks))
        except Exception:
            self.max_clicks = 0
        try:
            self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        except Exception:
            self.cooldown_seconds = 0.0

        self.clicks_used = 0
        self._last_click_mono: float | None = None

    def try_acquire(self, now_mono: float) -> bool:
        """
        Returns True iff a click is allowed at `now_mono` and consumes one budget unit.

        Blocked attempts do not consume budget.
        """
        if int(self.max_clicks) <= 0:
            return False
        if int(self.clicks_used) >= int(self.max_clicks):
            return False
        try:
            ts = float(now_mono)
        except Exception:
            return False

        last = self._last_click_mono
        if last is not None:
            if ts < float(last):
                return False
            if (ts - float(last)) < float(self.cooldown_seconds):
                return False

        self._last_click_mono = ts
        self.clicks_used += 1
        return True

def normalize_user_agent_value(user_agent: object) -> str:
    ua = str(user_agent or "").strip()
    if not ua:
        return ""
    if ua.lower() in ("user-agent", "user agent"):
        return ""
    return ua

def upsert_browser_session(config: dict, cookies: list[dict], user_agent: str | None = None) -> bool:
    """
    Persist useful browser session identity (cookies + UA) into config.json.
    """
    changed = False

    cookie_store = config.get("browser_cookies")
    if not isinstance(cookie_store, dict):
        cookie_store = {}
        config["browser_cookies"] = cookie_store
        changed = True

    for cookie in cookies or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        name = str(name)
        if name == "arena-auth-prod-v1" and not bool(config.get("persist_arena_auth_cookie")):
            continue
        value = str(value)
        if cookie_store.get(name) != value:
            cookie_store[name] = value
            changed = True

    # Promote frequently-used cookies to top-level config keys.
    cf_clearance = str(cookie_store.get("cf_clearance") or "").strip()
    cf_bm = str(cookie_store.get("__cf_bm") or "").strip()
    cfuvid = str(cookie_store.get("_cfuvid") or "").strip()
    provisional_user_id = str(cookie_store.get("provisional_user_id") or "").strip()

    if cf_clearance and config.get("cf_clearance") != cf_clearance:
        config["cf_clearance"] = cf_clearance
        changed = True
    if cf_bm and config.get("cf_bm") != cf_bm:
        config["cf_bm"] = cf_bm
        changed = True
    if cfuvid and config.get("cfuvid") != cfuvid:
        config["cfuvid"] = cfuvid
        changed = True
    if provisional_user_id and config.get("provisional_user_id") != provisional_user_id:
        config["provisional_user_id"] = provisional_user_id
        changed = True

    ua = str(user_agent or "").strip()
    if ua and str(config.get("user_agent") or "").strip() != ua:
        config["user_agent"] = ua
        changed = True

    return changed

def extract_recaptcha_params_from_text(text: str) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(text, str) or not text:
        return None, None

    discovered_sitekey: Optional[str] = None
    discovered_action: Optional[str] = None

    if "execute" in text and "action" in text:
        patterns = [
            r'grecaptcha\.enterprise\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\"]{1,80})["\']',
            r'grecaptcha\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\"]{1,80})["\']',
            r'\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\"]{1,80})["\']',
        ]
        for pattern in patterns:
            try:
                match = re.search(pattern, text)
            except re.error:
                continue
            if not match:
                continue
            sitekey = str(match.group("sitekey") or "").strip()
            action = str(match.group("action") or "").strip()
            if sitekey and action:
                return sitekey, action

    sitekey_patterns = [
        r'recaptcha/(?:enterprise|api)\.js\?render=(?P<sitekey>[0-9A-Za-z_-]{8,200})',
        r'(?:enterprise|api)\.js\?render=(?P<sitekey>[0-9A-Za-z_-]{8,200})',
    ]
    for pattern in sitekey_patterns:
        try:
            match = re.search(pattern, text)
        except re.error:
            continue
        if not match:
            continue
        sitekey = str(match.group("sitekey") or "").strip()
        if sitekey:
            discovered_sitekey = sitekey
            break

    if "recaptcha" in text.lower() or "X-Recaptcha-Action" in text or "x-recaptcha-action" in text:
        action_patterns = [
            r'X-Recaptcha-Action["\"]\s*[:=]\s*["\'](?P<action>[^"\"]{1,80})["\"]',
            r'X-Recaptcha-Action["\"]\s*,\s*["\"](?P<action>[^"\"]{1,80})["\"]',
            r'x-recaptcha-action["\"]\s*[:=]\s*["\'](?P<action>[^"\"]{1,80})["\"]',
        ]
        for pattern in action_patterns:
            try:
                match = re.search(pattern, text)
            except re.error:
                continue
            if not match:
                continue
            action = str(match.group("action") or "").strip()
            if action:
                discovered_action = action
                break

    return discovered_sitekey, discovered_action

def get_recaptcha_settings(config: dict) -> tuple[str, str]:
    # Require config to be passed (dependency injection)
    cfg = config or {}
    sitekey = str(cfg.get("recaptcha_sitekey") or "").strip()
    action = str(cfg.get("recaptcha_action") or "").strip()
    if not sitekey:
        sitekey = RECAPTCHA_SITEKEY
    if not action:
        action = RECAPTCHA_ACTION
    return sitekey, action

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
    if not _is_windows():
        return False
    if not isinstance(title_substring, str) or not title_substring.strip():
        return False
    normalized_mode = _normalize_camoufox_window_mode(mode)
    if normalized_mode == "visible":
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

    GetWindowLongW = user32.GetWindowLongW
    GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    GetWindowLongW.restype = ctypes.c_long

    SetWindowLongW = user32.SetWindowLongW
    SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_long]
    SetWindowLongW.restype = ctypes.c_long

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
    SWP_NOMOVE = 0x0002
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
                # Hide from the Windows taskbar while keeping the browser "headful" (not headless).
                # Minimizing can cause Turnstile/grecaptcha interaction stalls; keep the window un-minimized.
                try:
                    exstyle = int(GetWindowLongW(hwnd, GWL_EXSTYLE) or 0)
                    new_exstyle = (exstyle | WS_EX_TOOLWINDOW) & (~WS_EX_APPWINDOW)
                    if new_exstyle != exstyle:
                        SetWindowLongW(hwnd, GWL_EXSTYLE, ctypes.c_long(int(new_exstyle)))
                    SetWindowPos(
                        hwnd,
                        0,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                    )
                except Exception:
                    pass
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

async def apply_camoufox_window_mode(
    page,
    config: dict,
    *,
    mode_key: str,
    marker: str,
    headless: bool,
) -> None:
    if headless:
        return
    if not _is_windows():
        return
    cfg = config or {}
    raw_mode = cfg.get(mode_key)
    if str(mode_key or "") == "camoufox_proxy_window_mode":
        if raw_mode is None or not str(raw_mode).strip():
            raw_mode = "hide"
    mode = _normalize_camoufox_window_mode(raw_mode)
    if mode == "visible":
        return
    try:
        await page.evaluate("t => { document.title = t; }", str(marker))
    except Exception:
        pass
    for _ in range(20):
        if _windows_apply_window_mode_by_title_substring(str(marker), mode):
            return
        await asyncio.sleep(0.1)

async def click_turnstile(page):
    try:
        selectors = [
            '#lm-bridge-turnstile',
            '#lm-bridge-turnstile iframe',
            '#cf-turnstile',
            'iframe[src*="challenges.cloudflare.com"]',
            '[style*="display: grid"] iframe'
        ]
        
        for selector in selectors:
            try:
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

            if elements:
                debug_print(f"  🖱️  Attempting to click Cloudflare Turnstile (found {selector})...")

            for element in elements or []:
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

                try:
                    try:
                        await element.click(force=True)
                    except TypeError:
                        await element.click()
                    await asyncio.sleep(2)
                    return True
                except Exception:
                    pass

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

async def get_recaptcha_v3_token_with_chrome(
    config: dict,
    save_config_callback: Optional[Callable[[dict], None]] = None,
    *,
    config_file: str = "config.json",
) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None

    chrome_path = find_chrome_executable()
    if not chrome_path:
        return None

    profile_dir = Path(str(config_file or "config.json")).with_name("chrome_grecaptcha")

    cf_clearance = str(config.get("cf_clearance") or "").strip()
    cf_bm = str(config.get("cf_bm") or "").strip()
    cfuvid = str(config.get("cfuvid") or "").strip()
    provisional_user_id = str(config.get("provisional_user_id") or "").strip()
    user_agent = normalize_user_agent_value(config.get("user_agent"))
    recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(config)

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
            headless=False,
            user_agent=user_agent or None,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )
        try:
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
                        if name == "arena-auth-prod-v1":
                            cookies_to_add.append(c)
                            continue

                        if name in ("cf_clearance", "__cf_bm", "_GRECAPTCHA"):
                            continue

                        if name in existing_names:
                            continue
                        cookies_to_add.append(c)

                    if cookies_to_add:
                        await context.add_cookies(cookies_to_add)
                except Exception:
                    pass

            page = await context.new_page()
            await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)

            try:
                for _ in range(5):
                    title = await page.title()
                    if "Just a moment" not in title:
                        break
                    await click_turnstile(page)
                    await asyncio.sleep(2)
            except Exception:
                pass

            try:
                await page.mouse.move(100, 100)
                await page.mouse.wheel(0, 200)
                await asyncio.sleep(1)
                await page.mouse.move(200, 300)
                await page.mouse.wheel(0, 300)
                await asyncio.sleep(3)
            except Exception:
                pass

            try:
                fresh_cookies = await context.cookies("https://lmarena.ai")
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                
                if upsert_browser_session(config, fresh_cookies, user_agent=ua_now):
                    if save_config_callback:
                        save_config_callback(config)
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
