import asyncio
import builtins as _builtins
import json
import os
import re
import shutil
import sys
import uuid
import time
import secrets
import base64
import mimetypes
from collections import defaultdict
from contextlib import asynccontextmanager, AsyncExitStack
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit

import uvicorn
from camoufox.async_api import AsyncCamoufox
from fastapi import FastAPI, HTTPException, Depends, status, Form, Request, Response
from starlette.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import APIKeyHeader

import httpx

# ============================================================
# CONFIGURATION
# ============================================================
# Set to True for detailed logging, False for minimal logging
DEBUG = True

# Port to run the server on
PORT = 8000

# HTTP Status Codes
class HTTPStatus:
    # 1xx Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    EARLY_HINTS = 103
    
    # 2xx Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    
    # 3xx Redirection
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    MOVED_TEMPORARILY = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308
    
    # 4xx Client Errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    REQUEST_TOO_LONG = 413
    REQUEST_URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    IM_A_TEAPOT = 418
    INSUFFICIENT_SPACE_ON_RESOURCE = 419
    METHOD_FAILURE = 420
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    UNAVAILABLE_FOR_LEGAL_REASONS = 451
    
    # 5xx Server Errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    INSUFFICIENT_STORAGE = 507
    NETWORK_AUTHENTICATION_REQUIRED = 511

# Status code descriptions for logging
STATUS_MESSAGES = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK - Success",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request - Invalid request syntax",
    401: "Unauthorized - Invalid or expired token",
    402: "Payment Required",
    403: "Forbidden - Access denied",
    404: "Not Found - Resource doesn't exist",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone - Resource permanently deleted",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Too Long - Payload too large",
    414: "Request URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a Teapot",
    419: "Insufficient Space on Resource",
    420: "Method Failure",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests - Rate limit exceeded",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    507: "Insufficient Storage",
    511: "Network Authentication Required"
}

def get_status_emoji(status_code: int) -> str:
    """Get emoji for status code"""
    if 200 <= status_code < 300:
        return "✅"
    elif 300 <= status_code < 400:
        return "↪️"
    elif 400 <= status_code < 500:
        if status_code == 401:
            return "🔒"
        elif status_code == 403:
            return "🚫"
        elif status_code == 404:
            return "❓"
        elif status_code == 429:
            return "⏱️"
        return "⚠️"
    elif 500 <= status_code < 600:
        return "❌"
    return "ℹ️"

def log_http_status(status_code: int, context: str = ""):
    """Log HTTP status with readable message"""
    emoji = get_status_emoji(status_code)
    message = STATUS_MESSAGES.get(status_code, f"Unknown Status {status_code}")
    if context:
        debug_print(f"{emoji} HTTP {status_code}: {message} ({context})")
    else:
        debug_print(f"{emoji} HTTP {status_code}: {message}")
# ============================================================

def get_rate_limit_sleep_seconds(retry_after: Optional[str], attempt: int) -> int:
    """Compute backoff seconds for upstream 429 responses."""
    if isinstance(retry_after, str):
        try:
            value = int(float(retry_after.strip()))
        except Exception:
            value = 0
        if value > 0:
            # Respect upstream guidance when present (Retry-After can exceed 60s).
            return min(value, 3600)

    attempt = max(0, int(attempt))
    # Exponential backoff, capped to avoid unbounded waits.
    return int(min(5 * (2**attempt), 300))


def get_general_backoff_seconds(attempt: int) -> int:
    """Compute general exponential backoff seconds."""
    attempt = max(0, int(attempt))
    return int(min(2 * (2**attempt), 30))

def safe_print(*args, **kwargs) -> None:
    """
    Print without crashing on Windows console encoding issues (e.g., GBK can't encode emoji).
    This must never raise, because it's used inside request handlers/streaming generators.
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


# Ensure all module-level `print(...)` calls are resilient to Windows console encoding issues.
# (Some environments default to GBK, which cannot encode emoji.)
print = safe_print  # type: ignore[assignment]

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is True"""
    if DEBUG:
        print(*args, **kwargs)

# --- New reCAPTCHA Functions ---

# Updated constants from gpt4free/g4f/Provider/needs_auth/LMArena.py
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"
# reCAPTCHA Enterprise v2 sitekey used when v3 scoring fails and LMArena prompts a checkbox challenge.
RECAPTCHA_V2_SITEKEY = "6Ld7ePYrAAAAAB34ovoFoDau1fqCJ6IyOjFEQaMn"
# Cloudflare Turnstile sitekey used by LMArena to mint anonymous-user signup tokens.
# (Used for POST /nextjs-api/sign-up before `arena-auth-prod-v1` exists.)
TURNSTILE_SITEKEY = "0x4AAAAAAA65vWDmG-O_lPtT"

# LMArena occasionally changes the reCAPTCHA sitekey/action. We try to discover them from captured JS chunks on startup
# and persist them into config.json; these helpers read and apply those values with safe fallbacks.
def extract_recaptcha_params_from_text(text: str) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(text, str) or not text:
        return None, None

    discovered_sitekey: Optional[str] = None
    discovered_action: Optional[str] = None

    # 1) Prefer direct matches from execute(sitekey,{action:"..."}) when present.
    if "execute" in text and "action" in text:
        patterns = [
            r'grecaptcha\.enterprise\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'grecaptcha\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
            # Fallback for minified code that aliases grecaptcha to another identifier.
            r'\.execute\(\s*["\'](?P<sitekey>6[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
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

    # 2) Discover sitekey from the enterprise.js/api.js render URL (common in HTML/JS chunks).
    # Example: https://www.google.com/recaptcha/enterprise.js?render=SITEKEY
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

    # 3) Discover action from headers/constants in client-side code.
    if "recaptcha" in text.lower() or "X-Recaptcha-Action" in text or "x-recaptcha-action" in text:
        action_patterns = [
            r'X-Recaptcha-Action["\']\s*[:=]\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'X-Recaptcha-Action["\']\s*,\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'x-recaptcha-action["\']\s*[:=]\s*["\'](?P<action>[^"\']{1,80})["\']',
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


def get_recaptcha_settings(config: Optional[dict] = None) -> tuple[str, str]:
    cfg = config or get_config()
    sitekey = str((cfg or {}).get("recaptcha_sitekey") or "").strip()
    action = str((cfg or {}).get("recaptcha_action") or "").strip()
    if not sitekey:
        sitekey = RECAPTCHA_SITEKEY
    if not action:
        action = RECAPTCHA_ACTION
    return sitekey, action

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
                    debug_print(f"Windows hide mode exstyle update failed: {ex}")
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
    """
    if headless:
        return
    if not _is_windows():
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
        if _windows_apply_window_mode_by_title_substring(marker_str, mode):
            return
        await asyncio.sleep(0.1)

    async def _late_apply() -> None:
        for _ in range(180):  # ~18s best-effort
            if _windows_apply_window_mode_by_title_substring(marker_str, mode):
                return
            await asyncio.sleep(0.1)

    try:
        asyncio.create_task(_late_apply())
    except Exception:
        return


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


async def _mint_recaptcha_v3_token_in_page(
    page,
    *,
    sitekey: str,
    action: str,
    grecaptcha_timeout_ms: int = 60000,
    grecaptcha_poll_ms: int = 250,
    outer_timeout_seconds: float = 70.0,
) -> str:
    """
    Best-effort reCAPTCHA v3 token minting inside an existing page.

    LMArena currently requires a `recaptchaToken` (action: "sign_up") for anonymous signup.
    """
    sitekey = str(sitekey or "").strip()
    action = str(action or "").strip()
    if not sitekey:
        return ""
    if not action:
        action = "sign_up"

    mint_js = """async ({ sitekey, action, timeoutMs, pollMs }) => {
      // LM_BRIDGE_MINT_RECAPTCHA_V3
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const w = (window.wrappedJSObject || window);
      const key = String(sitekey || '');
      const act = String(action || 'sign_up');
      const limit = Math.max(1000, Math.min(Number(timeoutMs || 60000), 180000));
      const poll = Math.max(50, Math.min(Number(pollMs || 250), 2000));
      const start = Date.now();

      const pickG = () => {
        const ent = w?.grecaptcha?.enterprise;
        if (ent && typeof ent.execute === 'function' && typeof ent.ready === 'function') return ent;
        const g = w?.grecaptcha;
        if (g && typeof g.execute === 'function' && typeof g.ready === 'function') return g;
        return null;
      };

      const inject = () => {
        try {
          if (w.__LM_BRIDGE_RECAPTCHA_INJECTED) return;
          w.__LM_BRIDGE_RECAPTCHA_INJECTED = true;
          const h = w.document?.head;
          if (!h) return;
          const urls = [
            'https://www.google.com/recaptcha/enterprise.js?render=' + encodeURIComponent(key),
            'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(key),
          ];
          for (const u of urls) {
            const s = w.document.createElement('script');
            s.src = u;
            s.async = true;
            s.defer = true;
            h.appendChild(s);
          }
        } catch (e) { console.error('LM Bridge: reCAPTCHA v3 script injection failed', e); }
      };

      let injected = false;
      while ((Date.now() - start) < limit) {
        const g = pickG();
        if (g) {
          try {
            // g.ready can hang; guard with a short timeout.
            await Promise.race([
              new Promise((resolve) => { try { g.ready(resolve); } catch (e) { console.error('LM Bridge: reCAPTCHA v3 ready callback failed', e); resolve(true); } }),
              sleep(5000),
            ]);
          } catch (e) { console.error('LM Bridge: reCAPTCHA v3 ready wait failed', e); }
          try {
            // Firefox Xray wrappers: build params in the page compartment.
            const params = new w.Object();
            params.action = act;
            const tok = await g.execute(key, params);
            return String(tok || '');
          } catch (e) {
            console.error('LM Bridge: reCAPTCHA v3 execute failed', e);
            return '';
          }
        }
        if (!injected) { injected = true; inject(); }
        await sleep(poll);
      }
      return '';
    }"""

    try:
        tok = await asyncio.wait_for(
            page.evaluate(
                mint_js,
                {
                    "sitekey": sitekey,
                    "action": action,
                    "timeoutMs": int(grecaptcha_timeout_ms),
                    "pollMs": int(grecaptcha_poll_ms),
                },
            ),
            timeout=float(outer_timeout_seconds),
        )
    except asyncio.TimeoutError:
        debug_print("reCAPTCHA v3 mint timed out in page.")
        tok = ""
    except Exception as e:
        debug_print(f"Unexpected error minting reCAPTCHA v3 token in page: {type(e).__name__}: {e}")
        tok = ""
    return str(tok or "").strip()


async def _camoufox_proxy_signup_anonymous_user(
    page,
    *,
    turnstile_token: str,
    provisional_user_id: str,
    recaptcha_sitekey: str,
    recaptcha_action: str = "sign_up",
) -> Optional[dict]:
    """
    Perform LMArena anonymous signup using the same flow as the site JS:
    POST /nextjs-api/sign-up with {turnstileToken, recaptchaToken, provisionalUserId}.
    """
    turnstile_token = str(turnstile_token or "").strip()
    provisional_user_id = str(provisional_user_id or "").strip()
    recaptcha_sitekey = str(recaptcha_sitekey or "").strip()
    recaptcha_action = str(recaptcha_action or "").strip() or "sign_up"

    if not turnstile_token or not provisional_user_id:
        return None

    recaptcha_token = await _mint_recaptcha_v3_token_in_page(
        page,
        sitekey=recaptcha_sitekey,
        action=recaptcha_action,
    )
    if not recaptcha_token:
        debug_print("⚠️ Camoufox proxy: reCAPTCHA mint failed for anonymous signup.")
        return None

    sign_up_js = """async ({ turnstileToken, recaptchaToken, provisionalUserId }) => {
      // LM_BRIDGE_ANON_SIGNUP
      const w = (window.wrappedJSObject || window);
      const opts = new w.Object();
      opts.method = 'POST';
      opts.credentials = 'include';
      // Match site behavior: let the browser set Content-Type for string bodies (text/plain;charset=UTF-8).
      opts.body = JSON.stringify({
        turnstileToken: String(turnstileToken || ''),
        recaptchaToken: String(recaptchaToken || ''),
        provisionalUserId: String(provisionalUserId || ''),
      });
      const res = await w.fetch('/nextjs-api/sign-up', opts);
      let text = '';
      try { text = await res.text(); } catch (e) { text = ''; }
      return { status: Number(res.status || 0), ok: !!res.ok, body: String(text || '') };
    }"""

    try:
        resp = await asyncio.wait_for(
            page.evaluate(
                sign_up_js,
                {
                    "turnstileToken": turnstile_token,
                    "recaptchaToken": recaptcha_token,
                    "provisionalUserId": provisional_user_id,
                },
            ),
            timeout=20.0,
        )
    except Exception as e:
        debug_print(f"Unexpected error during anonymous signup evaluate: {type(e).__name__}: {e}")
        resp = None
    return resp if isinstance(resp, dict) else None


async def _set_provisional_user_id_in_browser(page, context, *, provisional_user_id: str) -> None:
    """
    Best-effort: keep the provisional user id consistent across cookies and storage.

    LMArena uses `provisional_user_id` to mint/restore anonymous sessions. If multiple storages disagree (e.g. a stale
    localStorage value vs a rotated cookie), /nextjs-api/sign-up can fail with confusing errors like "User already exists".
    """
    provisional_user_id = str(provisional_user_id or "").strip()
    if not provisional_user_id:
        return

    try:
        if context is not None:
            # Keep cookie variants in sync:
            # - Some sessions store `provisional_user_id` as a domain cookie on `.lmarena.ai`
            # - Others store it as a host-only cookie on `lmarena.ai` (via `url`)
            # If the two disagree, upstream can reject /nextjs-api/sign-up with confusing errors.
            await context.add_cookies(_provisional_user_id_cookie_specs(provisional_user_id))
    except Exception as e:
        debug_print(f"Failed to set provisional_user_id cookies in browser context: {type(e).__name__}: {e}")

    try:
        await page.evaluate(
            """(pid) => {
              const w = (window.wrappedJSObject || window);
              try { w.localStorage.setItem('provisional_user_id', String(pid || '')); } catch (e) {}
              return true;
            }""",
            provisional_user_id,
        )
    except Exception:
        pass


async def _maybe_inject_arena_auth_cookie_from_localstorage(page, context) -> Optional[str]:
    """
    Best-effort: recover a missing `arena-auth-prod-v1` cookie from browser storage.

    Some auth flows keep the Supabase session JSON in localStorage. If the cookie is missing but the session is still
    present, we can encode it into the `base64-<json>` cookie format and inject it.
    """
    if page is None or context is None:
        return None

    try:
        store = await page.evaluate(
            """() => {
              const w = (window.wrappedJSObject || window);
              try {
                const ls = w.localStorage;
                if (!ls) return {};
                const out = {};
                for (let i = 0; i < ls.length; i++) {
                  const k = ls.key(i);
                  if (!k) continue;
                  const key = String(k);
                  if (!(key.includes('auth') || key.includes('sb-') || key.includes('supabase') || key.includes('session'))) continue;
                  out[key] = String(ls.getItem(key) || '');
                }
                return out;
              } catch (e) {
                return {};
              }
            }"""
        )
    except Exception:
        return None

    if not isinstance(store, dict):
        return None

    for _, raw in list(store.items()):
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            cookie = maybe_build_arena_auth_cookie_from_signup_response_body(text)
        except Exception:
            cookie = None
        if not cookie:
            continue
        try:
            if is_arena_auth_token_expired(cookie, skew_seconds=0):
                continue
        except Exception:
            pass

        try:
            try:
                page_url = str(getattr(page, "url", "") or "")
            except Exception:
                page_url = ""
            await context.add_cookies(_arena_auth_cookie_specs(cookie, page_url=page_url))
            _capture_ephemeral_arena_auth_token_from_cookies([{"name": "arena-auth-prod-v1", "value": cookie}])
            debug_print("🦊 Camoufox proxy: injected arena-auth cookie from localStorage session.")
            return cookie
        except Exception:
            continue

    return None


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


async def get_recaptcha_v3_token_with_chrome(config: dict) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return None

    chrome_path = find_chrome_executable()
    if not chrome_path:
        return None

    profile_dir = Path(CONFIG_FILE).with_name("chrome_grecaptcha")

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
                        existing = await _get_arena_context_cookies(context)
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
            await _maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="chrome_fetch_window_mode",
                marker="LMArenaBridge Chrome Fetch",
                headless=bool(headless),
            )
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
                fresh_cookies = await _get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if _upsert_browser_session_into_config(config, fresh_cookies, user_agent=ua_now):
                    save_config(config)
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


class BrowserFetchStreamResponse:
    def __init__(
        self,
        status_code: int,
        headers: Optional[dict],
        text: str = "",
        method: str = "POST",
        url: str = "",
        lines_queue: Optional[asyncio.Queue] = None,
        done_event: Optional[asyncio.Event] = None,
    ):
        self.status_code = int(status_code or 0)
        self.headers = headers or {}
        self._text = text or ""
        self._method = str(method or "POST")
        self._url = str(url or "")
        self._lines_queue = lines_queue
        self._done_event = done_event

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def aclose(self) -> None:
        return None

    @property
    def text(self) -> str:
        if self._lines_queue is not None and not self._text:
            # This is a bit dangerous in a property because it's sync, 
            # but BrowserFetchStreamResponse is used in contexts where .text is expected.
            # However, in this codebase, we mostly use await aread() or aiter_lines().
            # Let's make it safe by NOT buffering here, but informing that it might be empty
            # OR better: the codebase should use await aread().
            return self._text
        return self._text

    async def aiter_lines(self):
        if self._lines_queue is not None:
            # Streaming mode
            while True:
                if self._done_event and self._done_event.is_set() and self._lines_queue.empty():
                    break
                try:
                    # Brief timeout to check done_event occasionally
                    line = await asyncio.wait_for(self._lines_queue.get(), timeout=1.0)
                    if line is None: # Sentinel for EOF
                        break
                    yield line
                except asyncio.TimeoutError:
                    continue
        else:
            # Buffered mode
            for line in self._text.splitlines():
                yield line

    async def aread(self) -> bytes:
        if self._lines_queue is not None:
            # If we try to read the full body of a streaming response, we buffer it all first.
            collected = []
            async for line in self.aiter_lines():
                collected.append(line)
            self._text = "\n".join(collected)
            self._lines_queue = None
            self._done_event = None
        return self._text.encode("utf-8")

    def raise_for_status(self) -> None:
        if self.status_code == 0 or self.status_code >= 400:
            request = httpx.Request(self._method, self._url or "https://lmarena.ai/")
            response = httpx.Response(self.status_code or 502, request=request, content=self._text.encode("utf-8"))
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=request, response=response)


USERSCRIPT_PROXY_LAST_POLL_AT: float = 0.0
_USERSCRIPT_PROXY_QUEUE: Optional[asyncio.Queue] = None
_USERSCRIPT_PROXY_JOBS: dict[str, dict] = {}

def _touch_userscript_poll(now: Optional[float] = None) -> None:
    """
    Update userscript-proxy "last seen" timestamps.

    The bridge supports both an external userscript poller and an internal Camoufox-backed poller.
    Keep both timestamps in sync so strict-model routing can reliably detect proxy availability.
    """
    global USERSCRIPT_PROXY_LAST_POLL_AT, last_userscript_poll
    ts = float(now if now is not None else time.time())
    USERSCRIPT_PROXY_LAST_POLL_AT = ts
    # Legacy timestamp used by older code paths/tests.
    last_userscript_poll = ts


def _get_userscript_proxy_queue() -> asyncio.Queue:
    global _USERSCRIPT_PROXY_QUEUE
    if _USERSCRIPT_PROXY_QUEUE is None:
        _USERSCRIPT_PROXY_QUEUE = asyncio.Queue()
    return _USERSCRIPT_PROXY_QUEUE


def _userscript_proxy_is_active(config: Optional[dict] = None) -> bool:
    cfg = config or get_config()
    poll_timeout = 25
    try:
        poll_timeout = int(cfg.get("userscript_proxy_poll_timeout_seconds", 25))
    except Exception:
        poll_timeout = 25
    active_window = max(10, min(poll_timeout + 10, 90))
    # Back-compat: some callers/tests still update the legacy `last_userscript_poll` timestamp.
    try:
        last = max(float(USERSCRIPT_PROXY_LAST_POLL_AT or 0.0), float(last_userscript_poll or 0.0))
    except Exception:
        last = float(USERSCRIPT_PROXY_LAST_POLL_AT or 0.0)
    try:
        delta = float(time.time()) - float(last)
    except Exception:
        delta = 999999.0
    # Guard against clock skew / patched clocks in tests: a "last poll" timestamp in the future is not active.
    if delta < 0:
        return False
    return delta <= float(active_window)


def _userscript_proxy_check_secret(request: Request) -> None:
    cfg = get_config()
    secret = str(cfg.get("userscript_proxy_secret") or "").strip()
    if secret and request.headers.get("X-LMBridge-Secret") != secret:
        raise HTTPException(status_code=401, detail="Invalid userscript proxy secret")


def _cleanup_userscript_proxy_jobs(config: Optional[dict] = None) -> None:
    cfg = config or get_config()
    ttl_seconds = 90
    try:
        ttl_seconds = int(cfg.get("userscript_proxy_job_ttl_seconds", 90))
    except Exception:
        ttl_seconds = 90
    ttl_seconds = max(10, min(ttl_seconds, 600))

    now = time.time()
    expired: list[str] = []
    for job_id, job in list(_USERSCRIPT_PROXY_JOBS.items()):
        created_at = float(job.get("created_at") or 0.0)
        done = bool(job.get("done"))
        picked_up = False
        try:
            picked_up_event = job.get("picked_up_event")
            if isinstance(picked_up_event, asyncio.Event):
                picked_up = bool(picked_up_event.is_set())
        except Exception:
            picked_up = False
        if done and (now - created_at) > ttl_seconds:
            expired.append(job_id)
        # If a job was never picked up, expire it even if not marked done (stuck/abandoned queue entries).
        elif (not done) and (not picked_up) and (now - created_at) > ttl_seconds:
            expired.append(job_id)
        # Safety: even if picked up, expire if it's been in-flight for too long (e.g. browser crash).
        elif (not done) and picked_up and (now - created_at) > (ttl_seconds * 5):
            expired.append(job_id)
    for job_id in expired:
        _USERSCRIPT_PROXY_JOBS.pop(job_id, None)


def _mark_userscript_proxy_inactive() -> None:
    """
    Mark the userscript-proxy as inactive.

    Do this when we detect proxy health/timeouts so strict-model routing stops preferring a proxy that is not
    responding. The proxy becomes active again once a real poll/push updates the timestamps.
    """
    global USERSCRIPT_PROXY_LAST_POLL_AT, last_userscript_poll
    USERSCRIPT_PROXY_LAST_POLL_AT = 0.0
    last_userscript_poll = 0.0


async def _finalize_userscript_proxy_job(job_id: str, *, error: Optional[str] = None, remove: bool = False) -> None:
    """
    Finalize a userscript-proxy job without touching proxy "last seen" timestamps.

    This is intentionally separate from `push_proxy_chunk()`: server-side timeouts must not keep the proxy
    marked as "active" because that would route future requests back into a dead proxy.
    """
    jid = str(job_id or "").strip()
    if not jid:
        return
    job = _USERSCRIPT_PROXY_JOBS.get(jid)
    if not isinstance(job, dict):
        return

    if error and not job.get("error"):
        job["error"] = str(error)

    if job.get("_finalized"):
        if remove:
            _USERSCRIPT_PROXY_JOBS.pop(jid, None)
        return

    job["_finalized"] = True
    job["done"] = True

    done_event = job.get("done_event")
    if isinstance(done_event, asyncio.Event):
        done_event.set()
    status_event = job.get("status_event")
    if isinstance(status_event, asyncio.Event):
        status_event.set()

    q = job.get("lines_queue")
    if isinstance(q, asyncio.Queue):
        try:
            q.put_nowait(None)
        except Exception:
            try:
                await q.put(None)
            except Exception:
                pass

    if remove:
        _USERSCRIPT_PROXY_JOBS.pop(jid, None)


class UserscriptProxyStreamResponse:
    def __init__(self, job_id: str, timeout_seconds: int = 120):
        self.job_id = str(job_id)
        self._status_code: int = 200
        self._headers: dict = {}
        self._timeout_seconds = int(timeout_seconds or 120)
        self._method = "POST"
        self._url = "https://lmarena.ai/"

    @property
    def status_code(self) -> int:
        # Do not rely on a snapshot: proxy workers can report status after `__aenter__` returns.
        job = _USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if isinstance(job, dict):
            status = job.get("status_code")
            if isinstance(status, int):
                return int(status)
        return int(self._status_code or 0)

    @status_code.setter
    def status_code(self, value: int) -> None:
        try:
            self._status_code = int(value)
        except Exception:
            self._status_code = 0

    @property
    def headers(self) -> dict:
        job = _USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if isinstance(job, dict):
            headers = job.get("headers")
            if isinstance(headers, dict):
                return headers
        return self._headers

    @headers.setter
    def headers(self, value: dict) -> None:
        self._headers = value if isinstance(value, dict) else {}

    async def __aenter__(self):
        job = _USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if not isinstance(job, dict):
            self.status_code = 503
            return self
        # Give the proxy a short window to report the upstream HTTP status before we snapshot it, but don't
        # block if it has already started streaming lines (some proxy implementations report status late).
        status_event = job.get("status_event")
        should_wait_status = False
        if isinstance(status_event, asyncio.Event) and not status_event.is_set():
            should_wait_status = True
            try:
                if job.get("error"):
                    should_wait_status = False
            except Exception:
                pass
            done_event = job.get("done_event")
            if isinstance(done_event, asyncio.Event) and done_event.is_set():
                should_wait_status = False
            q = job.get("lines_queue")
            if isinstance(q, asyncio.Queue) and not q.empty():
                should_wait_status = False

        if should_wait_status:
            try:
                await asyncio.wait_for(
                    status_event.wait(),
                    timeout=min(15.0, float(max(1, self._timeout_seconds))),
                )
            except Exception:
                pass
        self._method = str(job.get("method") or "POST")
        self._url = str(job.get("url") or self._url)
        status = job.get("status_code")
        if isinstance(status, int):
            self.status_code = int(status)
        headers = job.get("headers")
        if isinstance(headers, dict):
            self.headers = headers
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        await self.aclose()
        return False

    async def aclose(self) -> None:
        # Do not eagerly delete completed jobs here.
        #
        # Callers may need to inspect `status_code`/`error` after the context exits (e.g. to decide whether to
        # fall back to Chrome fetch). Jobs are pruned by `_cleanup_userscript_proxy_jobs()` on a short TTL.
        return None

    async def aiter_lines(self):
        job = _USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if not isinstance(job, dict):
            return
        q = job.get("lines_queue")
        done_event = job.get("done_event")
        if not isinstance(q, asyncio.Queue) or not isinstance(done_event, asyncio.Event):
            return

        deadline = time.time() + float(max(5, self._timeout_seconds))
        while True:
            if done_event.is_set() and q.empty():
                break
            remaining = deadline - time.time()
            if remaining <= 0:
                job["error"] = job.get("error") or "userscript proxy timeout"
                job["done"] = True
                done_event.set()
                break
            timeout = max(0.25, min(2.0, remaining))
            try:
                item = await asyncio.wait_for(q.get(), timeout=timeout)
            except asyncio.TimeoutError:
                continue
            if item is None:
                break
            yield str(item)

    async def aread(self) -> bytes:
        job = _USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if not isinstance(job, dict):
            return b""
        q = job.get("lines_queue")
        if not isinstance(q, asyncio.Queue):
            return b""
        items: list[str] = []
        try:
            while True:
                item = q.get_nowait()
                if item is None:
                    break
                items.append(str(item))
        except Exception:
            pass
        return ("\n".join(items)).encode("utf-8")

    def raise_for_status(self) -> None:
        job = _USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if isinstance(job, dict) and job.get("error"):
            request = httpx.Request(self._method, self._url)
            response = httpx.Response(503, request=request, content=str(job.get("error")).encode("utf-8"))
            raise httpx.HTTPStatusError("Userscript proxy error", request=request, response=response)
        status = int(self.status_code or 0)
        if status == 0 or status >= 400:
            request = httpx.Request(self._method, self._url)
            response = httpx.Response(status or 502, request=request)
            raise httpx.HTTPStatusError(f"HTTP {status}", request=request, response=response)


_LMARENA_ORIGIN = "https://lmarena.ai"
_ARENA_ORIGIN = "https://arena.ai"
_ARENA_HOST_TO_ORIGIN = {
    "lmarena.ai": _LMARENA_ORIGIN,
    "www.lmarena.ai": _LMARENA_ORIGIN,
    "arena.ai": _ARENA_ORIGIN,
    "www.arena.ai": _ARENA_ORIGIN,
}


def _detect_arena_origin(url: Optional[str] = None) -> str:
    """
    Return the canonical origin (https://lmarena.ai or https://arena.ai) for a URL-like string.

    LMArena has historically used both domains. Browser automation can land on `arena.ai` even when the backend
    constructs `https://lmarena.ai/...` URLs, so cookie ops must follow the actual origin.
    """
    text = str(url or "").strip()
    if not text:
        return _LMARENA_ORIGIN
    try:
        parts = urlsplit(text)
    except Exception:
        parts = None

    host = ""
    if parts and parts.scheme and parts.netloc:
        host = str(parts.netloc or "").split("@")[-1].split(":")[0].lower()
    if not host:
        host = text.split("/")[0].split("@")[-1].split(":")[0].lower()
    return _ARENA_HOST_TO_ORIGIN.get(host, _LMARENA_ORIGIN)


def _arena_origin_candidates(url: Optional[str] = None) -> list[str]:
    """Return `[primary, secondary]` origins, preferring the detected origin but always including both."""
    primary = _detect_arena_origin(url)
    secondary = _ARENA_ORIGIN if primary == _LMARENA_ORIGIN else _LMARENA_ORIGIN
    return [primary, secondary]


def _arena_auth_cookie_specs(token: str, *, page_url: Optional[str] = None) -> list[dict]:
    """
    Build host-only `arena-auth-prod-v1` cookie specs for both arena.ai and lmarena.ai.

    Using `url` (instead of `domain`) more closely matches how the site stores this cookie (host-only).
    """
    value = str(token or "").strip()
    if not value:
        return []
    specs: list[dict] = []
    for origin in _arena_origin_candidates(page_url):
        specs.append({"name": "arena-auth-prod-v1", "value": value, "url": origin, "path": "/"})
    return specs


def _provisional_user_id_cookie_specs(provisional_user_id: str, *, page_url: Optional[str] = None) -> list[dict]:
    """
    Build `provisional_user_id` cookie specs for both origins.

    LMArena sometimes stores this cookie as host-only and sometimes as a domain cookie; keep both in sync.
    """
    value = str(provisional_user_id or "").strip()
    if not value:
        return []
    specs: list[dict] = []
    for origin in _arena_origin_candidates(page_url):
        specs.append({"name": "provisional_user_id", "value": value, "url": origin, "path": "/"})
    for domain in (".lmarena.ai", ".arena.ai"):
        specs.append({"name": "provisional_user_id", "value": value, "domain": domain, "path": "/"})
    return specs


async def _get_arena_context_cookies(context, *, page_url: Optional[str] = None) -> list[dict]:
    """
    Fetch cookies for both arena.ai and lmarena.ai from a Playwright/Camoufox browser context.
    """
    urls = _arena_origin_candidates(page_url)
    try:
        cookies = await context.cookies(urls)
        return cookies if isinstance(cookies, list) else []
    except Exception:
        pass

    merged: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for url in urls:
        try:
            chunk = await context.cookies(url)
        except Exception:
            chunk = []
        if not isinstance(chunk, list):
            continue
        for c in chunk:
            try:
                key = (
                    str(c.get("name") or ""),
                    str(c.get("domain") or ""),
                    str(c.get("path") or ""),
                )
            except Exception:
                continue
            if key in seen:
                continue
            seen.add(key)
            merged.append(c)
    return merged


def _normalize_userscript_proxy_url(url: str) -> str:
    """
    Convert LMArena absolute URLs into same-origin paths for in-page fetch.

    The Camoufox proxy page can land on `arena.ai` while the backend constructs `https://lmarena.ai/...` URLs.
    Absolute cross-origin URLs can cause browser fetch to reject with a generic NetworkError (CORS).
    """
    text = str(url or "").strip()
    if not text:
        return ""
    if text.startswith("/"):
        return text
    try:
        parts = urlsplit(text)
    except Exception:
        return text
    if not parts.scheme or not parts.netloc:
        return text
    host = str(parts.netloc or "").split("@")[-1].split(":")[0].lower()
    if host not in {"lmarena.ai", "www.lmarena.ai", "arena.ai", "www.arena.ai"}:
        return text
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return path


async def fetch_lmarena_stream_via_userscript_proxy(
    http_method: str,
    url: str,
    payload: dict,
    timeout_seconds: int = 120,
    auth_token: str = "",
) -> Optional[UserscriptProxyStreamResponse]:
    config = get_config()
    _cleanup_userscript_proxy_jobs(config)

    job_id = str(uuid.uuid4())
    lines_queue: asyncio.Queue = asyncio.Queue()
    done_event: asyncio.Event = asyncio.Event()
    status_event: asyncio.Event = asyncio.Event()
    picked_up_event: asyncio.Event = asyncio.Event()

    proxy_url = _normalize_userscript_proxy_url(str(url))
    sitekey, action = get_recaptcha_settings(config)
    job = {
        "created_at": time.time(),
        "job_id": job_id,
        # Job lifecycle markers used by the server-side stream handler to apply timeouts correctly.
        # - phase: queued -> picked_up -> signup -> fetch
        # - picked_up_at_monotonic: set when any proxy worker/poller claims the job
        # - upstream_started_at_monotonic: set when the proxy begins processing the request (may include preflight)
        # - upstream_fetch_started_at_monotonic: set when the upstream HTTP fetch is initiated (after preflight)
        "phase": "queued",
        "picked_up_at_monotonic": None,
        "upstream_started_at_monotonic": None,
        "upstream_fetch_started_at_monotonic": None,
        "url": str(url),
        "method": str(http_method or "POST"),
        # Per-request auth token (do not mutate persisted config). The proxy worker uses this to set
        # the `arena-auth-prod-v1` cookie before executing the in-page fetch.
        "arena_auth_token": str(auth_token or "").strip(),
        "recaptcha_sitekey": sitekey,
        "recaptcha_action": action,
        "payload": {
            "url": proxy_url or str(url),
            "method": str(http_method or "POST"),
            "headers": {"Content-Type": "text/plain;charset=UTF-8"},
            "body": json.dumps(payload) if payload is not None else "",
        },
        "lines_queue": lines_queue,
        "done_event": done_event,
        "status_event": status_event,
        "picked_up_event": picked_up_event,
        "done": False,
        "status_code": 200,
        "headers": {},
        "error": None,
    }
    _USERSCRIPT_PROXY_JOBS[job_id] = job
    await _get_userscript_proxy_queue().put(job_id)
    return UserscriptProxyStreamResponse(job_id, timeout_seconds=timeout_seconds)


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

    config = get_config()
    recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(config)

    cookie_store = config.get("browser_cookies")
    cookie_map: dict[str, str] = {}
    if isinstance(cookie_store, dict):
        for name, value in cookie_store.items():
            if not name or not value:
                continue
            cookie_map[str(name)] = str(value)

    # Prefer the Chrome persistent profile's own Cloudflare/BM cookies when present.
    # We only inject missing cookies to avoid overwriting a valid cf_clearance/__cf_bm with stale values
    # coming from a different browser fingerprint.
    cf_clearance = str(config.get("cf_clearance") or cookie_map.get("cf_clearance") or "").strip()
    cf_bm = str(config.get("cf_bm") or cookie_map.get("__cf_bm") or "").strip()
    cfuvid = str(config.get("cfuvid") or cookie_map.get("_cfuvid") or "").strip()
    provisional_user_id = str(config.get("provisional_user_id") or cookie_map.get("provisional_user_id") or "").strip()
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
        desired_cookies.extend(_arena_auth_cookie_specs(auth_token))

    user_agent = normalize_user_agent_value(config.get("user_agent"))

    fetch_url = _normalize_userscript_proxy_url(url)
    if fetch_url and not fetch_url.startswith("/"):
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

    profile_dir = Path(CONFIG_FILE).with_name("chrome_grecaptcha")
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
                        existing = await _get_arena_context_cookies(context)
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
            await _maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="chrome_fetch_window_mode",
                marker="LMArenaBridge Chrome Fetch",
                headless=bool(headless),
            )
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
                fresh_cookies = await _get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                _capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if _upsert_browser_session_into_config(config, fresh_cookies, user_agent=ua_now):
                    save_config(config)
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
                    {"sitekey": RECAPTCHA_V2_SITEKEY, "timeoutMs": 60000},
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
                    await _cancel_background_task(fetch_task)
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

                        def _on_fetch_task_done(task: "asyncio.Task") -> None:
                            _consume_background_task_exception(task)
                            try:
                                done_event.set()
                            except Exception:
                                pass

                        try:
                            fetch_task.add_done_callback(_on_fetch_task_done)
                        except Exception:
                            pass
                        
                        return BrowserFetchStreamResponse(
                            status_code=status_code,
                            headers=result.get("headers", {}),
                            method=http_method,
                            url=url,
                            lines_queue=lines_queue,
                            done_event=done_event
                        )
                    await _cancel_background_task(fetch_task)
                    break

                await _cancel_background_task(fetch_task)
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
    
    config = get_config()
    recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(config)
    
    cookie_store = config.get("browser_cookies")
    cookie_map: dict[str, str] = {}
    if isinstance(cookie_store, dict):
        for name, value in cookie_store.items():
            if not name or not value:
                continue
            cookie_map[str(name)] = str(value)

    cf_clearance = str(config.get("cf_clearance") or cookie_map.get("cf_clearance") or "").strip()
    cf_bm = str(config.get("cf_bm") or cookie_map.get("__cf_bm") or "").strip()
    cfuvid = str(config.get("cfuvid") or cookie_map.get("_cfuvid") or "").strip()
    provisional_user_id = str(config.get("provisional_user_id") or cookie_map.get("provisional_user_id") or "").strip()
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
        desired_cookies.extend(_arena_auth_cookie_specs(auth_token))

    user_agent = normalize_user_agent_value(config.get("user_agent"))

    fetch_url = _normalize_userscript_proxy_url(url)
    if fetch_url and not fetch_url.startswith("/"):
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
            headless_value = config.get("camoufox_fetch_headless", None)
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
                config,
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
                fresh_cookies = await _get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                _capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if _upsert_browser_session_into_config(config, fresh_cookies, user_agent=ua_now):
                    save_config(config)
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
                            sitekey: {json.dumps(RECAPTCHA_V2_SITEKEY)},
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
                    await _cancel_background_task(fetch_task)
                    await asyncio.sleep(5)
                    continue

                if not _is_recaptcha_validation_failed(status_code, result.get("text")):
                    if status_code < 400:
                        def _on_fetch_task_done(task: "asyncio.Task") -> None:
                            _consume_background_task_exception(task)
                            try:
                                done_event.set()
                            except Exception:
                                pass

                        try:
                            fetch_task.add_done_callback(_on_fetch_task_done)
                        except Exception:
                            pass
                        
                        return BrowserFetchStreamResponse(
                            status_code=status_code,
                            headers=result.get("headers", {}),
                            method=http_method,
                            url=url,
                            lines_queue=lines_queue,
                            done_event=done_event
                        )
                    await _cancel_background_task(fetch_task)
                    break

                await _cancel_background_task(fetch_task)
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


async def fetch_via_proxy_queue(
    url: str,
    payload: dict,
    http_method: str = "POST",
    timeout_seconds: int = 120,
    streaming: bool = False,
    auth_token: str = "",
) -> Optional[object]:
    """
    Fallback transport: delegates the request to a connected Userscript via the Task Queue.
    """
    # Prefer the streaming-capable proxy endpoints when available.
    proxy_stream = await fetch_lmarena_stream_via_userscript_proxy(
        http_method=http_method,
        url=url,
        payload=payload or {},
        timeout_seconds=timeout_seconds,
        auth_token=auth_token,
    )
    if proxy_stream is not None:
        if streaming:
            return proxy_stream

        # Non-streaming call: buffer everything and return a plain response wrapper.
        collected_lines: list[str] = []
        async with proxy_stream as response:
            async for line in response.aiter_lines():
                collected_lines.append(str(line))

        return BrowserFetchStreamResponse(
            status_code=getattr(proxy_stream, "status_code", 200),
            headers=getattr(proxy_stream, "headers", {}),
            text="\n".join(collected_lines),
            method=http_method,
            url=url,
        )

    task_id = str(uuid.uuid4())
    future = asyncio.Future()
    proxy_pending_tasks[task_id] = future

    # Add to queue
    proxy_task_queue.append({
        "id": task_id,
        "url": url,
        "method": http_method,
        "body": json.dumps(payload) if payload else ""
    })
    
    debug_print(f"📫 Added task {task_id} to Proxy Queue. Waiting for Userscript...")

    try:
        # Wait for the first chunk/response from the userscript
        # In a full implementation, we'd handle a stream of chunks.
        # For simplicity here, we await the *first* signal which might be the full text or start of stream.
        # But wait, the userscript sends chunks via POST.
        # We need a way to feed those chunks into a generator.
        # For this MVP, let's assume the userscript sends the FULL response or we handle it via a shared buffer.
        
        # ACTUALLY: The `BrowserFetchStreamResponse` expects a full text or an iterator.
        # If we want true streaming via proxy, we need a Queue, not a Future.
        
        # Let's upgrade `proxy_pending_tasks` to hold an asyncio.Queue for this task_id
        # But `proxy_pending_tasks` type definition above was Future. 
        # For this step, let's implement a simple non-streaming wait (or buffered stream) to keep it KISS as requested.
        # If the userscript sends chunks, we can accumulate them? 
        # No, "stream: True" needs real-time chunks.
        
        # Revised approach for `fetch_via_proxy_queue`:
        # We will wait for the userscript to signal "start" or provide content.
        # Since `BrowserFetchStreamResponse` is designed to wrap a completed text OR an async iterator,
        # let's make it wrap an async iterator that pulls from a Queue.
        
        # We'll need to change `proxy_pending_tasks` value type to `asyncio.Queue` dynamically.
        # But the endpoint `post_proxy_result` expects to set_result on a Future.
        
        # Let's stick to the Future for the *initial connection* / *first byte*.
        result = await asyncio.wait_for(future, timeout=timeout_seconds)
        
        # If result contains "chunk", it's a stream part. 
        # This simple implementation assumes the userscript might send the full text for now OR we accept that
        # we only support non-streaming or buffered-streaming via this simple Future mechanism for the MVP.
        #
        # TO SUPPORT REAL STREAMING:
        # We would need a dedicated WebSocket or a polling mechanism for the *response* too.
        # Given "minimal code changes", let's assume the Userscript gathers the response and sends it back.
        # This might delay the "first token" but ensures reliability.
        
        if isinstance(result, dict):
            if "error" in result:
                debug_print(f"❌ Proxy Task Error: {result['error']}")
                return None
            
            text = result.get("text", "")
            # If the userscript sent "chunk", we might have missed subsequent chunks if we only waited for one Future.
            # So for this MVP, the userscript should buffer and send the full text, 
            # OR we need a more complex "Queue" based mechanism.
            
            # Let's return a response with the text we got.
            return BrowserFetchStreamResponse(
                status_code=result.get("status", 200),
                headers=result.get("headers", {}),
                text=text,
                method=http_method,
                url=url
            )
            
    except asyncio.TimeoutError:
        debug_print(f"❌ Proxy Task {task_id} timed out. Is the Userscript running?")
        if task_id in proxy_pending_tasks:
            del proxy_pending_tasks[task_id]
        if task_id in [t['id'] for t in proxy_task_queue]:
            # Remove from queue if not picked up
            proxy_task_queue[:] = [t for t in proxy_task_queue if t['id'] != task_id]
        return None
    except Exception as e:
        debug_print(f"❌ Proxy Task Exception: {e}")
        return None

    return None

async def get_recaptcha_v3_token() -> Optional[str]:
    """
    Retrieves reCAPTCHA v3 token using a 'Side-Channel' approach.
    We write the token to a global window variable and poll for it, 
    bypassing Promise serialization issues in the Main World bridge.
    """
    global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
    debug_print("🔐 Starting reCAPTCHA v3 token retrieval (Side-Channel Mode)...")
    
    config = get_config()
    cf_clearance = config.get("cf_clearance", "")
    recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(config)
    
    try:
        chrome_token = await get_recaptcha_v3_token_with_chrome(config)
        if chrome_token:
            RECAPTCHA_TOKEN = chrome_token
            RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
            return chrome_token

        # Use isolated world (main_world_eval=False) to avoid execution context destruction issues.
        # We will access the main world objects via window.wrappedJSObject.
        async with AsyncCamoufox(headless=True, main_world_eval=False) as browser:
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
                RECAPTCHA_TOKEN = token
                RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
                return token
            else:
                debug_print("❌ Timed out waiting for token variable to update.")
                return None

    except Exception as e:
        debug_print(f"❌ Unexpected error: {e}")
        return None

async def refresh_recaptcha_token(force_new: bool = False):
    """Checks if the global reCAPTCHA token is expired and refreshes it if necessary."""
    global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
    
    current_time = datetime.now(timezone.utc)
    if force_new:
        RECAPTCHA_TOKEN = None
        RECAPTCHA_EXPIRY = current_time - timedelta(days=365)
    # Unit tests should never launch real browser automation. Tests that need a token patch
    # `refresh_recaptcha_token` / `get_recaptcha_v3_token` explicitly.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return get_cached_recaptcha_token() or None
    # Check if token is expired (set a refresh margin of 10 seconds)
    if RECAPTCHA_TOKEN is None or current_time > RECAPTCHA_EXPIRY - timedelta(seconds=10):
        debug_print("🔄 Recaptcha token expired or missing. Refreshing...")
        new_token = await get_recaptcha_v3_token()
        if new_token:
            RECAPTCHA_TOKEN = new_token
            # reCAPTCHA v3 tokens typically last 120 seconds (2 minutes)
            RECAPTCHA_EXPIRY = current_time + timedelta(seconds=120)
            debug_print(f"✅ Recaptcha token refreshed, expires at {RECAPTCHA_EXPIRY.isoformat()}")
            return new_token
        else:
            debug_print("❌ Failed to refresh recaptcha token.")
            # Set a short retry delay if refresh fails
            RECAPTCHA_EXPIRY = current_time + timedelta(seconds=10)
            return None
    
    return RECAPTCHA_TOKEN

# --- End New reCAPTCHA Functions ---

def get_cached_recaptcha_token() -> str:
    """Return the current reCAPTCHA v3 token if it's still valid, without refreshing."""
    global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
    token = RECAPTCHA_TOKEN
    if not token:
        return ""
    current_time = datetime.now(timezone.utc)
    if current_time > RECAPTCHA_EXPIRY - timedelta(seconds=10):
        return ""
    return str(token)

# Custom UUIDv7 implementation (using correct Unix epoch)
def uuid7():
    """
    Generate a UUIDv7 using Unix epoch (milliseconds since 1970-01-01)
    matching the browser's implementation.
    """
    timestamp_ms = int(time.time() * 1000)
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    
    uuid_int = timestamp_ms << 80
    uuid_int |= (0x7000 | rand_a) << 64
    uuid_int |= (0x8000000000000000 | rand_b)
    
    hex_str = f"{uuid_int:032x}"
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"

# Image upload helper functions
async def upload_image_to_lmarena(image_data: bytes, mime_type: str, filename: str) -> Optional[tuple]:
    """
    Upload an image to LMArena R2 storage and return the key and download URL.
    
    Args:
        image_data: Binary image data
        mime_type: MIME type of the image (e.g., 'image/png')
        filename: Original filename for the image
    
    Returns:
        Tuple of (key, download_url) if successful, or None if upload fails
    """
    try:
        # Validate inputs
        if not image_data:
            debug_print("❌ Image data is empty")
            return None
        
        if not mime_type or not mime_type.startswith('image/'):
            debug_print(f"❌ Invalid MIME type: {mime_type}")
            return None
        
        # Step 1: Request upload URL
        debug_print(f"📤 Step 1: Requesting upload URL for {filename}")
        
        # Get Next-Action IDs from config
        config = get_config()
        upload_action_id = config.get("next_action_upload")
        signed_url_action_id = config.get("next_action_signed_url")
        
        if not upload_action_id or not signed_url_action_id:
            debug_print("❌ Next-Action IDs not found in config. Please refresh tokens from dashboard.")
            return None
        
        # Prepare headers for Next.js Server Action
        request_headers = get_request_headers()
        request_headers.update({
            "Accept": "text/x-component",
            "Content-Type": "text/plain;charset=UTF-8",
            "Next-Action": upload_action_id,
            "Referer": "https://lmarena.ai/?mode=direct",
        })
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://lmarena.ai/?mode=direct",
                    headers=request_headers,
                    content=json.dumps([filename, mime_type]),
                    timeout=30.0
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                debug_print("❌ Timeout while requesting upload URL")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while requesting upload URL: {e}")
                return None
            
            # Parse response - format: 0:{...}\n1:{...}\n
            try:
                lines = response.text.strip().split('\n')
                upload_data = None
                for line in lines:
                    if line.startswith('1:'):
                        upload_data = json.loads(line[2:])
                        break
                
                if not upload_data or not upload_data.get('success'):
                    debug_print(f"❌ Failed to get upload URL: {response.text[:200]}")
                    return None
                
                upload_url = upload_data['data']['uploadUrl']
                key = upload_data['data']['key']
                debug_print(f"✅ Got upload URL and key: {key}")
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                debug_print(f"❌ Failed to parse upload URL response: {e}")
                return None
            
            # Step 2: Upload image to R2 storage
            debug_print(f"📤 Step 2: Uploading image to R2 storage ({len(image_data)} bytes)")
            try:
                response = await client.put(
                    upload_url,
                    content=image_data,
                    headers={"Content-Type": mime_type},
                    timeout=60.0
                )
                response.raise_for_status()
                debug_print(f"✅ Image uploaded successfully")
            except httpx.TimeoutException:
                debug_print("❌ Timeout while uploading image to R2 storage")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while uploading image: {e}")
                return None
            
            # Step 3: Get signed download URL (uses different Next-Action)
            debug_print(f"📤 Step 3: Requesting signed download URL")
            request_headers_step3 = request_headers.copy()
            request_headers_step3["Next-Action"] = signed_url_action_id
            
            try:
                response = await client.post(
                    "https://lmarena.ai/?mode=direct",
                    headers=request_headers_step3,
                    content=json.dumps([key]),
                    timeout=30.0
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                debug_print("❌ Timeout while requesting download URL")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while requesting download URL: {e}")
                return None
            
            # Parse response
            try:
                lines = response.text.strip().split('\n')
                download_data = None
                for line in lines:
                    if line.startswith('1:'):
                        download_data = json.loads(line[2:])
                        break
                
                if not download_data or not download_data.get('success'):
                    debug_print(f"❌ Failed to get download URL: {response.text[:200]}")
                    return None
                
                download_url = download_data['data']['url']
                debug_print(f"✅ Got signed download URL: {download_url[:100]}...")
                return (key, download_url)
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                debug_print(f"❌ Failed to parse download URL response: {e}")
                return None
            
    except Exception as e:
        debug_print(f"❌ Unexpected error uploading image: {type(e).__name__}: {e}")
        return None

def _coerce_message_content_to_text(content) -> str:
    """Best-effort coercion of message content to plain text (no images)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict):
                if part.get("type") == "text":
                    parts.append(str(part.get("text", "")))
                elif "text" in part:
                    parts.append(str(part.get("text", "")))
                elif "content" in part:
                    parts.append(str(part.get("content", "")))
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join([p for p in parts if p is not None]).strip()
    return str(content)


async def process_message_content(content, model_capabilities: dict) -> tuple[str, List[dict]]:
    """
    Process message content, handle images if present and model supports them.
    
    Args:
        content: Message content (string or list of content parts)
        model_capabilities: Model's capability dictionary
    
    Returns:
        Tuple of (text_content, experimental_attachments)
    """
    # Check if model supports image input
    supports_images = model_capabilities.get('inputCapabilities', {}).get('image', False)
    
    # If content is a string, return it as-is
    if isinstance(content, str):
        return content, []
    
    # If content is a list (OpenAI format with multiple parts)
    if isinstance(content, list):
        text_parts = []
        attachments = []
        
        for part in content:
            if isinstance(part, dict):
                if part.get('type') == 'text':
                    text_parts.append(part.get('text', ''))
                elif 'text' in part:
                    text_parts.append(part.get('text', ''))
                elif 'content' in part:
                    text_parts.append(part.get('content', ''))
                    
                elif part.get('type') == 'image_url' and supports_images:
                    image_url = part.get('image_url', {})
                    if isinstance(image_url, dict):
                        url = image_url.get('url', '')
                    else:
                        url = image_url
                    
                    # Handle base64-encoded images
                    if url.startswith('data:'):
                        # Format: data:image/png;base64,iVBORw0KGgo...
                        try:
                            # Validate and parse data URI
                            if ',' not in url:
                                debug_print(f"❌ Invalid data URI format (no comma separator)")
                                continue
                            
                            header, data = url.split(',', 1)
                            
                            # Parse MIME type
                            if ';' not in header or ':' not in header:
                                debug_print(f"❌ Invalid data URI header format")
                                continue
                            
                            mime_type = header.split(';')[0].split(':')[1]
                            
                            # Validate MIME type
                            if not mime_type.startswith('image/'):
                                debug_print(f"❌ Invalid MIME type: {mime_type}")
                                continue
                            
                            # Decode base64
                            try:
                                image_data = base64.b64decode(data)
                            except Exception as e:
                                debug_print(f"❌ Failed to decode base64 data: {e}")
                                continue
                            
                            # Validate image size (max 10MB)
                            if len(image_data) > 10 * 1024 * 1024:
                                debug_print(f"❌ Image too large: {len(image_data)} bytes (max 10MB)")
                                continue
                            
                            # Generate filename
                            ext = mimetypes.guess_extension(mime_type) or '.png'
                            filename = f"upload-{uuid.uuid4()}{ext}"
                            
                            debug_print(f"🖼️  Processing base64 image: {filename}, size: {len(image_data)} bytes")
                            
                            # Upload to LMArena
                            upload_result = await upload_image_to_lmarena(image_data, mime_type, filename)
                            
                            if upload_result:
                                key, download_url = upload_result
                                # Add as attachment in LMArena format
                                attachments.append({
                                    "name": key,
                                    "contentType": mime_type,
                                    "url": download_url
                                })
                                debug_print(f"✅ Image uploaded and added to attachments")
                            else:
                                debug_print(f"⚠️  Failed to upload image, skipping")
                        except Exception as e:
                            debug_print(f"❌ Unexpected error processing base64 image: {type(e).__name__}: {e}")
                    
                    # Handle URL images (direct URLs)
                    elif url.startswith('http://') or url.startswith('https://'):
                        # For external URLs, we'd need to download and re-upload
                        # For now, skip this case
                        debug_print(f"⚠️  External image URLs not yet supported: {url[:100]}")
                        
                elif part.get('type') == 'image_url' and not supports_images:
                    debug_print(f"⚠️  Image provided but model doesn't support images")
            elif isinstance(part, str):
                text_parts.append(part)
        
        # Combine text parts
        text_content = '\n'.join(text_parts).strip()
        return text_content, attachments
    
    # Fallback
    return str(content), []

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await startup_event()
    except Exception as e:
        debug_print(f"❌ Error during startup: {e}")
    yield

app = FastAPI(lifespan=lifespan)

# --- Constants & Global State ---
CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)

# In-memory stores
# { "api_key": { "conversation_id": session_data } }
chat_sessions: Dict[str, Dict[str, dict]] = defaultdict(dict)
# { "session_id": "username" }
dashboard_sessions = {}
# { "api_key": [timestamp1, timestamp2, ...] }
api_key_usage = defaultdict(list)
# { "model_id": count }
model_usage_stats = defaultdict(int)
# Token cycling: current index for round-robin selection
current_token_index = 0
# Track config file path changes to reset per-config state in tests/dev.
_LAST_CONFIG_FILE: Optional[str] = None
# Track which token is assigned to each conversation (conversation_id -> token)
conversation_tokens: Dict[str, str] = {}
# Track failed tokens per request to avoid retrying with same token
request_failed_tokens: Dict[str, set] = {}

# Ephemeral Arena auth cookie captured from browser sessions (not persisted unless enabled).
EPHEMERAL_ARENA_AUTH_TOKEN: Optional[str] = None

# Supabase anon key (public client key) discovered from LMArena's JS bundles. Kept in-memory by default.
SUPABASE_ANON_KEY: Optional[str] = None

# --- New Global State for reCAPTCHA ---
RECAPTCHA_TOKEN: Optional[str] = None
# Initialize expiry far in the past to force a refresh on startup
RECAPTCHA_EXPIRY: datetime = datetime.now(timezone.utc) - timedelta(days=365)
# --------------------------------------

# --- Helper Functions ---

def get_config():
    global current_token_index, _LAST_CONFIG_FILE
    # If tests or callers swap CONFIG_FILE at runtime, reset the token round-robin index so token selection
    # is deterministic per config file.
    if _LAST_CONFIG_FILE != CONFIG_FILE:
        _LAST_CONFIG_FILE = CONFIG_FILE
        current_token_index = 0
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        debug_print(f"⚠️  Config file error: {e}, using defaults")
        config = {}
    except Exception as e:
        debug_print(f"⚠️  Unexpected error reading config: {e}, using defaults")
        config = {}

    # Ensure default keys exist
    try:
        config.setdefault("password", "admin")
        config.setdefault("auth_token", "")
        config.setdefault("auth_tokens", [])  # Multiple auth tokens
        config.setdefault("cf_clearance", "")
        config.setdefault("api_keys", [])
        config.setdefault("usage_stats", {})
        config.setdefault("prune_invalid_tokens", False)
        config.setdefault("persist_arena_auth_cookie", False)
        config.setdefault("camoufox_proxy_window_mode", "hide")
        config.setdefault("camoufox_fetch_window_mode", "hide")
        config.setdefault("chrome_fetch_window_mode", "hide")
        
        # Normalize api_keys to prevent KeyErrors in dashboard and rate limiting
        if isinstance(config.get("api_keys"), list):
            normalized_keys = []
            for i, key_entry in enumerate(config["api_keys"]):
                if isinstance(key_entry, dict):
                    # Ensure 'key' exists as it's critical
                    if "key" not in key_entry:
                        continue # Skip invalid entries missing the actual key
                    
                    if "name" not in key_entry:
                        key_entry["name"] = "Unnamed Key"
                    if "created" not in key_entry:
                        # Use a default old timestamp (Jan 3 2024)
                        key_entry["created"] = 1704236400
                    if "rpm" not in key_entry:
                        key_entry["rpm"] = 60
                    normalized_keys.append(key_entry)
            config["api_keys"] = normalized_keys
    except Exception as e:
        debug_print(f"⚠️  Error setting config defaults: {e}")
    
    return config

def load_usage_stats():
    """Load usage stats from config into memory"""
    global model_usage_stats
    try:
        config = get_config()
        model_usage_stats = defaultdict(int, config.get("usage_stats", {}))
    except Exception as e:
        debug_print(f"⚠️  Error loading usage stats: {e}, using empty stats")
        model_usage_stats = defaultdict(int)

def save_config(config, *, preserve_auth_tokens: bool = True):
    try:
        # Avoid clobbering user-provided auth tokens when multiple tasks write config.json concurrently.
        # Background refreshes/cookie upserts shouldn't overwrite auth tokens that may have been added via the dashboard.
        if preserve_auth_tokens:
            try:
                with open(CONFIG_FILE, "r") as f:
                    on_disk = json.load(f)
            except Exception:
                on_disk = None

            if isinstance(on_disk, dict):
                if "auth_tokens" in on_disk and isinstance(on_disk.get("auth_tokens"), list):
                    config["auth_tokens"] = list(on_disk.get("auth_tokens") or [])
                if "auth_token" in on_disk:
                    config["auth_token"] = str(on_disk.get("auth_token") or "")

        # Persist in-memory stats to the config dict before saving
        config["usage_stats"] = dict(model_usage_stats)
        tmp_path = f"{CONFIG_FILE}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
        os.replace(tmp_path, CONFIG_FILE)
    except Exception as e:
        debug_print(f"❌ Error saving config: {e}")


def _combine_split_arena_auth_cookies(cookies: list[dict]) -> Optional[str]:
    """
    Combine split arena-auth-prod-v1.0 and .1 cookies into a single value.
    Google OAuth sometimes creates split cookies due to size limits.
    """
    parts = {}
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        if name == "arena-auth-prod-v1.0":
            parts[0] = str(cookie.get("value") or "")
        elif name == "arena-auth-prod-v1.1":
            parts[1] = str(cookie.get("value") or "")
    if 0 in parts and 1 in parts:
        combined = (parts[0] + parts[1]).strip()
        return combined if combined else None
    elif 0 in parts:
        value = parts[0].strip()
        return value if value else None
    return None



def _capture_ephemeral_arena_auth_token_from_cookies(cookies: list[dict]) -> None:
    """
    Capture the current `arena-auth-prod-v1` cookie value into an in-memory global.

    This keeps the bridge usable even if the user hasn't pasted tokens into config.json,
    while still honoring `persist_arena_auth_cookie` for persistence.
    """
    global EPHEMERAL_ARENA_AUTH_TOKEN
    try:
        best: Optional[str] = None
        fallback: Optional[str] = None

        # First try to combine split cookies (.0 and .1)
        combined = _combine_split_arena_auth_cookies(cookies)
        if combined:
            try:
                if not is_arena_auth_token_expired(combined, skew_seconds=0):
                    EPHEMERAL_ARENA_AUTH_TOKEN = combined
                    return
                fallback = combined  # It's expired, but a candidate for fallback.
            except Exception:
                # If expiry check fails, treat it as a valid token and return.
                EPHEMERAL_ARENA_AUTH_TOKEN = combined
                return


        for cookie in cookies or []:
            if str(cookie.get("name") or "") != "arena-auth-prod-v1":
                continue
            value = str(cookie.get("value") or "").strip()
            if not value:
                continue
            if fallback is None:
                fallback = value
            try:
                if not is_arena_auth_token_expired(value, skew_seconds=0):
                    best = value
                    break
            except Exception:
                # Unknown formats: treat as usable if we don't have anything better yet.
                if best is None:
                    best = value
        if best:
            EPHEMERAL_ARENA_AUTH_TOKEN = best
        elif fallback:
            EPHEMERAL_ARENA_AUTH_TOKEN = fallback
    except Exception:
        return None

def _upsert_browser_session_into_config(config: dict, cookies: list[dict], user_agent: str | None = None) -> bool:
    """
    Persist useful browser session identity (cookies + UA) into config.json.
    This helps keep Cloudflare + LMArena auth aligned with reCAPTCHA/browser fetch flows.
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

    # Combine split cookies (.0 and .1) and save as arena-auth-prod-v1
    if bool(config.get("persist_arena_auth_cookie")):
        combined = _combine_split_arena_auth_cookies(cookies)
        if combined and cookie_store.get("arena-auth-prod-v1") != combined:
            cookie_store["arena-auth-prod-v1"] = combined
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

def get_models():
    try:
        with open(MODELS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_models(models):
    try:
        tmp_path = f"{MODELS_FILE}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(models, f, indent=2)
        os.replace(tmp_path, MODELS_FILE)
    except Exception as e:
        debug_print(f"❌ Error saving models: {e}")


def get_request_headers():
    """Get request headers with the first available auth token (for compatibility)"""
    config = get_config()
    
    # Try to get token from auth_tokens first, then fallback to single token
    auth_tokens = config.get("auth_tokens", [])
    if auth_tokens:
        token = auth_tokens[0]  # Just use first token for non-API requests
    else:
        token = config.get("auth_token", "").strip()
        if not token:
            cookie_store = config.get("browser_cookies")
            if isinstance(cookie_store, dict) and bool(config.get("persist_arena_auth_cookie")):
                token = str(cookie_store.get("arena-auth-prod-v1") or "").strip()
                if token:
                    config["auth_tokens"] = [token]
                    save_config(config, preserve_auth_tokens=False)
        if not token:
            raise HTTPException(status_code=500, detail="Arena auth token not set in dashboard.")
    
    return get_request_headers_with_token(token)

def normalize_user_agent_value(user_agent: object) -> str:
    ua = str(user_agent or "").strip()
    if not ua:
        return ""
    if ua.lower() in ("user-agent", "user agent"):
        return ""
    return ua

def get_request_headers_with_token(token: str, recaptcha_v3_token: Optional[str] = None):
    """Get request headers with a specific auth token and optional reCAPTCHA v3 token"""
    config = get_config()
    cf_clearance = str(config.get("cf_clearance") or "").strip()
    cf_bm = str(config.get("cf_bm") or "").strip()
    cfuvid = str(config.get("cfuvid") or "").strip()
    provisional_user_id = str(config.get("provisional_user_id") or "").strip()

    cookie_store = config.get("browser_cookies")
    if isinstance(cookie_store, dict):
        if not cf_clearance:
            cf_clearance = str(cookie_store.get("cf_clearance") or "").strip()
        if not cf_bm:
            cf_bm = str(cookie_store.get("__cf_bm") or "").strip()
        if not cfuvid:
            cfuvid = str(cookie_store.get("_cfuvid") or "").strip()
        if not provisional_user_id:
            provisional_user_id = str(cookie_store.get("provisional_user_id") or "").strip()

    cookie_parts: list[str] = []

    def _add_cookie(name: str, value: str) -> None:
        value = str(value or "").strip()
        if value:
            cookie_parts.append(f"{name}={value}")

    _add_cookie("cf_clearance", cf_clearance)
    _add_cookie("__cf_bm", cf_bm)
    _add_cookie("_cfuvid", cfuvid)
    _add_cookie("provisional_user_id", provisional_user_id)
    _add_cookie("arena-auth-prod-v1", token)

    headers: dict[str, str] = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Cookie": "; ".join(cookie_parts),
        "Origin": "https://lmarena.ai",
        "Referer": "https://lmarena.ai/?mode=direct",
    }

    user_agent = normalize_user_agent_value(config.get("user_agent"))
    if user_agent:
        headers["User-Agent"] = user_agent
    
    if recaptcha_v3_token:
        headers["X-Recaptcha-Token"] = recaptcha_v3_token
        _, recaptcha_action = get_recaptcha_settings(config)
        headers["X-Recaptcha-Action"] = recaptcha_action
    return headers

def _decode_arena_auth_session_token(token: str) -> Optional[dict]:
    """
    Decode the `arena-auth-prod-v1` cookie value when it is stored as `base64-<json>`.

    LMArena commonly stores a base64-encoded JSON session payload containing:
      - access_token (JWT)
      - refresh_token
      - expires_at (unix seconds)
    """
    token = str(token or "").strip()
    if not token.startswith("base64-"):
        return None
    b64 = token[len("base64-") :]
    if not b64:
        return None
    try:
        b64 += "=" * ((4 - (len(b64) % 4)) % 4)
        raw = base64.b64decode(b64.encode("utf-8"))
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if isinstance(obj, dict):
        return obj
    return None


def maybe_build_arena_auth_cookie_from_signup_response_body(
    body_text: str, *, now: Optional[float] = None
) -> Optional[str]:
    """
    Best-effort: derive an `arena-auth-prod-v1` cookie value from the /nextjs-api/sign-up response body.

    LMArena often uses a base64-encoded Supabase session payload as the cookie value. Some sign-up responses return
    the session JSON in the response body (instead of a Set-Cookie header). When that happens, we can encode it into
    the `base64-<json>` cookie format and inject it into the browser context.
    """
    text = str(body_text or "").strip()
    if not text:
        return None
    if text.startswith("base64-"):
        return text

    try:
        obj = json.loads(text)
    except Exception:
        return None

    def _looks_like_session(val: object) -> bool:
        if not isinstance(val, dict):
            return False
        access = str(val.get("access_token") or "").strip()
        refresh = str(val.get("refresh_token") or "").strip()
        return bool(access and refresh)

    session: Optional[dict] = None
    if isinstance(obj, dict):
        if _looks_like_session(obj):
            session = obj
        else:
            nested = obj.get("session")
            if _looks_like_session(nested):
                session = nested  # type: ignore[assignment]
            else:
                data = obj.get("data")
                if isinstance(data, dict):
                    if _looks_like_session(data):
                        session = data
                    else:
                        nested2 = data.get("session")
                        if _looks_like_session(nested2):
                            session = nested2  # type: ignore[assignment]
    if not isinstance(session, dict):
        return None

    updated = dict(session)
    if not str(updated.get("expires_at") or "").strip():
        try:
            expires_in = int(updated.get("expires_in") or 0)
        except Exception:
            expires_in = 0
        if expires_in > 0:
            base = float(now) if now is not None else float(time.time())
            updated["expires_at"] = int(base) + int(expires_in)

    try:
        raw = json.dumps(updated, separators=(",", ":")).encode("utf-8")
        b64 = base64.b64encode(raw).decode("utf-8").rstrip("=")
        return "base64-" + b64
    except Exception:
        return None

def _decode_jwt_payload(token: str) -> Optional[dict]:
    token = str(token or "").strip()
    if token.count(".") < 2:
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = str(parts[1] or "")
    if not payload_b64:
        return None
    try:
        payload_b64 += "=" * ((4 - (len(payload_b64) % 4)) % 4)
        raw = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if isinstance(obj, dict):
        return obj
    return None

_SUPABASE_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")


def extract_supabase_anon_key_from_text(text: str) -> Optional[str]:
    """
    Best-effort extraction of Supabase anon key from minified HTML/JS.

    The Supabase anon key is a JWT-like string whose payload commonly contains: {"role":"anon"}.
    """
    text = str(text or "")
    if not text:
        return None

    try:
        matches = _SUPABASE_JWT_RE.findall(text)
    except Exception:
        matches = []

    seen: set[str] = set()
    for cand in matches or []:
        cand = str(cand or "").strip()
        if not cand or cand in seen:
            continue
        seen.add(cand)
        payload = _decode_jwt_payload(cand)
        if not isinstance(payload, dict):
            continue
        if str(payload.get("role") or "") == "anon":
            return cand
    return None


def _derive_supabase_auth_base_url_from_arena_auth_token(token: str) -> Optional[str]:
    """
    Derive the Supabase Auth base URL (e.g. https://<ref>.supabase.co/auth/v1) from an arena-auth session cookie.
    """
    session = _decode_arena_auth_session_token(token)
    if not isinstance(session, dict):
        return None
    access = str(session.get("access_token") or "").strip()
    if not access:
        return None
    payload = _decode_jwt_payload(access)
    if not isinstance(payload, dict):
        return None
    iss = str(payload.get("iss") or "").strip()
    if not iss:
        return None
    if "/auth/v1" in iss:
        base = iss.split("/auth/v1", 1)[0] + "/auth/v1"
        return base
    return iss

def get_arena_auth_token_expiry_epoch(token: str) -> Optional[int]:
    """
    Best-effort expiry detection for arena-auth tokens.

    Returns a unix epoch (seconds) when the token expires, or None if unknown.
    """
    session = _decode_arena_auth_session_token(token)
    if isinstance(session, dict):
        try:
            exp = session.get("expires_at")
            if exp is not None:
                return int(exp)
        except Exception:
            pass
        try:
            access = str(session.get("access_token") or "").strip()
        except Exception:
            access = ""
        if access:
            payload = _decode_jwt_payload(access)
            if isinstance(payload, dict):
                try:
                    exp = payload.get("exp")
                    if exp is not None:
                        return int(exp)
                except Exception:
                    pass

    payload = _decode_jwt_payload(token)
    if isinstance(payload, dict):
        try:
            exp = payload.get("exp")
            if exp is not None:
                return int(exp)
        except Exception:
            return None
    return None

def is_arena_auth_token_expired(token: str, *, skew_seconds: int = 30) -> bool:
    """
    Return True if we can determine that a token is expired (or about to expire).
    Unknown/opaque token formats return False (do not assume expired).
    """
    exp = get_arena_auth_token_expiry_epoch(token)
    if exp is None:
        return False
    try:
        skew = int(skew_seconds)
    except Exception:
        skew = 30
    now = time.time()
    return now >= (float(exp) - float(max(0, skew)))

def is_probably_valid_arena_auth_token(token: str) -> bool:
    """
    LMArena's `arena-auth-prod-v1` cookie is typically a base64-encoded JSON session payload.

    This helper is intentionally conservative: it returns True only for formats we recognize
    as plausible session cookies (base64 session payloads or JWT-like strings).
    """
    token = str(token or "").strip()
    if not token:
        return False
    if token.startswith("base64-"):
        session = _decode_arena_auth_session_token(token)
        if not isinstance(session, dict):
            return False
        access = str(session.get("access_token") or "").strip()
        if access.count(".") < 2:
            return False
        return not is_arena_auth_token_expired(token)
    if token.count(".") >= 2:
        # JWT-like token: require a reasonable length to avoid treating random short strings as tokens.
        if len(token) < 100:
            return False
        return not is_arena_auth_token_expired(token)
    return False

ARENA_AUTH_REFRESH_LOCK: asyncio.Lock = asyncio.Lock()


async def refresh_arena_auth_token_via_lmarena_http(old_token: str, config: Optional[dict] = None) -> Optional[str]:
    """
    Best-effort refresh for `arena-auth-prod-v1` using LMArena itself.

    LMArena appears to refresh Supabase session cookies server-side when you request a page with an expired session
    cookie (it rotates refresh tokens and returns a new `arena-auth-prod-v1` via Set-Cookie).

    This avoids needing the Supabase anon key locally and keeps the bridge working even after `expires_at` passes.
    """
    old_token = str(old_token or "").strip()
    if not old_token or not old_token.startswith("base64-"):
        return None

    cfg = config or get_config()
    ua = normalize_user_agent_value((cfg or {}).get("user_agent")) or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    cookies: dict[str, str] = {}
    try:
        cf_clearance = str((cfg or {}).get("cf_clearance") or "").strip()
        if cf_clearance:
            cookies["cf_clearance"] = cf_clearance
    except Exception:
        pass
    try:
        cf_bm = str((cfg or {}).get("cf_bm") or "").strip()
        if cf_bm:
            cookies["__cf_bm"] = cf_bm
    except Exception:
        pass
    try:
        cfuvid = str((cfg or {}).get("cfuvid") or "").strip()
        if cfuvid:
            cookies["_cfuvid"] = cfuvid
    except Exception:
        pass
    try:
        provisional_user_id = str((cfg or {}).get("provisional_user_id") or "").strip()
        if provisional_user_id:
            cookies["provisional_user_id"] = provisional_user_id
    except Exception:
        pass

    cookies["arena-auth-prod-v1"] = old_token

    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": ua},
            follow_redirects=True,
            timeout=httpx.Timeout(connect=10.0, read=20.0, write=10.0, pool=10.0),
        ) as client:
            resp = await client.get("https://lmarena.ai/", cookies=cookies)
    except Exception:
        return None

    try:
        set_cookie_headers = resp.headers.get_list("set-cookie")
    except Exception:
        raw = resp.headers.get("set-cookie")
        set_cookie_headers = [raw] if raw else []

    for sc in set_cookie_headers or []:
        if not isinstance(sc, str) or not sc:
            continue
        if not sc.lower().startswith("arena-auth-prod-v1="):
            continue
        try:
            new_value = sc.split(";", 1)[0].split("=", 1)[1].strip()
        except Exception:
            continue
        if not new_value:
            continue
        # Accept even if identical (some servers still refresh internal tokens while keeping value stable),
        # but prefer a clearly-valid, non-expired cookie.
        if is_probably_valid_arena_auth_token(new_value) and not is_arena_auth_token_expired(new_value, skew_seconds=0):
            return new_value

    return None


async def refresh_arena_auth_token_via_supabase(old_token: str, *, anon_key: Optional[str] = None) -> Optional[str]:
    """
    Refresh an expired `arena-auth-prod-v1` base64 session directly via Supabase using the embedded refresh_token.

    Requires the Supabase anon key (public client key). We keep it in-memory (SUPABASE_ANON_KEY) by default.
    """
    old_token = str(old_token or "").strip()
    if not old_token or not old_token.startswith("base64-"):
        return None

    session = _decode_arena_auth_session_token(old_token)
    if not isinstance(session, dict):
        return None

    refresh_token = str(session.get("refresh_token") or "").strip()
    if not refresh_token:
        return None

    auth_base = _derive_supabase_auth_base_url_from_arena_auth_token(old_token)
    if not auth_base:
        return None

    key = str(anon_key or SUPABASE_ANON_KEY or "").strip()
    if not key:
        return None

    url = auth_base.rstrip("/") + "/token?grant_type=refresh_token"

    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=20.0, write=10.0, pool=10.0),
            follow_redirects=True,
        ) as client:
            resp = await client.post(url, headers=headers, json={"refresh_token": refresh_token})
    except Exception:
        return None

    try:
        if int(getattr(resp, "status_code", 0) or 0) != 200:
            return None
    except Exception:
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    updated = dict(session)
    for k in ("access_token", "refresh_token", "expires_in", "expires_at", "token_type", "user"):
        if k in data and data.get(k) is not None:
            updated[k] = data.get(k)

    # Ensure expires_at is populated if possible.
    try:
        exp = updated.get("expires_at")
        if exp is None:
            exp = None
        else:
            exp = int(exp)
    except Exception:
        exp = None
    if exp is None:
        try:
            access = str(updated.get("access_token") or "").strip()
        except Exception:
            access = ""
        payload = _decode_jwt_payload(access) if access else None
        if isinstance(payload, dict):
            try:
                jwt_exp = payload.get("exp")
                if jwt_exp is not None:
                    updated["expires_at"] = int(jwt_exp)
            except Exception:
                pass
        if "expires_at" not in updated:
            try:
                expires_in = int(updated.get("expires_in") or 0)
            except Exception:
                expires_in = 0
            if expires_in > 0:
                updated["expires_at"] = int(time.time()) + int(expires_in)

    try:
        raw = json.dumps(updated, separators=(",", ":")).encode("utf-8")
        b64 = base64.b64encode(raw).decode("utf-8").rstrip("=")
        return "base64-" + b64
    except Exception:
        return None


async def maybe_refresh_expired_auth_tokens_via_lmarena_http(exclude_tokens: Optional[set] = None) -> Optional[str]:
    """
    If the on-disk auth token list only contains expired base64 sessions, try to refresh one via LMArena and return it.

    This is in-memory only by default (does not mutate config.json), to avoid surprising users by rewriting tokens.
    """
    excluded = exclude_tokens or set()

    cfg = get_config()
    tokens = cfg.get("auth_tokens", [])
    if not isinstance(tokens, list):
        tokens = []

    expired_base64: list[str] = []
    for t in tokens:
        t = str(t or "").strip()
        if not t or t in excluded:
            continue
        if t.startswith("base64-") and is_arena_auth_token_expired(t, skew_seconds=0):
            expired_base64.append(t)

    if not expired_base64:
        return None

    async with ARENA_AUTH_REFRESH_LOCK:
        # Reload config within the lock to avoid concurrent writers.
        cfg = get_config()
        tokens = cfg.get("auth_tokens", [])
        if not isinstance(tokens, list):
            tokens = []

        for old in list(expired_base64):
            if old in excluded:
                continue
            if old not in tokens:
                continue
            if not is_arena_auth_token_expired(old, skew_seconds=0):
                continue

            new_token = await refresh_arena_auth_token_via_lmarena_http(old, cfg)
            if not new_token:
                continue

            # Also prefer it immediately for subsequent requests.
            global EPHEMERAL_ARENA_AUTH_TOKEN
            EPHEMERAL_ARENA_AUTH_TOKEN = new_token
            return new_token

    return None


async def maybe_refresh_expired_auth_tokens(exclude_tokens: Optional[set] = None) -> Optional[str]:
    """
    Refresh an expired `arena-auth-prod-v1` base64 session without mutating user settings.

    Strategy:
      1) Try LMArena Set-Cookie refresh (no anon key required).
      2) Fall back to Supabase refresh_token grant (requires Supabase anon key discovered from JS bundles).
    """
    excluded = exclude_tokens or set()

    try:
        token = await maybe_refresh_expired_auth_tokens_via_lmarena_http(exclude_tokens=excluded)
    except Exception:
        token = None
    if token:
        return token

    cfg = get_config()
    tokens = cfg.get("auth_tokens", [])
    if not isinstance(tokens, list):
        tokens = []

    expired_base64: list[str] = []
    for t in tokens:
        t = str(t or "").strip()
        if not t or t in excluded:
            continue
        if t.startswith("base64-") and is_arena_auth_token_expired(t, skew_seconds=0):
            expired_base64.append(t)
    if not expired_base64:
        return None

    async with ARENA_AUTH_REFRESH_LOCK:
        cfg = get_config()
        tokens = cfg.get("auth_tokens", [])
        if not isinstance(tokens, list):
            tokens = []

        for old in list(expired_base64):
            if old in excluded:
                continue
            if old not in tokens:
                continue
            if not is_arena_auth_token_expired(old, skew_seconds=0):
                continue

            new_token = await refresh_arena_auth_token_via_supabase(old)
            if not new_token:
                continue

            global EPHEMERAL_ARENA_AUTH_TOKEN
            EPHEMERAL_ARENA_AUTH_TOKEN = new_token
            return new_token

    return None


def get_next_auth_token(exclude_tokens: set = None, *, allow_ephemeral_fallback: bool = True):
    """Get next auth token using round-robin selection
     
    Args:
        exclude_tokens: Set of tokens to exclude from selection (e.g., already tried tokens)
        allow_ephemeral_fallback: If True, may fall back to an in-memory `EPHEMERAL_ARENA_AUTH_TOKEN` when all
            configured tokens are excluded.
    """
    global current_token_index
    config = get_config()
    
    # Get all available tokens
    auth_tokens = config.get("auth_tokens", [])
    if not isinstance(auth_tokens, list):
        auth_tokens = []

    # Normalize and drop empty tokens.
    auth_tokens = [str(t or "").strip() for t in auth_tokens if str(t or "").strip()]

    # Drop tokens we can confidently determine are expired, *except* base64 session cookies.
    # Expired base64 session cookies can often be refreshed via `Set-Cookie` (see
    # `maybe_refresh_expired_auth_tokens_via_lmarena_http`), so we keep them as a better fallback than short
    # placeholder strings like "test-auth".
    filtered_tokens: list[str] = []
    for t in auth_tokens:
        if t.startswith("base64-"):
            filtered_tokens.append(t)
            continue
        try:
            if is_arena_auth_token_expired(t):
                continue
        except Exception:
            # Unknown formats: do not assume expired.
            pass
        filtered_tokens.append(t)
    auth_tokens = filtered_tokens

    # Token preference order:
    #   1) plausible, non-expired tokens (base64/JWT-like)
    #   2) base64 session cookies (even if expired, refreshable)
    #   3) long opaque tokens
    #   4) anything else
    try:
        probable = [t for t in auth_tokens if is_probably_valid_arena_auth_token(t)]
    except Exception:
        probable = []
    base64_any = [t for t in auth_tokens if t.startswith("base64-")]
    long_opaque = [t for t in auth_tokens if len(str(t)) >= 100]
    if probable:
        auth_tokens = probable
    elif base64_any:
        auth_tokens = base64_any
    elif long_opaque:
        auth_tokens = long_opaque

    # If we have at least one *configured* token we recognize as a plausible arena-auth cookie, ignore
    # obviously placeholder/invalid entries (e.g. short "test-token" strings). Do not let an in-memory
    # ephemeral token cause us to drop user-configured tokens, because tests and some deployments use
    # opaque token formats.
    has_probably_valid_config = False
    for t in auth_tokens:
        try:
            if is_probably_valid_arena_auth_token(str(t)):
                has_probably_valid_config = True
                break
        except Exception:
            continue
    if has_probably_valid_config:
        filtered_tokens: list[str] = []
        for t in auth_tokens:
            s = str(t or "").strip()
            if not s:
                continue
            try:
                if is_probably_valid_arena_auth_token(s):
                    filtered_tokens.append(s)
                    continue
            except Exception:
                # Keep unknown formats (they may still be valid).
                filtered_tokens.append(s)
                continue
            # Drop short placeholders when we have at least one plausible token.
            if len(s) < 100:
                continue
            filtered_tokens.append(s)
        auth_tokens = filtered_tokens

    # Back-compat: support single-token config without persisting/mutating user settings.
    if not auth_tokens:
        single_token = str(config.get("auth_token") or "").strip()
        if single_token and not is_arena_auth_token_expired(single_token):
            auth_tokens = [single_token]
    if not auth_tokens and EPHEMERAL_ARENA_AUTH_TOKEN and not is_arena_auth_token_expired(EPHEMERAL_ARENA_AUTH_TOKEN):
        # Use an in-memory token captured from the browser session as a fallback (do not override configured tokens).
        auth_tokens = [EPHEMERAL_ARENA_AUTH_TOKEN]
    if not auth_tokens:
        cookie_store = config.get("browser_cookies")
        if isinstance(cookie_store, dict) and bool(config.get("persist_arena_auth_cookie")):
            token = str(cookie_store.get("arena-auth-prod-v1") or "").strip()
            if token and not is_arena_auth_token_expired(token):
                config["auth_tokens"] = [token]
                save_config(config, preserve_auth_tokens=False)
                auth_tokens = config.get("auth_tokens", [])
        if not auth_tokens:
            raise HTTPException(status_code=500, detail="No auth tokens configured")
    
    # Filter out excluded tokens
    if exclude_tokens:
        available_tokens = [t for t in auth_tokens if t not in exclude_tokens]
        if not available_tokens:
            if allow_ephemeral_fallback:
                # Last resort: if we have a valid in-memory token (captured/refreshed) that isn't excluded,
                # use it rather than failing hard.
                try:
                    candidate = str(EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
                except Exception:
                    candidate = ""
                if (
                    candidate
                    and candidate not in exclude_tokens
                    and is_probably_valid_arena_auth_token(candidate)
                    and not is_arena_auth_token_expired(candidate, skew_seconds=0)
                ):
                    return candidate
            raise HTTPException(status_code=500, detail="No more auth tokens available to try")
    else:
        available_tokens = auth_tokens
    
    # Round-robin selection from available tokens
    token = available_tokens[current_token_index % len(available_tokens)]
    current_token_index = (current_token_index + 1) % len(auth_tokens)
    # If we selected a token we can conclusively determine is expired, prefer a valid in-memory token
    # captured from the browser session (Camoufox/Chrome) rather than hammering upstream with 401s.
    try:
        if token and is_arena_auth_token_expired(token, skew_seconds=0):
            candidate = str(EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
            if (
                candidate
                and (not exclude_tokens or candidate not in exclude_tokens)
                and is_probably_valid_arena_auth_token(candidate)
                and not is_arena_auth_token_expired(candidate, skew_seconds=0)
            ):
                return candidate
    except Exception:
        pass
    return token

def remove_auth_token(token: str, force: bool = False):
    """Remove an expired/invalid auth token from the list if prune is enabled or forced"""
    try:
        config = get_config()
        prune_enabled = config.get("prune_invalid_tokens", False)
        
        if not prune_enabled and not force:
            debug_print(f"🔒 Token failed but pruning is disabled. Keep in config: {token[:20]}...")
            return

        auth_tokens = config.get("auth_tokens", [])
        if token in auth_tokens:
            auth_tokens.remove(token)
            config["auth_tokens"] = auth_tokens
            save_config(config, preserve_auth_tokens=False)
            debug_print(f"🗑️  Removed expired token from list: {token[:20]}...")
    except Exception as e:
        debug_print(f"⚠️  Error removing auth token: {e}")

# --- Dashboard Authentication ---

async def get_current_session(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in dashboard_sessions:
        return dashboard_sessions[session_id]
    return None

# --- API Key Authentication & Rate Limiting ---

async def rate_limit_api_key(key: str = Depends(API_KEY_HEADER)):
    config = get_config()
    api_keys = config.get("api_keys", [])

    api_key_str = None
    if key and key.startswith("Bearer "):
        api_key_str = key[7:].strip()

    # If no API keys configured, allow anonymous access (optional auth)
    if not api_keys:
        return {"key": "anonymous", "name": "Anonymous", "rpm": 9999}

    # If keys are configured but none provided, use first available key
    if not api_key_str:
        api_key_str = api_keys[0]["key"]

    key_data = next((k for k in api_keys if k["key"] == api_key_str), None)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API Key.")

    # Rate Limiting
    rate_limit = key_data.get("rpm", 60)
    current_time = time.time()

    # Clean up old timestamps (older than 60 seconds)
    api_key_usage[api_key_str] = [t for t in api_key_usage[api_key_str] if current_time - t < 60]

    if len(api_key_usage[api_key_str]) >= rate_limit:
        # Calculate seconds until oldest request expires (60 seconds window)
        oldest_timestamp = min(api_key_usage[api_key_str])
        retry_after = int(60 - (current_time - oldest_timestamp))
        retry_after = max(1, retry_after)  # At least 1 second

        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )

    api_key_usage[api_key_str].append(current_time)

    return key_data

# --- Core Logic ---

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
                    _capture_ephemeral_arena_auth_token_from_cookies(cookies)
                    try:
                        user_agent = await page.evaluate("() => navigator.userAgent")
                    except Exception:
                        user_agent = None

                    config = get_config()
                    ua_for_config = None
                    if not normalize_user_agent_value(config.get("user_agent")):
                        ua_for_config = user_agent
                    if _upsert_browser_session_into_config(config, cookies, user_agent=ua_for_config):
                        save_config(config)
                except Exception:
                    pass
                return

            # Give it time to capture all JS responses
            await asyncio.sleep(5)

            # Persist cookies + UA for downstream httpx/chrome-fetch alignment.
            cookies = await page.context.cookies()
            _capture_ephemeral_arena_auth_token_from_cookies(cookies)
            try:
                user_agent = await page.evaluate("() => navigator.userAgent")
            except Exception:
                user_agent = None

            config = get_config()
            # Prefer keeping an existing UA (often set by Chrome contexts) instead of overwriting with Camoufox UA.
            ua_for_config = None
            if not normalize_user_agent_value(config.get("user_agent")):
                ua_for_config = user_agent
            if _upsert_browser_session_into_config(config, cookies, user_agent=ua_for_config):
                save_config(config)

            if str(config.get("cf_clearance") or "").strip():
                debug_print(f"✅ Saved cf_clearance token: {str(config.get('cf_clearance'))[:20]}...")
            else:
                debug_print("⚠️ Could not find cf_clearance cookie.")

            page_body = ""

            # Extract models
            debug_print("Extracting models from page...")
            try:
                page_body = await page.content()
                match = re.search(r'{\\"initialModels\\":(\[.*?\]),\\"initialModel[A-Z]Id', page_body, re.DOTALL)
                if match:
                    models_json = match.group(1).encode().decode('unicode_escape')
                    models = json.loads(models_json)
                    save_models(models)
                    debug_print(f"✅ Saved {len(models)} models")
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
                    config["next_action_upload"] = upload_action_id
                if signed_url_action_id:
                    config["next_action_signed_url"] = signed_url_action_id
                
                if upload_action_id and signed_url_action_id:
                    save_config(config)
                    debug_print(f"\n✅ Saved both Next-Action IDs to config")
                    debug_print(f"   Upload: {upload_action_id}")
                    debug_print(f"   Signed URL: {signed_url_action_id}")
                elif upload_action_id or signed_url_action_id:
                    save_config(config)
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

            # Extract reCAPTCHA sitekey/action from captured JS responses (helps keep up with LMArena changes).
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
                    sitekey, action = extract_recaptcha_params_from_text(text)
                    if sitekey and not discovered_sitekey:
                        discovered_sitekey = sitekey
                    if action and not discovered_action:
                        discovered_action = action
                    if discovered_sitekey and discovered_action:
                        break

                # Fallback: try the HTML we already captured.
                if (not discovered_sitekey or not discovered_action) and page_body:
                    sitekey, action = extract_recaptcha_params_from_text(page_body)
                    if sitekey and not discovered_sitekey:
                        discovered_sitekey = sitekey
                    if action and not discovered_action:
                        discovered_action = action

                if discovered_sitekey:
                    config["recaptcha_sitekey"] = discovered_sitekey
                if discovered_action:
                    config["recaptcha_action"] = discovered_action

                if discovered_sitekey or discovered_action:
                    save_config(config)
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

            # Extract Supabase anon key from captured JS responses (in-memory only).
            # This enables refreshing expired `arena-auth-prod-v1` sessions without user interaction.
            try:
                global SUPABASE_ANON_KEY
                if not str(SUPABASE_ANON_KEY or "").strip():
                    discovered_key: Optional[str] = None
                    for item in captured_responses or []:
                        if not isinstance(item, dict):
                            continue
                        text = item.get("text")
                        if not isinstance(text, str) or not text:
                            continue
                        discovered_key = extract_supabase_anon_key_from_text(text)
                        if discovered_key:
                            break
                    if (not discovered_key) and page_body:
                        discovered_key = extract_supabase_anon_key_from_text(page_body)
                    if discovered_key:
                        SUPABASE_ANON_KEY = discovered_key
                        debug_print(f"✅ Discovered Supabase anon key: {discovered_key[:16]}...")
            except Exception:
                pass

            debug_print("✅ Initial data retrieval complete")
    except Exception as e:
        debug_print(f"❌ An error occurred during initial data retrieval: {e}")

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

async def startup_event():
    # Prevent unit tests (TestClient/ASGITransport) from clobbering the user's real config.json
    # and running slow browser/network startup routines.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return

    try:
        # Ensure config and models files exist
        config = get_config()
        if not config.get("api_keys"):
            config["api_keys"] = [
                {
                    "name": "Default Key",
                    "key": f"sk-lmab-{uuid.uuid4()}",
                    "rpm": 60,
                    "created": int(time.time()),
                }
            ]
        save_config(config)
        save_models(get_models())
        # Load usage stats from config
        load_usage_stats()
        
        # 1. First, get initial data (cookies, models, etc.)
        # We await this so we have the cookie BEFORE trying reCAPTCHA
        await get_initial_data() 

        # Best-effort: if the user-configured auth cookies are expired base64 sessions, try to refresh one so the
        # Camoufox proxy worker can start with a valid `arena-auth-prod-v1` cookie.
        try:
            refreshed = await maybe_refresh_expired_auth_tokens()
        except Exception:
            refreshed = None
        if refreshed:
            debug_print("🔄 Refreshed arena-auth-prod-v1 session (startup).")
        
        # 2. Do not prefetch reCAPTCHA at startup.
        # The internal Camoufox userscript-proxy mints tokens in-page for strict models, and non-strict
        # requests can refresh on-demand. Avoid launching extra browser instances at startup.

        # 3. Start background tasks
        asyncio.create_task(periodic_refresh_task())
        
        # Mark userscript proxy as active at startup to allow immediate delegation
        # to the internal Camoufox proxy worker.
        global last_userscript_poll, USERSCRIPT_PROXY_LAST_POLL_AT
        now = time.time()
        last_userscript_poll = now
        USERSCRIPT_PROXY_LAST_POLL_AT = now
        
        asyncio.create_task(camoufox_proxy_worker())
        
    except Exception as e:
        debug_print(f"❌ Error during startup: {e}")
        # Continue anyway - server should still start

# --- UI Endpoints (Login/Dashboard) ---

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    return RedirectResponse(url="/dashboard")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    if await get_current_session(request):
        return RedirectResponse(url="/dashboard")
    
    error_msg = '<div class="error-message">Invalid password. Please try again.</div>' if error else ''
    
    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - LMArena Bridge</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .login-container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    width: 100%;
                    max-width: 400px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 28px;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #555;
                    font-weight: 500;
                }}
                input[type="password"] {{
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e1e8ed;
                    border-radius: 6px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }}
                input[type="password"]:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                button {{
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s;
                }}
                button:hover {{
                    transform: translateY(-2px);
                }}
                button:active {{
                    transform: translateY(0);
                }}
                .error-message {{
                    background: #fee;
                    color: #c33;
                    padding: 12px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                    border-left: 4px solid #c33;
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>LMArena Bridge</h1>
                <div class="subtitle">Sign in to access the dashboard</div>
                {error_msg}
                <form action="/login" method="post">
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="Enter your password" required autofocus>
                    </div>
                    <button type="submit">Sign In</button>
                </form>
            </div>
        </body>
        </html>
    """

@app.post("/login")
async def login_submit(response: Response, password: str = Form(...)):
    config = get_config()
    if password == config.get("password"):
        session_id = str(uuid.uuid4())
        dashboard_sessions[session_id] = "admin"
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    return RedirectResponse(url="/login?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if session_id in dashboard_sessions:
        del dashboard_sessions[session_id]
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session_id")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/login")

    try:
        config = get_config()
        models = get_models()
    except Exception as e:
        debug_print(f"❌ Error loading dashboard data: {e}")
        # Return error page
        return HTMLResponse(f"""
            <html><body style="font-family: sans-serif; padding: 40px; text-align: center;">
                <h1>⚠️ Dashboard Error</h1>
                <p>Failed to load configuration: {str(e)}</p>
                <p><a href="/logout">Logout</a> | <a href="/dashboard">Retry</a></p>
            </body></html>
        """, status_code=500)

    # Render API Keys
    keys_html = ""
    for key in config["api_keys"]:
        key_name = key.get("name") or "Unnamed Key"
        key_value = key.get("key") or ""
        rpm_value = key.get("rpm", 60)
        created_date = time.strftime('%Y-%m-%d %H:%M', time.localtime(key.get('created', 0)))
        keys_html += f"""
            <tr>
                <td><strong>{key_name}</strong></td>
                <td><code class="api-key-code">{key_value}</code></td>
                <td><span class="badge">{rpm_value} RPM</span></td>
                <td><small>{created_date}</small></td>
                <td>
                    <form action='/delete-key' method='post' style='margin:0;' onsubmit='return confirm("Delete this API key?");'>
                        <input type='hidden' name='key_id' value='{key_value}'>
                        <button type='submit' class='btn-delete'>Delete</button>
                    </form>
                </td>
            </tr>
        """

    # Render Models (limit to first 20 with text output)
    text_models = [m for m in models if m.get('capabilities', {}).get('outputCapabilities', {}).get('text')]
    models_html = ""
    for i, model in enumerate(text_models[:20]):
        rank = model.get('rank', '?')
        org = model.get('organization', 'Unknown')
        models_html += f"""
            <div class="model-card">
                <div class="model-header">
                    <span class="model-name">{model.get('publicName', 'Unnamed')}</span>
                    <span class="model-rank">Rank {rank}</span>
                </div>
                <div class="model-org">{org}</div>
            </div>
        """
    
    if not models_html:
        models_html = '<div class="no-data">No models found. Token may be invalid or expired.</div>'

    # Render Stats
    stats_html = ""
    if model_usage_stats:
        for model, count in sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_html += f"<tr><td>{model}</td><td><strong>{count}</strong></td></tr>"
    else:
        stats_html = "<tr><td colspan='2' class='no-data'>No usage data yet</td></tr>"

    # Check token status
    token_status = "✅ Configured" if config.get("auth_token") else "❌ Not Set"
    token_class = "status-good" if config.get("auth_token") else "status-bad"
    
    cf_status = "✅ Configured" if config.get("cf_clearance") else "❌ Not Set"
    cf_class = "status-good" if config.get("cf_clearance") else "status-bad"
    
    # Get recent activity count (last 24 hours)
    recent_activity = sum(1 for timestamps in api_key_usage.values() for t in timestamps if time.time() - t < 86400)

    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - LMArena Bridge</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
            <style>
                @keyframes fadeIn {{
                    from {{ opacity: 0; transform: translateY(20px); }}
                    to {{ opacity: 1; transform: translateY(0); }}
                }}
                @keyframes slideIn {{
                    from {{ opacity: 0; transform: translateX(-20px); }}
                    to {{ opacity: 1; transform: translateX(0); }}
                }}
                @keyframes pulse {{
                    0%, 100% {{ transform: scale(1); }}
                    50% {{ transform: scale(1.05); }}
                }}
                @keyframes shimmer {{
                    0% {{ background-position: -1000px 0; }}
                    100% {{ background-position: 1000px 0; }}
                }}
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: #f5f7fa;
                    color: #333;
                    line-height: 1.6;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px 0;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header-content {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 0 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                h1 {{
                    font-size: 24px;
                    font-weight: 600;
                }}
                .logout-btn {{
                    background: rgba(255,255,255,0.2);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 6px;
                    text-decoration: none;
                    transition: background 0.3s;
                }}
                .logout-btn:hover {{
                    background: rgba(255,255,255,0.3);
                }}
                .container {{
                    max-width: 1200px;
                    margin: 30px auto;
                    padding: 0 20px;
                }}
                .section {{
                    background: white;
                    border-radius: 10px;
                    padding: 25px;
                    margin-bottom: 25px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                }}
                .section-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid #f0f0f0;
                }}
                h2 {{
                    font-size: 20px;
                    color: #333;
                    font-weight: 600;
                }}
                .status-badge {{
                    padding: 6px 12px;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 600;
                }}
                .status-good {{ background: #d4edda; color: #155724; }}
                .status-bad {{ background: #f8d7da; color: #721c24; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th {{
                    background: #f8f9fa;
                    padding: 12px;
                    text-align: left;
                    font-weight: 600;
                    color: #555;
                    font-size: 14px;
                    border-bottom: 2px solid #e9ecef;
                }}
                td {{
                    padding: 12px;
                    border-bottom: 1px solid #f0f0f0;
                }}
                tr:hover {{
                    background: #f8f9fa;
                }}
                .form-group {{
                    margin-bottom: 15px;
                }}
                label {{
                    display: block;
                    margin-bottom: 6px;
                    font-weight: 500;
                    color: #555;
                }}
                input[type="text"], input[type="number"], textarea {{
                    width: 100%;
                    padding: 10px;
                    border: 2px solid #e1e8ed;
                    border-radius: 6px;
                    font-size: 14px;
                    font-family: inherit;
                    transition: border-color 0.3s;
                }}
                input:focus, textarea:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                textarea {{
                    resize: vertical;
                    font-family: 'Courier New', monospace;
                    min-height: 100px;
                }}
                button, .btn {{
                    padding: 10px 20px;
                    border: none;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                button[type="submit"]:not(.btn-delete) {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }}
                button[type="submit"]:not(.btn-delete):hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }}
                .btn-delete {{
                    background: #dc3545;
                    color: white;
                    padding: 6px 12px;
                    font-size: 13px;
                }}
                .btn-delete:hover {{
                    background: #c82333;
                }}
                .api-key-code {{
                    background: #f8f9fa;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    color: #495057;
                }}
                .badge {{
                    background: #e7f3ff;
                    color: #0066cc;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .model-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }}
                .model-card {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid #667eea;
                }}
                .model-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 8px;
                }}
                .model-name {{
                    font-weight: 600;
                    color: #333;
                    font-size: 14px;
                }}
                .model-rank {{
                    background: #667eea;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 11px;
                    font-weight: 600;
                }}
                .model-org {{
                    color: #666;
                    font-size: 12px;
                }}
                .no-data {{
                    text-align: center;
                    color: #999;
                    padding: 20px;
                    font-style: italic;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .stat-card {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    animation: fadeIn 0.6s ease-out;
                    transition: transform 0.3s;
                }}
                .stat-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 8px 16px rgba(102, 126, 234, 0.4);
                }}
                .section {{
                    animation: slideIn 0.5s ease-out;
                }}
                .section:nth-child(2) {{ animation-delay: 0.1s; }}
                .section:nth-child(3) {{ animation-delay: 0.2s; }}
                .section:nth-child(4) {{ animation-delay: 0.3s; }}
                .model-card {{
                    animation: fadeIn 0.4s ease-out;
                    transition: transform 0.2s, box-shadow 0.2s;
                }}
                .model-card:hover {{
                    transform: translateY(-3px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                }}
                .stat-value {{
                    font-size: 32px;
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                .stat-label {{
                    font-size: 14px;
                    opacity: 0.9;
                }}
                .form-row {{
                    display: grid;
                    grid-template-columns: 2fr 1fr auto;
                    gap: 10px;
                    align-items: end;
                }}
                @media (max-width: 768px) {{
                    .form-row {{
                        grid-template-columns: 1fr;
                    }}
                    .model-grid {{
                        grid-template-columns: 1fr;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="header-content">
                    <h1>🚀 LMArena Bridge Dashboard</h1>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>

            <div class="container">
                <!-- Stats Overview -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{len(config['api_keys'])}</div>
                        <div class="stat-label">API Keys</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(text_models)}</div>
                        <div class="stat-label">Available Models</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{sum(model_usage_stats.values())}</div>
                        <div class="stat-label">Total Requests</div>
                    </div>
                </div>

                <!-- Arena Auth Token -->
                <div class="section">
                    <div class="section-header">
                        <h2>🔐 Arena Authentication Tokens</h2>
                        <span class="status-badge {token_class}">{token_status}</span>
                    </div>
                    
                    <h3 style="margin-bottom: 15px; font-size: 16px;">Multiple Auth Tokens (Round-Robin)</h3>
                    <p style="color: #666; margin-bottom: 15px;">Add multiple tokens for automatic cycling. Each conversation will use a consistent token.</p>
                    
                    {''.join([f'''
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px; padding: 10px; background: #f8f9fa; border-radius: 6px;">
                        <code style="flex: 1; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all;">{token[:50]}...</code>
                        <form action="/delete-auth-token" method="post" style="margin: 0;" onsubmit="return confirm('Delete this token?');">
                            <input type="hidden" name="token_index" value="{i}">
                            <button type="submit" class="btn-delete">Delete</button>
                        </form>
                    </div>
                    ''' for i, token in enumerate(config.get("auth_tokens", []))])}
                    
                    {('<div class="no-data">No tokens configured. Add tokens below.</div>' if not config.get("auth_tokens") else '')}
                    
                    <h3 style="margin-top: 25px; margin-bottom: 15px; font-size: 16px;">Add New Token</h3>
                    <form action="/add-auth-token" method="post">
                        <div class="form-group">
                            <label for="new_auth_token">New Arena Auth Token</label>
                            <textarea id="new_auth_token" name="new_auth_token" placeholder="Paste a new arena-auth-prod-v1 token here" required></textarea>
                        </div>
                        <button type="submit">Add Token</button>
                    </form>
                </div>

                <!-- Cloudflare Clearance -->
                <div class="section">
                    <div class="section-header">
                        <h2>☁️ Cloudflare Clearance</h2>
                        <span class="status-badge {cf_class}">{cf_status}</span>
                    </div>
                    <p style="color: #666; margin-bottom: 15px;">This is automatically fetched on startup. If API requests fail with 404 errors, the token may have expired.</p>
                    <code style="background: #f8f9fa; padding: 10px; display: block; border-radius: 6px; word-break: break-all; margin-bottom: 15px;">
                        {config.get("cf_clearance", "Not set")}
                    </code>
                    <form action="/refresh-tokens" method="post" style="margin-top: 15px;">
                        <button type="submit" style="background: #28a745;">🔄 Refresh Tokens &amp; Models</button>
                    </form>
                    <p style="color: #999; font-size: 13px; margin-top: 10px;"><em>Note: This will fetch a fresh cf_clearance token and update the model list.</em></p>
                </div>

                <!-- API Keys -->
                <div class="section">
                    <div class="section-header">
                        <h2>🔑 API Keys</h2>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Key</th>
                                <th>Rate Limit</th>
                                <th>Created</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {keys_html if keys_html else '<tr><td colspan="5" class="no-data">No API keys configured</td></tr>'}
                        </tbody>
                    </table>
                    
                    <h3 style="margin-top: 30px; margin-bottom: 15px; font-size: 18px;">Create New API Key</h3>
                    <form action="/create-key" method="post">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="name">Key Name</label>
                                <input type="text" id="name" name="name" placeholder="e.g., Production Key" required>
                            </div>
                            <div class="form-group">
                                <label for="rpm">Rate Limit (RPM)</label>
                                <input type="number" id="rpm" name="rpm" value="60" min="1" max="1000" required>
                            </div>
                            <div class="form-group">
                                <label>&nbsp;</label>
                                <button type="submit">Create Key</button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Usage Statistics -->
                <div class="section">
                    <div class="section-header">
                        <h2>📊 Usage Statistics</h2>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px;">
                        <div>
                            <h3 style="text-align: center; margin-bottom: 15px; font-size: 16px; color: #666;">Model Usage Distribution</h3>
                            <canvas id="modelPieChart" style="max-height: 300px;"></canvas>
                        </div>
                        <div>
                            <h3 style="text-align: center; margin-bottom: 15px; font-size: 16px; color: #666;">Request Count by Model</h3>
                            <canvas id="modelBarChart" style="max-height: 300px;"></canvas>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Model</th>
                                <th>Requests</th>
                            </tr>
                        </thead>
                        <tbody>
                            {stats_html}
                        </tbody>
                    </table>
                </div>

                <!-- Available Models -->
                <div class="section">
                    <div class="section-header">
                        <h2>🤖 Available Models</h2>
                    </div>
                    <p style="color: #666; margin-bottom: 15px;">Showing top 20 text-based models (Rank 1 = Best)</p>
                    <div class="model-grid">
                        {models_html}
                    </div>
                </div>
            </div>
            
            <script>
                // Prepare data for charts
                const statsData = {json.dumps(dict(sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]))};
                const modelNames = Object.keys(statsData);
                const modelCounts = Object.values(statsData);
                
                // Generate colors for charts
                const colors = [
                    '#667eea', '#764ba2', '#f093fb', '#4facfe',
                    '#43e97b', '#fa709a', '#fee140', '#30cfd0',
                    '#a8edea', '#fed6e3'
                ];
                
                // Pie Chart
                if (modelNames.length > 0) {{
                    const pieCtx = document.getElementById('modelPieChart').getContext('2d');
                    new Chart(pieCtx, {{
                        type: 'doughnut',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                data: modelCounts,
                                backgroundColor: colors,
                                borderWidth: 2,
                                borderColor: '#fff'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {{
                                legend: {{
                                    position: 'bottom',
                                    labels: {{
                                        padding: 15,
                                        font: {{
                                            size: 11
                                        }}
                                    }}
                                }},
                                tooltip: {{
                                    callbacks: {{
                                        label: function(context) {{
                                            const label = context.label || '';
                                            const value = context.parsed || 0;
                                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = ((value / total) * 100).toFixed(1);
                                            return label + ': ' + value + ' (' + percentage + '%)';
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }});
                    
                    // Bar Chart
                    const barCtx = document.getElementById('modelBarChart').getContext('2d');
                    new Chart(barCtx, {{
                        type: 'bar',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                label: 'Requests',
                                data: modelCounts,
                                backgroundColor: colors[0],
                                borderColor: colors[1],
                                borderWidth: 1
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {{
                                legend: {{
                                    display: false
                                }},
                                tooltip: {{
                                    callbacks: {{
                                        label: function(context) {{
                                            return 'Requests: ' + context.parsed.y;
                                        }}
                                    }}
                                }}
                            }},
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    ticks: {{
                                        stepSize: 1
                                    }}
                                }},
                                x: {{
                                    ticks: {{
                                        font: {{
                                            size: 10
                                        }},
                                        maxRotation: 45,
                                        minRotation: 45
                                    }}
                                }}
                            }}
                        }}
                    }});
                }} else {{
                    // Show "no data" message
                    document.getElementById('modelPieChart').parentElement.innerHTML = '<p style="text-align: center; color: #999; padding: 50px;">No usage data yet</p>';
                    document.getElementById('modelBarChart').parentElement.innerHTML = '<p style="text-align: center; color: #999; padding: 50px;">No usage data yet</p>';
                }}
            </script>
        </body>
        </html>
    """

@app.post("/update-auth-token")
async def update_auth_token(session: str = Depends(get_current_session), auth_token: str = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    config = get_config()
    config["auth_token"] = auth_token.strip()
    save_config(config, preserve_auth_tokens=False)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/create-key")
async def create_key(session: str = Depends(get_current_session), name: str = Form(...), rpm: int = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    try:
        config = get_config()
        new_key = {
            "name": name.strip(),
            "key": f"sk-lmab-{uuid.uuid4()}",
            "rpm": max(1, min(rpm, 1000)),  # Clamp between 1-1000
            "created": int(time.time())
        }
        config["api_keys"].append(new_key)
        save_config(config)
    except Exception as e:
        debug_print(f"❌ Error creating key: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-key")
async def delete_key(session: str = Depends(get_current_session), key_id: str = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    try:
        config = get_config()
        config["api_keys"] = [k for k in config["api_keys"] if k["key"] != key_id]
        save_config(config)
    except Exception as e:
        debug_print(f"❌ Error deleting key: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/add-auth-token")
async def add_auth_token(session: str = Depends(get_current_session), new_auth_token: str = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    try:
        config = get_config()
        token = new_auth_token.strip()
        if token and token not in config.get("auth_tokens", []):
            if "auth_tokens" not in config:
                config["auth_tokens"] = []
            config["auth_tokens"].append(token)
            save_config(config, preserve_auth_tokens=False)
    except Exception as e:
        debug_print(f"❌ Error adding auth token: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-auth-token")
async def delete_auth_token(session: str = Depends(get_current_session), token_index: int = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    try:
        config = get_config()
        auth_tokens = config.get("auth_tokens", [])
        if 0 <= token_index < len(auth_tokens):
            auth_tokens.pop(token_index)
            config["auth_tokens"] = auth_tokens
            save_config(config, preserve_auth_tokens=False)
    except Exception as e:
        debug_print(f"❌ Error deleting auth token: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/refresh-tokens")
async def refresh_tokens(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/login")
    try:
        await get_initial_data()
    except Exception as e:
        debug_print(f"❌ Error refreshing tokens: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

# --- Userscript Proxy Support ---

# In-memory queue for Userscript Proxy
# { task_id: asyncio.Future }
proxy_pending_tasks: Dict[str, asyncio.Future] = {}
# List of tasks waiting to be picked up by the userscript
# [ { id, url, method, body } ]
proxy_task_queue: List[dict] = []
# Timestamp of last userscript poll
last_userscript_poll: float = 0

@app.get("/proxy/tasks")
async def get_proxy_tasks(api_key: dict = Depends(rate_limit_api_key)):
    """
    Endpoint for the Userscript to poll for new tasks.
    Requires a valid API key to prevent unauthorized task stealing.
    """
    global last_userscript_poll
    last_userscript_poll = time.time()
    
    # In a real multi-user scenario, we might want to filter tasks by user/session.
    # For this bridge, we assume a single trust domain.
    current_tasks = list(proxy_task_queue)
    proxy_task_queue.clear()
    return current_tasks

@app.post("/proxy/result/{task_id}")
async def post_proxy_result(task_id: str, request: Request, api_key: dict = Depends(rate_limit_api_key)):
    """
    Endpoint for the Userscript to post results (chunks or full response).
    """
    try:
        data = await request.json()
        if task_id in proxy_pending_tasks:
            future = proxy_pending_tasks[task_id]
            if not future.done():
                future.set_result(data)
        return {"status": "ok"}
    except Exception as e:
        debug_print(f"❌ Error processing proxy result for {task_id}: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/v1/userscript/poll")
async def userscript_poll(request: Request):
    """
    Long-poll endpoint for the Tampermonkey/Violetmonkey proxy client (docs/lmbridge-proxy.user.js).
    Returns 204 when no jobs are available.
    """
    _userscript_proxy_check_secret(request)

    global USERSCRIPT_PROXY_LAST_POLL_AT, last_userscript_poll
    now = time.time()
    USERSCRIPT_PROXY_LAST_POLL_AT = now
    # Keep legacy proxy detection working too.
    last_userscript_poll = now

    try:
        data = await request.json()
    except Exception:
        data = {}

    cfg = get_config()
    timeout_seconds = data.get("timeout_seconds")
    if timeout_seconds is None:
        timeout_seconds = cfg.get("userscript_proxy_poll_timeout_seconds", 25)
    try:
        timeout_seconds = int(timeout_seconds)
    except Exception:
        timeout_seconds = 25
    timeout_seconds = max(0, min(timeout_seconds, 60))

    _cleanup_userscript_proxy_jobs(cfg)

    queue = _get_userscript_proxy_queue()
    end = time.time() + float(timeout_seconds)
    while True:
        remaining = end - time.time()
        if remaining <= 0:
            return Response(status_code=204)
        try:
            job_id = await asyncio.wait_for(queue.get(), timeout=remaining)
        except asyncio.TimeoutError:
            return Response(status_code=204)

        job = _USERSCRIPT_PROXY_JOBS.get(str(job_id))
        if not isinstance(job, dict):
            continue
        # Mark as picked up as soon as we hand the job to a poller so the server-side pickup timeout
        # doesn't trip while the poller/browser is starting.
        try:
            picked = job.get("picked_up_event")
            if isinstance(picked, asyncio.Event) and not picked.is_set():
                picked.set()
                if not job.get("picked_up_at_monotonic"):
                    job["picked_up_at_monotonic"] = time.monotonic()
            if str(job.get("phase") or "") == "queued":
                job["phase"] = "picked_up"
        except Exception:
            pass
        return {"job_id": str(job_id), "payload": job.get("payload") or {}}


@app.post("/api/v1/userscript/push")
async def userscript_push(request: Request):
    """
    Receives streamed lines from the userscript proxy and feeds them into the waiting request.
    """
    _userscript_proxy_check_secret(request)

    try:
        data = await request.json()
    except Exception:
        data = {}

    job_id = str(data.get("job_id") or "").strip()
    if not job_id:
        raise HTTPException(status_code=400, detail="Missing job_id")

    job = _USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Unknown job_id")

    fetch_started = data.get("upstream_fetch_started")
    if fetch_started is None:
        fetch_started = data.get("fetch_started")
    status_code = data.get("status")
    if fetch_started or isinstance(status_code, int):
        try:
            if not job.get("upstream_fetch_started_at_monotonic"):
                job["upstream_fetch_started_at_monotonic"] = time.monotonic()
        except Exception:
            pass

    if isinstance(status_code, int):
        job["status_code"] = int(status_code)
        status_event = job.get("status_event")
        if isinstance(status_event, asyncio.Event):
            status_event.set()
    headers = data.get("headers")
    if isinstance(headers, dict):
        job["headers"] = headers

    error = data.get("error")
    if error:
        job["error"] = str(error)

    lines = data.get("lines") or []
    if isinstance(lines, list):
        for line in lines:
            if line is None:
                continue
            await job["lines_queue"].put(str(line))

    if bool(data.get("done")):
        job["done"] = True
        done_event = job.get("done_event")
        if isinstance(done_event, asyncio.Event):
            done_event.set()
        status_event = job.get("status_event")
        if isinstance(status_event, asyncio.Event):
            status_event.set()
        await job["lines_queue"].put(None)

    return {"status": "ok"}

async def push_proxy_chunk(jid, d) -> None:
    _touch_userscript_poll()

    job_id = str(jid or "").strip()
    job = _USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        return

    if isinstance(d, dict):
        fetch_started = d.get("upstream_fetch_started")
        if fetch_started is None:
            fetch_started = d.get("fetch_started")
        status = d.get("status")
        if fetch_started or isinstance(status, int):
            try:
                if not job.get("upstream_fetch_started_at_monotonic"):
                    job["upstream_fetch_started_at_monotonic"] = time.monotonic()
            except Exception:
                pass

        if isinstance(status, int):
            job["status_code"] = int(status)
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()
            if not job.get("_proxy_status_logged"):
                job["_proxy_status_logged"] = True
                debug_print(f"🦊 Camoufox proxy job {job_id[:8]} upstream status: {int(status)}")
        headers = d.get("headers")
        if isinstance(headers, dict):
            job["headers"] = headers
        error = d.get("error")
        if error:
            job["error"] = str(error)
            debug_print(f"⚠️ Camoufox proxy job {job_id[:8]} error: {str(error)[:200]}")

        debug_obj = d.get("debug")
        if debug_obj and os.environ.get("LM_BRIDGE_PROXY_DEBUG"):
            try:
                dbg_text = json.dumps(debug_obj, ensure_ascii=False)
            except Exception:
                dbg_text = str(debug_obj)
            debug_print(f"🦊 Camoufox proxy debug {job_id[:8]}: {dbg_text[:300]}")

        buffer = str(job.get("_proxy_buffer") or "")
        raw_lines = d.get("lines") or []
        if isinstance(raw_lines, list):
            for raw in raw_lines:
                if raw is None:
                    continue
                # The in-page fetch script emits newline-delimited *lines* (without trailing "\n").
                # Join with an explicit newline so we can safely split/enqueue each line here.
                buffer += f"{raw}\n"

        # Safety: normalize and split regardless of whether JS already split lines.
        buffer = buffer.replace("\r\n", "\n").replace("\r", "\n")
        parts = buffer.split("\n")
        buffer = parts.pop() if parts else ""
        job["_proxy_buffer"] = buffer
        for part in parts:
            part = str(part).strip()
            if not part:
                continue
            await job["lines_queue"].put(part)

        if bool(d.get("done")):
            # Flush any remaining partial line.
            remainder = str(job.get("_proxy_buffer") or "").strip()
            if remainder:
                await job["lines_queue"].put(remainder)
            job["_proxy_buffer"] = ""

            job["done"] = True
            done_event = job.get("done_event")
            if isinstance(done_event, asyncio.Event):
                done_event.set()
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()
            await job["lines_queue"].put(None)
            debug_print(f"🦊 Camoufox proxy job {job_id[:8]} done")


async def camoufox_proxy_worker():
    """
    Internal Userscript-Proxy client backed by Camoufox.
    Maintains a SINGLE persistent browser instance to avoid crash loops and resource exhaustion.
    """
    # Mark the proxy as alive immediately
    _touch_userscript_poll()
    debug_print("🦊 Camoufox proxy worker started (Singleton Mode).")

    browser_cm = None
    browser = None
    context = None
    page = None

    proxy_recaptcha_sitekey = RECAPTCHA_SITEKEY
    proxy_recaptcha_action = RECAPTCHA_ACTION
    last_signup_attempt_at: float = 0.0
    
    queue = _get_userscript_proxy_queue()

    while True:
        try:
            _touch_userscript_poll()
            
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

                cfg = get_config()
                recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(cfg)
                proxy_recaptcha_sitekey = recaptcha_sitekey
                proxy_recaptcha_action = recaptcha_action
                user_agent = normalize_user_agent_value(cfg.get("user_agent"))
                
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
                        profile_dir = Path(CONFIG_FILE).with_name("grecaptcha")
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
                            existing = await _get_arena_context_cookies(context)
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
                        existing = await _get_arena_context_cookies(context)
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
                            has_fresh_existing = not is_arena_auth_token_expired(existing_auth, skew_seconds=0)
                        except Exception:
                            has_fresh_existing = True
                    
                    if not has_fresh_existing:
                        candidate = ""
                        try:
                            if EPHEMERAL_ARENA_AUTH_TOKEN and not is_arena_auth_token_expired(
                                EPHEMERAL_ARENA_AUTH_TOKEN, skew_seconds=0
                            ):
                                candidate = str(EPHEMERAL_ARENA_AUTH_TOKEN).strip()
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
                                    if is_probably_valid_arena_auth_token(t) and not is_arena_auth_token_expired(
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
                            await context.add_cookies(_arena_auth_cookie_specs(candidate))
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
                        asyncio.create_task(push_proxy_chunk(str(jid), payload))
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

                # Capture initial cookies and persist to config.json
                try:
                    fresh_cookies = await _get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                    _capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                    _cfg = get_config()
                    if _upsert_browser_session_into_config(_cfg, fresh_cookies):
                        save_config(_cfg)
                        debug_print("🦊 Camoufox proxy: initial cookies saved to config.")
                except Exception:
                    pass

            async def _get_auth_cookie_value() -> str:
                nonlocal context, page
                if context is None:
                    return ""
                try:
                    cookies = await _get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                except Exception:
                    return ""
                try:
                    _capture_ephemeral_arena_auth_token_from_cookies(cookies or [])
                    # Also persist cookies to config.json when capturing
                    _cfg = get_config()
                    if _upsert_browser_session_into_config(_cfg, cookies):
                        save_config(_cfg)
                except Exception:
                    pass
                candidates: list[str] = []

                # First check for combined split cookies (.0 and .1)
                combined = _combine_split_arena_auth_cookies(cookies)
                if combined:
                    candidates.append(combined)

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
                        if not is_arena_auth_token_expired(value, skew_seconds=0):
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
                        if cur and not is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        try:
                            await click_turnstile(page)
                        except Exception:
                            pass
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

                # If the cookie is missing but an auth session is still present in localStorage, recover it now.
                try:
                    recovered = await _maybe_inject_arena_auth_cookie_from_localstorage(page, context)
                    if recovered and not is_arena_auth_token_expired(recovered, skew_seconds=0):
                        return
                except Exception:
                    pass

                try:
                    cfg_now = get_config()
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
                    await _set_provisional_user_id_in_browser(
                        page,
                        context,
                        provisional_user_id=fresh_provisional,
                    )
                    provisional_user_id = fresh_provisional
                except Exception:
                    pass
                try:
                    try:
                        page_url = str(getattr(page, "url", "") or "")
                    except Exception:
                        page_url = ""
                    clear_specs: list[dict] = []
                    for origin in _arena_origin_candidates(page_url):
                        clear_specs.append(
                            {
                                "name": "arena-auth-prod-v1",
                                "value": "",
                                "url": origin,
                                "path": "/",
                                "expires": 1,
                            }
                        )
                    if clear_specs:
                        await context.add_cookies(clear_specs)
                except Exception:
                    pass
                try:
                    await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)
                except Exception:
                    pass
                try:
                    for _ in range(30):
                        cur = await _get_auth_cookie_value()
                        if cur and not is_arena_auth_token_expired(cur, skew_seconds=0):
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
                        page.evaluate(render_turnstile_js, {"sitekey": TURNSTILE_SITEKEY}),
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

                try:
                    if provisional_user_id:
                        debug_print(
                            f"🦊 Camoufox proxy: provisional_user_id (trunc): {provisional_user_id[:8]}...{provisional_user_id[-4:]}"
                        )
                    resp = await _camoufox_proxy_signup_anonymous_user(
                        page,
                        turnstile_token=token_value,
                        provisional_user_id=provisional_user_id,
                        recaptcha_sitekey=proxy_recaptcha_sitekey,
                        recaptcha_action="sign_up",
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
                if status >= 400 and body_text:
                    debug_print(f"🦊 Camoufox proxy: /nextjs-api/sign-up body (trunc): {body_text[:200]}")
                if status == 400 and "User already exists" in body_text:
                    try:
                        await _maybe_inject_arena_auth_cookie_from_localstorage(page, context)
                    except Exception:
                        pass
                try:
                    derived_cookie = maybe_build_arena_auth_cookie_from_signup_response_body(body_text)
                except Exception:
                    derived_cookie = None
                if derived_cookie:
                    try:
                        if not is_arena_auth_token_expired(derived_cookie, skew_seconds=0):
                            await context.add_cookies(
                                _arena_auth_cookie_specs(
                                    derived_cookie,
                                    page_url=str(getattr(page, "url", "") or ""),
                                )
                            )
                            _capture_ephemeral_arena_auth_token_from_cookies(
                                [{"name": "arena-auth-prod-v1", "value": derived_cookie}]
                            )
                            debug_print("🦊 Camoufox proxy: injected arena-auth cookie from sign-up response body.")
                    except Exception:
                        pass

                # Wait for the cookie to appear
                try:
                    wait_loops = 10
                    try:
                        if status == 400 and "User already exists" in str(body_text or ""):
                            # Existing provisional user IDs can lead to 400s from sign-up without immediately
                            # surfacing the auth cookie. Reload and poll longer to give the app time to restore
                            # the session cookie.
                            wait_loops = 40
                            try:
                                await page.goto(
                                    "https://lmarena.ai/?mode=direct",
                                    wait_until="domcontentloaded",
                                    timeout=120000,
                                )
                            except Exception:
                                pass
                    except Exception:
                        pass

                    for _ in range(int(wait_loops)):
                        cur = await _get_auth_cookie_value()
                        if cur and not is_arena_auth_token_expired(cur, skew_seconds=0):
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
            job = _USERSCRIPT_PROXY_JOBS.get(job_id)
            if not isinstance(job, dict):
                continue
            
            # Signal that a proxy worker picked up this job (used to avoid long hangs when no worker is running).
            try:
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
                if not job.get("picked_up_at_monotonic"):
                    job["picked_up_at_monotonic"] = time.monotonic()
                if str(job.get("phase") or "") == "queued":
                    job["phase"] = "picked_up"
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

                  let upstreamFetchMarked = false;
                  const doFetch = async (body, token) => {
                    if (!upstreamFetchMarked) {
                      upstreamFetchMarked = true;
                      emit({ upstream_fetch_started: true });
                    }
                    return fetch(payload.url, {
                      method: payload.method || 'POST',
                      body,
                      headers: {
                        ...(payload.headers || { 'Content-Type': 'text/plain;charset=UTF-8' }),
                        ...(token ? { 'X-Recaptcha-Token': token, ...(action ? { 'X-Recaptcha-Action': action } : {}) } : {}),
                      },
                      credentials: 'include',
                      signal: controller.signal,
                    });
                  };

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
                            if is_arena_auth_token_expired(browser_auth_cookie, skew_seconds=60):
                                use_job_token = True
                        except Exception:
                            use_job_token = True
                
                if use_job_token:
                    await context.add_cookies(
                        _arena_auth_cookie_specs(
                            auth_token,
                            page_url=str(getattr(page, "url", "") or ""),
                        )
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
                    expired = is_arena_auth_token_expired(current_cookie, skew_seconds=0)
                except Exception:
                    expired = False
                debug_print(f"🦊 Camoufox proxy: arena-auth cookie present (len={len(current_cookie)} expired={expired})")
            else:
                debug_print("🦊 Camoufox proxy: arena-auth cookie missing")
            try:
                needs_signup = (not current_cookie) or is_arena_auth_token_expired(current_cookie, skew_seconds=0)
            except Exception:
                needs_signup = not bool(current_cookie)
            # Unit tests stub out the browser; avoid slow/interactive signup flows there.
            if needs_signup and not os.environ.get("PYTEST_CURRENT_TEST"):
                try:
                    job["phase"] = "signup"
                except Exception:
                    pass
                await _attempt_anonymous_signup(min_interval_seconds=20.0)
             
            try:
                try:
                    job["phase"] = "fetch"
                    if not job.get("upstream_started_at_monotonic"):
                        job["upstream_started_at_monotonic"] = time.monotonic()
                except Exception:
                    pass
                await asyncio.wait_for(
                    page.evaluate(
                        fetch_script,
                        {
                            "jid": job_id,
                            "payload": job.get("payload") or {},
                            "sitekey": proxy_recaptcha_sitekey,
                            "action": proxy_recaptcha_action,
                            "sitekeyV2": RECAPTCHA_V2_SITEKEY,
                            "grecaptchaTimeoutMs": 60000,
                            "grecaptchaPollMs": 250,
                            "timeoutMs": 180000,
                            "debug": bool(os.environ.get("LM_BRIDGE_PROXY_DEBUG")),
                        }
                    ),
                    timeout=200.0
                )
            except asyncio.TimeoutError:
                await push_proxy_chunk(job_id, {"error": "camoufox proxy evaluate timeout", "done": True})
            except Exception as e:
                await push_proxy_chunk(job_id, {"error": str(e), "done": True})

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

# --- OpenAI Compatible API Endpoints ---

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        models = get_models()
        config = get_config()
        
        # Basic health checks
        has_cf_clearance = bool(config.get("cf_clearance"))
        has_models = len(models) > 0
        has_api_keys = len(config.get("api_keys", [])) > 0
        
        status = "healthy" if (has_cf_clearance and has_models) else "degraded"
        
        return {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "cf_clearance": has_cf_clearance,
                "models_loaded": has_models,
                "model_count": len(models),
                "api_keys_configured": has_api_keys
            }
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }

@app.get("/api/v1/models")
async def list_models(api_key: dict = Depends(rate_limit_api_key)):
    try:
        models = get_models()
        
        # Filter for models with text OR search OR image output capability and an organization (exclude stealth models)
        # Always include image models - no special key needed
        valid_models = [m for m in models 
                       if (m.get('capabilities', {}).get('outputCapabilities', {}).get('text')
                           or m.get('capabilities', {}).get('outputCapabilities', {}).get('search')
                           or m.get('capabilities', {}).get('outputCapabilities', {}).get('image'))
                       and m.get('organization')]
        
        return {
            "object": "list",
            "data": [
                {
                    "id": model.get("publicName"),
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": model.get("organization", "lmarena")
                } for model in valid_models if model.get("publicName")
            ]
        }
    except Exception as e:
        debug_print(f"❌ Error listing models: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load models: {str(e)}")


@app.get("/api/v1/_debug/stream")
async def debug_stream(api_key: dict = Depends(rate_limit_api_key)):  # noqa: ARG001
    async def _gen():
        yield ": keep-alive\n\n"
        await asyncio.sleep(0.05)
        yield 'data: {"ok":true}\n\n'
        yield "data: [DONE]\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream")

@app.post("/api/v1/chat/completions")
async def api_chat_completions(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    debug_print("\n" + "="*80)
    debug_print("🔵 NEW API REQUEST RECEIVED")
    debug_print("="*80)
    
    try:
        # Parse request body with error handling
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            debug_print(f"❌ Invalid JSON in request body: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid JSON in request body: {str(e)}")
        except Exception as e:
            debug_print(f"❌ Failed to read request body: {e}")
            raise HTTPException(status_code=400, detail=f"Failed to read request body: {str(e)}")
        
        debug_print(f"📥 Request body keys: {list(body.keys())}")
        
        # Validate required fields
        model_public_name = body.get("model")
        messages = body.get("messages", [])
        stream = body.get("stream", False)
        
        debug_print(f"🌊 Stream mode: {stream}")
        debug_print(f"🤖 Requested model: {model_public_name}")
        debug_print(f"💬 Number of messages: {len(messages)}")
        
        if not model_public_name:
            debug_print("❌ Missing 'model' in request")
            raise HTTPException(status_code=400, detail="Missing 'model' in request body.")
        
        if not messages:
            debug_print("❌ Missing 'messages' in request")
            raise HTTPException(status_code=400, detail="Missing 'messages' in request body.")
        
        if not isinstance(messages, list):
            debug_print("❌ 'messages' must be an array")
            raise HTTPException(status_code=400, detail="'messages' must be an array.")
        
        if len(messages) == 0:
            debug_print("❌ 'messages' array is empty")
            raise HTTPException(status_code=400, detail="'messages' array cannot be empty.")

        # Find model ID from public name
        try:
            models = get_models()
            debug_print(f"📚 Total models loaded: {len(models)}")
        except Exception as e:
            debug_print(f"❌ Failed to load models: {e}")
            raise HTTPException(
                status_code=503,
                detail="Failed to load model list from LMArena. Please try again later."
            )
        
        model_id = None
        model_org = None
        model_capabilities = {}
        
        for m in models:
            if m.get("publicName") == model_public_name:
                model_id = m.get("id")
                model_org = m.get("organization")
                model_capabilities = m.get("capabilities", {})
                break
        
        if not model_id:
            debug_print(f"❌ Model '{model_public_name}' not found in model list")
            raise HTTPException(
                status_code=404, 
                detail=f"Model '{model_public_name}' not found. Use /api/v1/models to see available models."
            )
        
        # Check if model is a stealth model (no organization)
        if not model_org:
            debug_print(f"❌ Model '{model_public_name}' is a stealth model (no organization)")
            raise HTTPException(
                status_code=403,
                detail="You do not have access to stealth models. Contact cloudwaddie for more info."
            )
        
        debug_print(f"✅ Found model ID: {model_id}")
        debug_print(f"🔧 Model capabilities: {model_capabilities}")
        
        # Determine modality based on model capabilities.
        # Priority: image > search > chat
        if model_capabilities.get("outputCapabilities", {}).get("image"):
            modality = "image"
        elif model_capabilities.get("outputCapabilities", {}).get("search"):
            modality = "search"
        else:
            modality = "chat"
        debug_print(f"🔍 Model modality: {modality}")

        # Log usage
        try:
            model_usage_stats[model_public_name] += 1
            # Save stats immediately after incrementing
            config = get_config()
            config["usage_stats"] = dict(model_usage_stats)
            save_config(config)
        except Exception as e:
            # Don't fail the request if usage logging fails
            debug_print(f"⚠️  Failed to log usage stats: {e}")

        # Extract system prompt if present and prepend to first user message
        system_prompt = ""
        system_messages = [m for m in messages if m.get("role") == "system"]
        if system_messages:
            system_prompt = "\n\n".join([_coerce_message_content_to_text(m.get("content", "")) for m in system_messages])
            debug_print(f"📋 System prompt found: {system_prompt[:100]}..." if len(system_prompt) > 100 else f"📋 System prompt: {system_prompt}")
        
        # Process last message content (may include images)
        try:
            last_message_content = messages[-1].get("content", "")
            try:
                prompt, experimental_attachments = await process_message_content(last_message_content, model_capabilities)
            except Exception as e:
                debug_print(f"❌ Failed to process message content: {e}")
                raise HTTPException(status_code=400, detail=f"Invalid message content: {str(e)}")
            
            # If there's a system prompt and this is the first user message, prepend it
            if system_prompt:
                prompt = f"{system_prompt}\n\n{prompt}"
                debug_print(f"✅ System prompt prepended to user message")
        except Exception as e:
            debug_print(f"❌ Failed to process message content: {e}")
            raise HTTPException(
                status_code=400,
                detail=f"Failed to process message content: {str(e)}"
            )
        
        # Validate prompt
        if not prompt:
            # If no text but has attachments, that's okay for vision models
            if not experimental_attachments:
                debug_print("❌ Last message has no content")
                raise HTTPException(status_code=400, detail="Last message must have content.")
        
        # Log prompt length for debugging character limit issues
        debug_print(f"📝 User prompt length: {len(prompt)} characters")
        debug_print(f"🖼️  Attachments: {len(experimental_attachments)} images")
        debug_print(f"📝 User prompt preview: {prompt[:100]}..." if len(prompt) > 100 else f"📝 User prompt: {prompt}")
        
        # Check for reasonable character limit (LMArena appears to have limits)
        # Typical limit seems to be around 32K-64K characters based on testing
        MAX_PROMPT_LENGTH = 113567  # User hardcoded limit
        if len(prompt) > MAX_PROMPT_LENGTH:
            error_msg = f"Prompt too long ({len(prompt)} characters). LMArena has a character limit of approximately {MAX_PROMPT_LENGTH} characters. Please reduce the message size."
            debug_print(f"❌ {error_msg}")
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Use API key + conversation tracking
        api_key_str = api_key["key"]

        # --- NEW: Get reCAPTCHA v3 Token for Payload ---
        # For strict models, we defer token minting to the in-browser fetch transport to avoid extra
        # automation-driven token requests (which can lower scores and increase flakiness).
        use_chrome_fetch_for_model = model_public_name in STRICT_CHROME_FETCH_MODELS
        strict_chrome_fetch_model = use_chrome_fetch_for_model

        recaptcha_token = ""
        if strict_chrome_fetch_model:
            # If the internal proxy is active, we MUST NOT use a cached token, as it causes 403s.
            # Instead, we pass an empty string and let the in-page minting handle it.
            if (time.time() - last_userscript_poll) < 15:
                debug_print("🔐 Strict model + Proxy: token will be minted in-page.")
                recaptcha_token = ""
            else:
                # Best-effort: use a cached token so browser transports don't have to wait on grecaptcha to load.
                # (They can still mint in-session if needed.)
                recaptcha_token = get_cached_recaptcha_token()
                if recaptcha_token:
                    debug_print("🔐 Strict model: using cached reCAPTCHA v3 token in payload.")
                else:
                    debug_print("🔐 Strict model: reCAPTCHA token will be minted in the Chrome fetch session.")
        else:
            # reCAPTCHA v3 tokens can behave like single-use tokens; force a fresh token for streaming requests.
            # For streaming, we defer this until inside generate_stream to avoid blocking initial headers.
            if stream:
                recaptcha_token = ""
            else:
                recaptcha_token = await refresh_recaptcha_token(force_new=False)
                if not recaptcha_token:
                    debug_print("❌ Cannot proceed, failed to get reCAPTCHA token.")
                    raise HTTPException(
                        status_code=503,
                        detail="Service Unavailable: Failed to acquire reCAPTCHA token. The bridge server may be blocked."
                    )
                debug_print(f"🔑 Using reCAPTCHA v3 token: {recaptcha_token[:20]}...")
        # -----------------------------------------------
        
        # Generate conversation ID from context (API key + model + first user message)
        import hashlib
        first_user_message = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
        if isinstance(first_user_message, list):
            # Handle array content format
            first_user_message = str(first_user_message)
        conversation_key = f"{api_key_str}_{model_public_name}_{first_user_message[:100]}"
        conversation_id = hashlib.sha256(conversation_key.encode()).hexdigest()[:16]
        
        debug_print(f"🔑 API Key: {api_key_str[:20]}...")
        debug_print(f"💭 Auto-generated Conversation ID: {conversation_id}")
        debug_print(f"🔑 Conversation key: {conversation_key[:100]}...")

        # Headers are prepared after selecting an auth token (or when falling back to browser-only transports).
        headers: dict[str, str] = {}
        
        # Check if conversation exists for this API key (robust to tests patching chat_sessions to a plain dict)
        per_key_sessions = chat_sessions.setdefault(api_key_str, {})
        session = per_key_sessions.get(conversation_id)
        
        # Detect retry: if session exists and last message is same user message (no assistant response after it)
        is_retry = False
        retry_message_id = None
        
        if session and len(session.get("messages", [])) >= 2:
            stored_messages = session["messages"]
            # Check if last stored message is from user with same content
            if stored_messages[-1]["role"] == "user" and stored_messages[-1]["content"] == prompt:
                # This is a retry - client sent same message again without assistant response
                is_retry = True
                retry_message_id = stored_messages[-1]["id"]
                # Get the assistant message ID that needs to be regenerated
                if len(stored_messages) >= 2 and stored_messages[-2]["role"] == "assistant":
                    # There was a previous assistant response - we'll retry that one
                    retry_message_id = stored_messages[-2]["id"]
                    debug_print(f"🔁 RETRY DETECTED - Regenerating assistant message {retry_message_id}")
        
        if is_retry and retry_message_id:
            debug_print(f"🔁 Using RETRY endpoint")
            # Use LMArena's retry endpoint
            # Format: PUT /nextjs-api/stream/retry-evaluation-session-message/{sessionId}/messages/{messageId}
            payload = {}
            url = f"https://lmarena.ai/nextjs-api/stream/retry-evaluation-session-message/{session['conversation_id']}/messages/{retry_message_id}"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Using PUT method for retry")
            http_method = "PUT"
        elif not session:
            debug_print("🆕 Creating NEW conversation session")
            # New conversation - Generate all IDs at once (like the browser does)
            session_id = str(uuid7())
            user_msg_id = str(uuid7())
            model_msg_id = str(uuid7())
            model_b_msg_id = str(uuid7())
            
            debug_print(f"🔑 Generated session_id: {session_id}")
            debug_print(f"👤 Generated user_msg_id: {user_msg_id}")
            debug_print(f"🤖 Generated model_msg_id: {model_msg_id}")
            debug_print(f"🤖 Generated model_b_msg_id: {model_b_msg_id}")
             
            payload = {
                "id": session_id,
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "modelBMessageId": model_b_msg_id,
                "userMessage": {
                    "content": prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = "https://lmarena.ai/nextjs-api/stream/create-evaluation"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Payload structure: Simple userMessage format")
            debug_print(f"🔍 Full payload: {json.dumps(payload, indent=2)}")
            http_method = "POST"
        else:
            debug_print("🔄 Using EXISTING conversation session")
            # Follow-up message - Generate new message IDs
            user_msg_id = str(uuid7())
            debug_print(f"👤 Generated followup user_msg_id: {user_msg_id}")
            model_msg_id = str(uuid7())
            debug_print(f"🤖 Generated followup model_msg_id: {model_msg_id}")
            model_b_msg_id = str(uuid7())
            debug_print(f"🤖 Generated followup model_b_msg_id: {model_b_msg_id}")
             
            payload = {
                "id": session["conversation_id"],
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "modelBMessageId": model_b_msg_id,
                "userMessage": {
                    "content": prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = f"https://lmarena.ai/nextjs-api/stream/post-to-evaluation/{session['conversation_id']}"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Payload structure: Simple userMessage format")
            debug_print(f"🔍 Full payload: {json.dumps(payload, indent=2)}")
            http_method = "POST"

        debug_print(f"\n🚀 Making API request to LMArena...")
        debug_print(f"⏱️  Timeout set to: 120 seconds")
        
        # Initialize failed tokens tracking for this request
        request_id = str(uuid.uuid4())
        failed_tokens = set()
        force_browser_transports_in_stream = False
        
        # Get initial auth token using round-robin (excluding any failed ones)
        current_token = ""
        try:
            current_token = get_next_auth_token(exclude_tokens=failed_tokens)
        except HTTPException:
            # Stream mode: when no auth token is configured, fall back to browser-backed transports
            # (Userscript proxy / Chrome/Camoufox fetch). This matches strict-model behavior and avoids a hard 500.
            if stream:
                debug_print("⚠️ No auth token configured for streaming; enabling browser/proxy transports.")
                current_token = ""
                force_browser_transports_in_stream = True
            # Non-streaming strict models can still proceed via browser fetch transports, which may have a valid
            # arena-auth cookie already stored in the persistent profile.
            elif strict_chrome_fetch_model:
                debug_print("⚠️ No auth token configured; proceeding with browser-only transports.")
                current_token = ""
            else:
                raise

        # Strict models: if round-robin picked a placeholder/invalid-looking token but there is a better token
        # available, switch to the first plausible token without mutating user config.
        if strict_chrome_fetch_model and current_token and not is_probably_valid_arena_auth_token(current_token):
            try:
                cfg_now = get_config()
                tokens_now = cfg_now.get("auth_tokens", [])
                if not isinstance(tokens_now, list):
                    tokens_now = []
            except Exception:
                tokens_now = []
            better = ""
            for cand in tokens_now:
                cand = str(cand or "").strip()
                if not cand or cand == current_token or cand in failed_tokens:
                    continue
                if is_probably_valid_arena_auth_token(cand):
                    better = cand
                    break
            if better:
                debug_print("🔑 Switching to a plausible auth token for strict model streaming.")
                current_token = better
            else:
                debug_print("⚠️ Selected auth token format looks unusual; continuing with it (no better token found).")

        # If we still don't have a usable token (e.g. only expired base64 sessions remain), try to refresh one
        # in-memory only (do not rewrite the user's config.json auth tokens).
        if (not current_token) or (not is_probably_valid_arena_auth_token(current_token)):
            try:
                refreshed = await maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
            except Exception:
                refreshed = None
            if refreshed:
                debug_print("🔄 Refreshed arena-auth-prod-v1 session.")
                current_token = refreshed
        headers = get_request_headers_with_token(current_token, recaptcha_token)
        if current_token:
            debug_print(f"🔑 Using token (round-robin): {current_token[:20]}...")
        else:
            debug_print("🔑 No auth token configured (will rely on browser session cookies).")
        
        # Retry logic wrapper
        async def make_request_with_retry(url, payload, http_method, max_retries=3):
            """Make request with automatic retry on 429/401 errors"""
            nonlocal current_token, headers, failed_tokens, recaptcha_token
            
            for attempt in range(max_retries):
                try:
                    async with httpx.AsyncClient() as client:
                        if http_method == "PUT":
                            response = await client.put(url, json=payload, headers=headers, timeout=120)
                        else:
                            response = await client.post(url, json=payload, headers=headers, timeout=120)
                        
                        # Log status with human-readable message
                        log_http_status(response.status_code, "LMArena API")
                        
                        # Check for retry-able errors
                        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                            debug_print(f"⏱️  Attempt {attempt + 1}/{max_retries} - Rate limit with token {current_token[:20]}...")
                            retry_after = response.headers.get("Retry-After")
                            sleep_seconds = get_rate_limit_sleep_seconds(retry_after, attempt)
                            debug_print(f"  Retry-After header: {retry_after!r}")
                            
                            if attempt < max_retries - 1:
                                try:
                                    # Try with next token (excluding failed ones)
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    headers = get_request_headers_with_token(current_token, recaptcha_token)
                                    debug_print(f"🔄 Retrying with next token: {current_token[:20]}...")
                                    await asyncio.sleep(sleep_seconds)
                                    continue
                                except HTTPException as e:
                                    debug_print(f"❌ No more tokens available: {e.detail}")
                                    break
                        
                        elif response.status_code == HTTPStatus.FORBIDDEN:
                            try:
                                error_body = response.json()
                            except Exception:
                                error_body = None
                            if isinstance(error_body, dict) and error_body.get("error") == "recaptcha validation failed":
                                debug_print(
                                    f"🤖 Attempt {attempt + 1}/{max_retries} - reCAPTCHA validation failed. Refreshing token..."
                                )
                                new_token = await refresh_recaptcha_token(force_new=True)
                                if new_token and isinstance(payload, dict):
                                    payload["recaptchaV3Token"] = new_token
                                    recaptcha_token = new_token
                                if attempt < max_retries - 1:
                                    headers = get_request_headers_with_token(current_token, recaptcha_token)
                                    await asyncio.sleep(1)
                                    continue

                        elif response.status_code == HTTPStatus.UNAUTHORIZED:
                            debug_print(f"🔒 Attempt {attempt + 1}/{max_retries} - Auth failed with token {current_token[:20]}...")
                            # Add current token to failed set
                            failed_tokens.add(current_token)
                            # (Pruning disabled)
                            debug_print(f"📝 Failed tokens so far: {len(failed_tokens)}")
                            
                            if attempt < max_retries - 1:
                                try:
                                    # Try with next available token (excluding failed ones)
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    headers = get_request_headers_with_token(current_token, recaptcha_token)
                                    debug_print(f"🔄 Retrying with next token: {current_token[:20]}...")
                                    await asyncio.sleep(1)  # Brief delay
                                    continue
                                except HTTPException as e:
                                    debug_print(f"❌ No more tokens available: {e.detail}")
                                    break
                        
                        # If we get here, return the response (success or non-retryable error)
                        response.raise_for_status()
                        return response
                        
                except httpx.HTTPStatusError as e:
                    # Only handle 429 and 401, let other errors through
                    if e.response.status_code not in [429, 401]:
                        raise
                    # If last attempt, raise the error
                    if attempt == max_retries - 1:
                        raise
            
            # Should not reach here, but just in case
            raise HTTPException(status_code=503, detail="Max retries exceeded")
        
        # Handle streaming mode
        if stream:
            async def generate_stream():
                nonlocal current_token, headers, failed_tokens, recaptcha_token
                
                # Safety: don't keep client sockets open forever on repeated upstream failures.
                try:
                    stream_total_timeout_seconds = float(get_config().get("stream_total_timeout_seconds", 600))
                except Exception:
                    stream_total_timeout_seconds = 600.0
                stream_total_timeout_seconds = max(30.0, min(stream_total_timeout_seconds, 3600.0))
                stream_started_at = time.monotonic()

                # Flush an immediate comment to keep the client connection alive while we do heavy lifting upstream
                yield ": keep-alive\n\n"
                await asyncio.sleep(0)
                
                async def wait_for_task(task):
                    while True:
                        done, _ = await asyncio.wait({task}, timeout=1.0)
                        if task in done:
                            break
                        yield ": keep-alive\n\n"

                chunk_id = f"chatcmpl-{uuid.uuid4()}"
                
                # Helper to keep connection alive during backoff
                async def wait_with_keepalive(seconds: float):
                    end_time = time.time() + float(seconds)
                    while time.time() < end_time:
                        yield ": keep-alive\n\n"
                        await asyncio.sleep(min(1.0, end_time - time.time()))

                # Use browser transports (Userscript proxy / Chrome/Camoufox) proactively for:
                #   - models known to be strict with reCAPTCHA
                #   - any streaming request when no auth token is available (browser session may be able to sign up / reuse cookies)
                disable_userscript_proxy_env = bool(os.environ.get("LM_BRIDGE_DISABLE_USERSCRIPT_PROXY"))
                proxy_active_at_start = False
                if not disable_userscript_proxy_env:
                    try:
                        proxy_active_at_start = _userscript_proxy_is_active()
                    except Exception:
                        proxy_active_at_start = False

                # If the userscript proxy is active (internal Camoufox worker / extension poller), route streaming
                # through it immediately to avoid side-channel reCAPTCHA token minting (which can launch headful Chrome).
                use_browser_transports = (
                    force_browser_transports_in_stream
                    or (model_public_name in STRICT_CHROME_FETCH_MODELS)
                    or proxy_active_at_start
                )
                prefer_chrome_transport = True
                if use_browser_transports and (model_public_name in STRICT_CHROME_FETCH_MODELS):
                    debug_print(f"🔐 Strict model detected ({model_public_name}), enabling browser fetch transport.")
                elif use_browser_transports and force_browser_transports_in_stream:
                    debug_print("⚠️ Stream mode without auth token: preferring userscript proxy / browser fetch transports.")
                elif use_browser_transports and proxy_active_at_start:
                    debug_print("🦊 Userscript proxy is ACTIVE: routing stream through proxy and skipping side-channel reCAPTCHA mint.")

                # Non-strict models: mint a fresh side-channel token before the first upstream attempt so we don't
                # send an empty `recaptchaV3Token` (which commonly yields 403 "recaptcha validation failed").
                if (not use_browser_transports) and (not str(recaptcha_token or "").strip()):
                    try:
                        refresh_task = asyncio.create_task(refresh_recaptcha_token(force_new=True))
                        async for ka in wait_for_task(refresh_task):
                            yield ka
                        new_token = refresh_task.result()
                    except Exception:
                        new_token = None
                    if new_token:
                        recaptcha_token = new_token
                        if isinstance(payload, dict):
                            payload["recaptchaV3Token"] = new_token
                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                
                recaptcha_403_failures = 0
                no_delta_failures = 0
                attempt = 0
                recaptcha_403_consecutive = 0
                recaptcha_403_last_transport: Optional[str] = None
                strict_token_prefill_attempted = False
                disable_userscript_for_request = False
                force_proxy_recaptcha_mint = False

                retry_429_count = 0
                retry_403_count = 0

                max_retries = 3
                current_retry_attempt = 0
                
                # Infinite retry loop (until client disconnects, max attempts reached, or we get success)
                while True:
                    attempt += 1

                    # Abort if the client disconnects.
                    try:
                        if await request.is_disconnected():
                            return
                    except Exception:
                        pass

                    # Stop retrying after a configurable deadline or too many attempts to avoid infinite hangs.
                    if (time.monotonic() - stream_started_at) > stream_total_timeout_seconds or attempt > 20:
                        error_chunk = {
                            "error": {
                                "message": "Upstream retry timeout or max attempts exceeded while streaming from LMArena.",
                                "type": "upstream_timeout",
                                "code": HTTPStatus.GATEWAY_TIMEOUT,
                            }
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                    # Reset response data for each attempt
                    response_text = ""
                    reasoning_text = ""
                    citations = []
                    unhandled_preview: list[str] = []

                    try:
                        async with AsyncExitStack() as stack:
                            debug_print(f"📡 Sending {http_method} request for streaming (attempt {attempt})...")
                            stream_context = None
                            transport_used = "httpx"
                            
                            # Prefer the userscript proxy only when it is actually polling (or when a poller connects
                            # shortly after the request starts). This avoids hanging strict-model requests when no
                            # proxy is running, while still supporting "late" pollers (tests/reconnects).
                            use_userscript = False
                            cfg_now = None
                            if (
                                use_browser_transports
                                and not disable_userscript_for_request
                                and not disable_userscript_proxy_env
                            ):
                                try:
                                    cfg_now = get_config()
                                except Exception:
                                    cfg_now = None

                                try:
                                    proxy_active = _userscript_proxy_is_active(cfg_now)
                                except Exception:
                                    proxy_active = False

                                if not proxy_active:
                                    try:
                                        grace_seconds = float((cfg_now or {}).get("userscript_proxy_grace_seconds", 0.5))
                                    except Exception:
                                        grace_seconds = 0.5
                                    grace_seconds = max(0.0, min(grace_seconds, 2.0))
                                    if grace_seconds > 0:
                                        deadline = time.time() + grace_seconds
                                        while time.time() < deadline:
                                            try:
                                                if _userscript_proxy_is_active(cfg_now):
                                                    proxy_active = True
                                                    break
                                            except Exception:
                                                pass
                                            yield ": keep-alive\n\n"
                                            await asyncio.sleep(0.05)

                                if proxy_active:
                                    use_userscript = True
                                    debug_print("🌐 Userscript Proxy is ACTIVE. Preferring Proxy over direct/Chrome fetch.")
                                # Default behavior: mint in-page (higher success rate than side-channel cached tokens).
                                # Optional: allow pre-filling a cached token for speed via config flag.
                                try:
                                    prefill_cached = bool((cfg_now or {}).get("userscript_proxy_prefill_cached_recaptcha", False))
                                except Exception:
                                    prefill_cached = False
                                if (
                                    prefill_cached
                                    and isinstance(payload, dict)
                                    and not force_proxy_recaptcha_mint
                                    and not str(payload.get("recaptchaV3Token") or "").strip()
                                ):
                                    try:
                                        cached = get_cached_recaptcha_token()
                                    except Exception:
                                        cached = ""
                                    if cached:
                                        debug_print(f"🔐 Using cached reCAPTCHA v3 token for proxy (len={len(str(cached))})")
                                        payload["recaptchaV3Token"] = cached

                            if use_userscript:
                                debug_print(
                                    f"📫 Delegating request to Userscript Proxy (poll active {int(time.time() - last_userscript_poll)}s ago)..."
                                )
                                proxy_auth_token = str(current_token or "").strip()
                                try:
                                    # Preserve expired base64 Supabase session cookies: they can often be refreshed
                                    # in-page via their embedded refresh_token (no user interaction).
                                    if (
                                        proxy_auth_token
                                        and not str(proxy_auth_token).startswith("base64-")
                                        and is_arena_auth_token_expired(proxy_auth_token, skew_seconds=0)
                                    ):
                                        proxy_auth_token = ""
                                except Exception:
                                    pass
                                stream_context = await fetch_via_proxy_queue(
                                    url=url,
                                    payload=payload if isinstance(payload, dict) else {},
                                    http_method=http_method,
                                    timeout_seconds=120,
                                    streaming=True,
                                    auth_token=proxy_auth_token,
                                )
                                if stream_context is None:
                                    debug_print("⚠️ Userscript Proxy returned None (timeout?). Falling back...")
                                    use_userscript = False
                                else:
                                    transport_used = "userscript"

                            # Strict models: when we're about to fall back to buffered browser fetch transports (not the
                            # streaming proxy), a side-channel token can avoid hangs while grecaptcha loads in-page.
                            if (
                                stream_context is None
                                and use_browser_transports
                                and not use_userscript
                                and isinstance(payload, dict)
                                and not strict_token_prefill_attempted
                                and not str(payload.get("recaptchaV3Token") or "").strip()
                            ):
                                strict_token_prefill_attempted = True
                                try:
                                    refresh_task = asyncio.create_task(refresh_recaptcha_token(force_new=True))
                                except Exception:
                                    refresh_task = None
                                if refresh_task is not None:
                                    while True:
                                        done, _ = await asyncio.wait({refresh_task}, timeout=1.0)
                                        if refresh_task in done:
                                            break
                                        yield ": keep-alive\n\n"
                                    try:
                                        new_token = refresh_task.result()
                                    except Exception:
                                        new_token = None
                                    if new_token:
                                        payload["recaptchaV3Token"] = new_token

                            if stream_context is None and use_browser_transports:
                                browser_fetch_attempts = 5
                                try:
                                    browser_fetch_attempts = int(get_config().get("chrome_fetch_recaptcha_max_attempts", 5))
                                except Exception:
                                    browser_fetch_attempts = 5

                                # If we have a cached side-channel reCAPTCHA token, prefer passing it into the browser
                                # fetch transports (they will reuse it on the first attempt and only mint in-page if
                                # needed). This helps when in-page grecaptcha is slow/flaky.
                                if isinstance(payload, dict) and not str(payload.get("recaptchaV3Token") or "").strip():
                                    try:
                                        cached_token = get_cached_recaptcha_token()
                                    except Exception:
                                        cached_token = ""
                                    if cached_token:
                                        payload["recaptchaV3Token"] = cached_token

                                async def _try_chrome_fetch() -> Optional[BrowserFetchStreamResponse]:
                                    debug_print("🌐 Using Chrome fetch transport for streaming...")
                                    try:
                                        auth_for_browser = str(current_token or "").strip()
                                        try:
                                            cand = str(EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
                                        except Exception:
                                            cand = ""
                                        if cand:
                                            try:
                                                if (
                                                    is_probably_valid_arena_auth_token(cand)
                                                    and not is_arena_auth_token_expired(cand, skew_seconds=0)
                                                    and (
                                                        (not auth_for_browser)
                                                        or (not is_probably_valid_arena_auth_token(auth_for_browser))
                                                        or is_arena_auth_token_expired(auth_for_browser, skew_seconds=0)
                                                    )
                                                ):
                                                    auth_for_browser = cand
                                            except Exception:
                                                auth_for_browser = cand

                                        try:
                                            chrome_outer_timeout = float(get_config().get("chrome_fetch_outer_timeout_seconds", 120))
                                        except Exception:
                                            chrome_outer_timeout = 120.0
                                        chrome_outer_timeout = max(20.0, min(chrome_outer_timeout, 300.0))

                                        return await asyncio.wait_for(
                                            fetch_lmarena_stream_via_chrome(
                                                http_method=http_method,
                                                url=url,
                                                payload=payload if isinstance(payload, dict) else {},
                                                auth_token=auth_for_browser,
                                                timeout_seconds=120,
                                                max_recaptcha_attempts=browser_fetch_attempts,
                                            ),
                                            timeout=chrome_outer_timeout,
                                        )
                                    except asyncio.TimeoutError:
                                        debug_print("⚠️ Chrome fetch transport timed out (launch/nav hang).")
                                        return None
                                    except Exception as e:
                                        debug_print(f"⚠️ Chrome fetch transport error: {e}")
                                        return None

                                async def _try_camoufox_fetch() -> Optional[BrowserFetchStreamResponse]:
                                    debug_print("🦊 Using Camoufox fetch transport for streaming...")
                                    try:
                                        auth_for_browser = str(current_token or "").strip()
                                        try:
                                            cand = str(EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
                                        except Exception:
                                            cand = ""
                                        if cand:
                                            try:
                                                if (
                                                    is_probably_valid_arena_auth_token(cand)
                                                    and not is_arena_auth_token_expired(cand, skew_seconds=0)
                                                    and (
                                                        (not auth_for_browser)
                                                        or (not is_probably_valid_arena_auth_token(auth_for_browser))
                                                        or is_arena_auth_token_expired(auth_for_browser, skew_seconds=0)
                                                    )
                                                ):
                                                    auth_for_browser = cand
                                            except Exception:
                                                auth_for_browser = cand

                                        try:
                                            camoufox_outer_timeout = float(
                                                get_config().get("camoufox_fetch_outer_timeout_seconds", 180)
                                            )
                                        except Exception:
                                            camoufox_outer_timeout = 180.0
                                        camoufox_outer_timeout = max(20.0, min(camoufox_outer_timeout, 300.0))

                                        return await asyncio.wait_for(
                                            fetch_lmarena_stream_via_camoufox(
                                                http_method=http_method,
                                                url=url,
                                                payload=payload if isinstance(payload, dict) else {},
                                                auth_token=auth_for_browser,
                                                timeout_seconds=120,
                                                max_recaptcha_attempts=browser_fetch_attempts,
                                            ),
                                            timeout=camoufox_outer_timeout,
                                        )
                                    except asyncio.TimeoutError:
                                        debug_print("⚠️ Camoufox fetch transport timed out (launch/nav hang).")
                                        return None
                                    except Exception as e:
                                        debug_print(f"⚠️ Camoufox fetch transport error: {e}")
                                        return None

                                if prefer_chrome_transport:
                                    chrome_task = asyncio.create_task(_try_chrome_fetch())
                                    while True:
                                        done, _ = await asyncio.wait({chrome_task}, timeout=1.0)
                                        if chrome_task in done:
                                            try:
                                                stream_context = chrome_task.result()
                                            except Exception:
                                                stream_context = None
                                            break
                                        yield ": keep-alive\n\n"
                                    if stream_context is not None:
                                        transport_used = "chrome"
                                    if stream_context is None:
                                        camoufox_task = asyncio.create_task(_try_camoufox_fetch())
                                        while True:
                                            done, _ = await asyncio.wait({camoufox_task}, timeout=1.0)
                                            if camoufox_task in done:
                                                try:
                                                    stream_context = camoufox_task.result()
                                                except Exception:
                                                    stream_context = None
                                                break
                                            yield ": keep-alive\n\n"
                                        if stream_context is not None:
                                            transport_used = "camoufox"
                                else:
                                    camoufox_task = asyncio.create_task(_try_camoufox_fetch())
                                    while True:
                                        done, _ = await asyncio.wait({camoufox_task}, timeout=1.0)
                                        if camoufox_task in done:
                                            try:
                                                stream_context = camoufox_task.result()
                                            except Exception:
                                                stream_context = None
                                            break
                                        yield ": keep-alive\n\n"
                                    if stream_context is not None:
                                        transport_used = "camoufox"
                                    if stream_context is None:
                                        chrome_task = asyncio.create_task(_try_chrome_fetch())
                                        while True:
                                            done, _ = await asyncio.wait({chrome_task}, timeout=1.0)
                                            if chrome_task in done:
                                                try:
                                                    stream_context = chrome_task.result()
                                                except Exception:
                                                    stream_context = None
                                                break
                                            yield ": keep-alive\n\n"
                                        if stream_context is not None:
                                            transport_used = "chrome"

                            if stream_context is None:
                                client = await stack.enter_async_context(httpx.AsyncClient())
                                if http_method == "PUT":
                                    stream_context = client.stream('PUT', url, json=payload, headers=headers, timeout=120)
                                else:
                                    stream_context = client.stream('POST', url, json=payload, headers=headers, timeout=120)
                                transport_used = "httpx"

                            # Userscript proxy jobs report their upstream HTTP status asynchronously.
                            # Wait for the status (or completion) before branching on status_code, while still
                            # keeping the client connection alive.
                            if transport_used == "userscript":
                                proxy_job_id = ""
                                try:
                                    proxy_job_id = str(getattr(stream_context, "job_id", "") or "").strip()
                                except Exception:
                                    proxy_job_id = ""

                                proxy_job = _USERSCRIPT_PROXY_JOBS.get(proxy_job_id) if proxy_job_id else None
                                status_event = None
                                done_event = None
                                picked_up_event = None
                                lines_queue = None
                                if isinstance(proxy_job, dict):
                                    status_event = proxy_job.get("status_event")
                                    done_event = proxy_job.get("done_event")
                                    picked_up_event = proxy_job.get("picked_up_event")
                                    lines_queue = proxy_job.get("lines_queue")
 
                                if isinstance(status_event, asyncio.Event) and not status_event.is_set():
                                    try:
                                        pickup_timeout_seconds = float(
                                            get_config().get("userscript_proxy_pickup_timeout_seconds", 10)
                                        )
                                    except Exception:
                                        pickup_timeout_seconds = 10.0
                                    pickup_timeout_seconds = max(0.5, min(pickup_timeout_seconds, 15.0))

                                    try:
                                        proxy_status_timeout_seconds = float(
                                            get_config().get("userscript_proxy_status_timeout_seconds", 30)
                                        )
                                    except Exception:
                                        proxy_status_timeout_seconds = 30.0
                                    proxy_status_timeout_seconds = max(5.0, min(proxy_status_timeout_seconds, 300.0))

                                    # Time between pickup and the proxy actually starting the upstream fetch. When the
                                    # Camoufox proxy needs to perform anonymous signup / Turnstile preflight, this can
                                    # legitimately take much longer than the upstream-status timeout.
                                    try:
                                        proxy_preflight_timeout_seconds = float(
                                            get_config().get(
                                                "userscript_proxy_preflight_timeout_seconds",
                                                proxy_status_timeout_seconds,
                                            )
                                        )
                                    except Exception:
                                        proxy_preflight_timeout_seconds = proxy_status_timeout_seconds
                                    proxy_preflight_timeout_seconds = max(
                                        5.0, min(proxy_preflight_timeout_seconds, 600.0)
                                    )

                                    try:
                                        proxy_signup_preflight_timeout_seconds = float(
                                            get_config().get(
                                                "userscript_proxy_signup_preflight_timeout_seconds",
                                                240,
                                            )
                                        )
                                    except Exception:
                                        proxy_signup_preflight_timeout_seconds = 240.0
                                    proxy_signup_preflight_timeout_seconds = max(
                                        proxy_preflight_timeout_seconds,
                                        min(proxy_signup_preflight_timeout_seconds, 900.0),
                                    )
 
                                    started = time.monotonic()
                                    proxy_status_timed_out = False
                                    while True:
                                        if status_event.is_set():
                                            break
                                        if isinstance(done_event, asyncio.Event) and done_event.is_set():
                                            break
                                        # If the proxy is already streaming lines, don't stall waiting for a separate
                                        # status report.
                                        if isinstance(lines_queue, asyncio.Queue) and not lines_queue.empty():
                                            break
                                        # If an error has already been recorded, stop waiting and let downstream handle it.
                                        try:
                                            if isinstance(proxy_job, dict) and proxy_job.get("error"):
                                                break
                                        except Exception:
                                            pass

                                        # Abort quickly if the client disconnected.
                                        try:
                                            if await request.is_disconnected():
                                                try:
                                                    await _finalize_userscript_proxy_job(
                                                        proxy_job_id, error="client disconnected", remove=True
                                                    )
                                                except Exception:
                                                    pass
                                                return
                                        except Exception:
                                            pass

                                        now_mono = time.monotonic()
                                        elapsed = now_mono - started
                                        picked_up = True
                                        if isinstance(picked_up_event, asyncio.Event):
                                            picked_up = bool(picked_up_event.is_set())

                                        if (not picked_up) and elapsed >= pickup_timeout_seconds:
                                            debug_print(
                                                f"⚠️ Userscript proxy did not pick up job within {int(pickup_timeout_seconds)}s."
                                            )
                                            disable_userscript_for_request = True
                                            try:
                                                _mark_userscript_proxy_inactive()
                                            except Exception:
                                                pass
                                            try:
                                                await _finalize_userscript_proxy_job(
                                                    proxy_job_id, error="userscript proxy pickup timeout", remove=True
                                                )
                                            except Exception:
                                                pass
                                            proxy_status_timed_out = True
                                            break

                                        if picked_up and isinstance(proxy_job, dict):
                                            pickup_at = proxy_job.get("picked_up_at_monotonic")
                                            try:
                                                pickup_at_mono = float(pickup_at)
                                            except Exception:
                                                pickup_at_mono = 0.0
                                            if pickup_at_mono <= 0:
                                                pickup_at_mono = float(now_mono)
                                                proxy_job["picked_up_at_monotonic"] = pickup_at_mono

                                            upstream_fetch_started_at = proxy_job.get(
                                                "upstream_fetch_started_at_monotonic"
                                            )
                                            try:
                                                upstream_fetch_started_at_mono = float(
                                                    upstream_fetch_started_at
                                                )
                                            except Exception:
                                                upstream_fetch_started_at_mono = 0.0

                                            if upstream_fetch_started_at_mono > 0:
                                                status_elapsed = now_mono - upstream_fetch_started_at_mono
                                                if status_elapsed < 0:
                                                    status_elapsed = 0.0
                                                if status_elapsed >= proxy_status_timeout_seconds:
                                                    debug_print(
                                                        f"⚠️ Userscript proxy did not report upstream status within {int(proxy_status_timeout_seconds)}s."
                                                    )
                                                    # Treat the proxy as unavailable for the rest of this request and fall back
                                                    # to other transports (Chrome/Camoufox/httpx). Otherwise we'd keep queuing
                                                    # jobs that will never be picked up and stall for a long time.
                                                    disable_userscript_for_request = True
                                                    try:
                                                        _mark_userscript_proxy_inactive()
                                                    except Exception:
                                                        pass
                                                    try:
                                                        await _finalize_userscript_proxy_job(
                                                            proxy_job_id,
                                                            error="userscript proxy status timeout",
                                                            remove=True,
                                                        )
                                                    except Exception:
                                                        pass
                                                    proxy_status_timed_out = True
                                                    break
                                            else:
                                                phase = str(proxy_job.get("phase") or "")
                                                preflight_timeout = proxy_preflight_timeout_seconds
                                                if phase == "signup":
                                                    preflight_timeout = proxy_signup_preflight_timeout_seconds
                                                preflight_started_at_mono = pickup_at_mono
                                                if phase == "fetch":
                                                    upstream_started_at = proxy_job.get(
                                                        "upstream_started_at_monotonic"
                                                    )
                                                    try:
                                                        upstream_started_at_mono = float(
                                                            upstream_started_at
                                                        )
                                                    except Exception:
                                                        upstream_started_at_mono = 0.0
                                                    if upstream_started_at_mono > 0:
                                                        preflight_started_at_mono = (
                                                            upstream_started_at_mono
                                                        )

                                                preflight_elapsed = now_mono - preflight_started_at_mono
                                                if preflight_elapsed < 0:
                                                    preflight_elapsed = 0.0
                                                if preflight_elapsed >= preflight_timeout:
                                                    phase_note = phase or "unknown"
                                                    debug_print(
                                                        f"⚠️ Userscript proxy did not start upstream fetch within {int(preflight_timeout)}s (phase={phase_note})."
                                                    )
                                                    disable_userscript_for_request = True
                                                    try:
                                                        _mark_userscript_proxy_inactive()
                                                    except Exception:
                                                        pass
                                                    try:
                                                        await _finalize_userscript_proxy_job(
                                                            proxy_job_id,
                                                            error="userscript proxy preflight timeout",
                                                            remove=True,
                                                        )
                                                    except Exception:
                                                        pass
                                                    proxy_status_timed_out = True
                                                    break
 
                                        yield ": keep-alive\n\n"
                                        await asyncio.sleep(1.0)

                                    if proxy_status_timed_out:
                                        async for ka in wait_with_keepalive(0.5):
                                            yield ka
                                        continue
                            
                            async with stream_context as response:
                                # Log status with human-readable message
                                log_http_status(response.status_code, "LMArena API Stream")

                                # Redirects break SSE streaming and usually indicate an origin change (arena.ai vs
                                # lmarena.ai) or bot-mitigation. Switch to browser transports (userscript proxy when
                                # active) and retry instead of trying to parse the redirect body as stream data.
                                try:
                                    status_int = int(getattr(response, "status_code", 0) or 0)
                                except Exception:
                                    status_int = 0
                                if 300 <= status_int < 400:
                                    location = ""
                                    try:
                                        location = str(
                                            response.headers.get("location")
                                            or response.headers.get("Location")
                                            or ""
                                        ).strip()
                                    except Exception:
                                        location = ""

                                    if transport_used == "httpx":
                                        debug_print(
                                            f"Upstream returned redirect {status_int} ({location or 'no Location header'}). "
                                            "Enabling browser transports and retrying..."
                                        )
                                        use_browser_transports = True
                                    else:
                                        debug_print(
                                            f"Upstream returned redirect {status_int} ({location or 'no Location header'}). Retrying..."
                                        )

                                    async for ka in wait_with_keepalive(0.5):
                                        yield ka
                                    continue
                                
                                # Check for retry-able errors before processing stream
                                if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                                    retry_429_count += 1
                                    if retry_429_count > 3:
                                        error_chunk = {
                                            "error": {
                                                "message": "Too Many Requests (429) from upstream. Retries exhausted.",
                                                "type": "rate_limit_error",
                                                "code": HTTPStatus.TOO_MANY_REQUESTS,
                                            }
                                        }
                                        yield f"data: {json.dumps(error_chunk)}\n\n"
                                        yield "data: [DONE]\n\n"
                                        return

                                    retry_after = None
                                    try:
                                        retry_after = response.headers.get("Retry-After")
                                    except Exception:
                                        retry_after = None
                                    if not retry_after:
                                        try:
                                            retry_after = response.headers.get("retry-after")
                                        except Exception:
                                            retry_after = None
                                    retry_after_value = 0.0
                                    if isinstance(retry_after, str):
                                        try:
                                            retry_after_value = float(retry_after.strip())
                                        except Exception:
                                            retry_after_value = 0.0
                                    sleep_seconds = get_rate_limit_sleep_seconds(retry_after, attempt)
                                    
                                    debug_print(
                                        f"⏱️  Stream attempt {attempt} - Upstream rate limited. Waiting {sleep_seconds}s..."
                                    )
                                    
                                    # Rotate token on rate limit to avoid spinning on the same blocked account.
                                    old_token = current_token
                                    token_rotated = False
                                    if current_token:
                                        try:
                                            rotation_exclude = set(failed_tokens)
                                            rotation_exclude.add(current_token)
                                            current_token = get_next_auth_token(
                                                exclude_tokens=rotation_exclude, allow_ephemeral_fallback=False
                                            )
                                            headers = get_request_headers_with_token(current_token, recaptcha_token)
                                            token_rotated = True
                                            debug_print(f"🔄 Retrying stream with next token: {current_token[:20]}...")
                                        except HTTPException:
                                            # Only one token (or all tokens excluded). Keep the current token and retry
                                            # after backoff instead of failing fast.
                                            debug_print("⚠️ No alternative token available; retrying with same token after backoff.")

                                    # reCAPTCHA v3 tokens can be single-use and may expire while we back off.
                                    # Clear it so the next browser fetch attempt mints a fresh token.
                                    if isinstance(payload, dict):
                                        payload["recaptchaV3Token"] = ""

                                    # If we rotated tokens, allow a fast retry when the backoff would exceed the remaining
                                    # stream deadline (common when one token is rate-limited but another isn't).
                                    if token_rotated and current_token and current_token != old_token:
                                        remaining_budget = float(stream_total_timeout_seconds) - float(
                                            time.monotonic() - stream_started_at
                                        )
                                        if float(sleep_seconds) > max(0.0, remaining_budget):
                                            sleep_seconds = min(float(sleep_seconds), 1.0)
                                    
                                    async for ka in wait_with_keepalive(sleep_seconds):
                                        yield ka
                                    continue
                                
                                elif response.status_code == HTTPStatus.FORBIDDEN:
                                    # Userscript proxy note:
                                    # The in-page fetch script can report an initial 403 while it mints/retries
                                    # reCAPTCHA (v3 retry + v2 fallback) and may later update the status to 200
                                    # without needing a new proxy job.
                                    if transport_used == "userscript":
                                        proxy_job_id = ""
                                        try:
                                            proxy_job_id = str(getattr(stream_context, "job_id", "") or "").strip()
                                        except Exception:
                                            proxy_job_id = ""

                                        proxy_job = _USERSCRIPT_PROXY_JOBS.get(proxy_job_id) if proxy_job_id else None
                                        proxy_done_event = None
                                        if isinstance(proxy_job, dict):
                                            proxy_done_event = proxy_job.get("done_event")

                                        # Give the proxy a chance to finish its in-page reCAPTCHA retry path before we
                                        # abandon this response and queue a new job (which can lead to pickup timeouts).
                                        try:
                                            grace_seconds = float(
                                                get_config().get("userscript_proxy_recaptcha_grace_seconds", 25)
                                            )
                                        except Exception:
                                            grace_seconds = 25.0
                                        grace_seconds = max(0.0, min(grace_seconds, 90.0))

                                        if (
                                            grace_seconds > 0.0
                                            and isinstance(proxy_done_event, asyncio.Event)
                                            and not proxy_done_event.is_set()
                                        ):
                                            # Important: do not enqueue a new proxy job while the current one is still
                                            # running. The internal Camoufox worker is single-threaded and will not pick
                                            # up new jobs until `page.evaluate()` returns.
                                            remaining_budget = float(stream_total_timeout_seconds) - float(
                                                time.monotonic() - stream_started_at
                                            )
                                            remaining_budget = max(0.0, remaining_budget)
                                            max_wait_seconds = min(max(float(grace_seconds), 200.0), remaining_budget)

                                            debug_print(
                                                f"⏳ Userscript proxy reported 403. Waiting up to {int(max_wait_seconds)}s for in-page retry..."
                                            )
                                            started = time.monotonic()
                                            warned_extended = False
                                            while (time.monotonic() - started) < float(max_wait_seconds):
                                                if response.status_code != HTTPStatus.FORBIDDEN:
                                                    debug_print(
                                                        f"✅ Userscript proxy recovered from 403 (status: {response.status_code})."
                                                    )
                                                    break
                                                if proxy_done_event.is_set():
                                                    break
                                                # If the proxy job already has an error, don't wait the full window.
                                                try:
                                                    if isinstance(proxy_job, dict) and proxy_job.get("error"):
                                                        break
                                                except Exception:
                                                    pass
                                                if (not warned_extended) and (time.monotonic() - started) >= float(
                                                    grace_seconds
                                                ):
                                                    warned_extended = True
                                                    debug_print(
                                                        "⏳ Still 403 after grace window; waiting for proxy job completion..."
                                                    )
                                                yield ": keep-alive\n\n"
                                                await asyncio.sleep(0.5)

                                    # If the userscript proxy recovered (status changed after in-page retries),
                                    # proceed to normal stream parsing below.
                                    if response.status_code != HTTPStatus.FORBIDDEN:
                                        pass
                                    else:
                                        retry_403_count += 1
                                        if retry_403_count > 5:
                                            error_chunk = {
                                                "error": {
                                                    "message": "Forbidden (403) from upstream. Retries exhausted.",
                                                    "type": "forbidden_error",
                                                    "code": HTTPStatus.FORBIDDEN,
                                                }
                                            }
                                            yield f"data: {json.dumps(error_chunk)}\n\n"
                                            yield "data: [DONE]\n\n"
                                            return

                                        body_text = ""
                                        error_body = None
                                        try:
                                            body_bytes = await response.aread()
                                            body_text = body_bytes.decode("utf-8", errors="replace")
                                            error_body = json.loads(body_text)
                                        except Exception:
                                            error_body = None
                                            # If it's not JSON, we'll use the body_text for keyword matching.

                                        is_recaptcha_failure = False
                                        try:
                                            if (
                                                isinstance(error_body, dict)
                                                and error_body.get("error") == "recaptcha validation failed"
                                            ):
                                                is_recaptcha_failure = True
                                            elif "recaptcha validation failed" in str(body_text).lower():
                                                is_recaptcha_failure = True
                                        except Exception:
                                            is_recaptcha_failure = False

                                        if transport_used == "userscript":
                                            # The proxy is our only truly streaming browser transport. Prefer retrying
                                            # it with a fresh in-page token mint over switching to buffered browser
                                            # fetch fallbacks (which can stall SSE).
                                            force_proxy_recaptcha_mint = True
                                            if is_recaptcha_failure:
                                                recaptcha_403_failures += 1
                                                if recaptcha_403_failures >= 5:
                                                    debug_print(
                                                        "? Too many reCAPTCHA failures in userscript proxy. Failing fast."
                                                    )
                                                    error_chunk = {
                                                        "error": {
                                                            "message": (
                                                                "Forbidden: reCAPTCHA validation failed repeatedly in userscript proxy."
                                                            ),
                                                            "type": "recaptcha_error",
                                                            "code": HTTPStatus.FORBIDDEN,
                                                        }
                                                    }
                                                    yield f"data: {json.dumps(error_chunk)}\n\n"
                                                    yield "data: [DONE]\n\n"
                                                    return

                                            if isinstance(payload, dict):
                                                payload["recaptchaV3Token"] = ""
                                                payload.pop("recaptchaV2Token", None)

                                            async for ka in wait_with_keepalive(1.5):
                                                yield ka
                                            continue

                                        if is_recaptcha_failure:
                                            # Track consecutive reCAPTCHA failures so we can escalate to browser
                                            # transports even for non-strict models.
                                            recaptcha_403_failures += 1
                                            if recaptcha_403_last_transport == transport_used:
                                                recaptcha_403_consecutive += 1
                                            else:
                                                recaptcha_403_consecutive = 1
                                                recaptcha_403_last_transport = transport_used

                                            if transport_used in ("chrome", "camoufox"):
                                                try:
                                                    debug_print(
                                                        "Refreshing token/cookies (side-channel) after browser fetch 403..."
                                                    )
                                                    refresh_task = asyncio.create_task(
                                                        refresh_recaptcha_token(force_new=True)
                                                    )
                                                    async for ka in wait_for_task(refresh_task):
                                                        yield ka
                                                    new_token = refresh_task.result()
                                                except Exception:
                                                    new_token = None
                                                # Prefer reusing a fresh side-channel token on the next attempt; if we
                                                # couldn't get one, fall back to in-page minting.
                                                if isinstance(payload, dict):
                                                    payload["recaptchaV3Token"] = new_token or ""
                                            else:
                                                debug_print("Refreshing token (side-channel)...")
                                                try:
                                                    refresh_task = asyncio.create_task(
                                                        refresh_recaptcha_token(force_new=True)
                                                    )
                                                    async for ka in wait_for_task(refresh_task):
                                                        yield ka
                                                    new_token = refresh_task.result()
                                                except Exception:
                                                    new_token = None
                                                if new_token and isinstance(payload, dict):
                                                    payload["recaptchaV3Token"] = new_token

                                            if recaptcha_403_consecutive >= 2 and transport_used == "chrome":
                                                debug_print(
                                                    "Switching to Camoufox-first after repeated Chrome reCAPTCHA failures."
                                                )
                                                use_browser_transports = True
                                                prefer_chrome_transport = False
                                                recaptcha_403_consecutive = 0
                                                recaptcha_403_last_transport = None
                                            elif recaptcha_403_consecutive >= 2 and transport_used != "chrome":
                                                debug_print(
                                                    "🌐 Switching to Chrome fetch transport after repeated reCAPTCHA failures."
                                                )
                                                use_browser_transports = True
                                                prefer_chrome_transport = True
                                                recaptcha_403_consecutive = 0
                                                recaptcha_403_last_transport = None

                                            async for ka in wait_with_keepalive(1.5):
                                                yield ka
                                            continue

                                        # If 403 but not recaptcha, might be other auth issue, but let's retry anyway
                                        async for ka in wait_with_keepalive(2.0):
                                            yield ka
                                        continue

                                elif response.status_code == HTTPStatus.UNAUTHORIZED:
                                    debug_print(f"🔒 Stream token expired")
                                    # Add current token to failed set
                                    failed_tokens.add(current_token)

                                    # Best-effort: refresh the current base64 session in-memory before rotating.
                                    refreshed_token: Optional[str] = None
                                    if current_token:
                                        try:
                                            cfg_now = get_config()
                                        except Exception:
                                            cfg_now = {}
                                        if not isinstance(cfg_now, dict):
                                            cfg_now = {}
                                        try:
                                            refreshed_token = await refresh_arena_auth_token_via_lmarena_http(
                                                current_token, cfg_now
                                            )
                                        except Exception:
                                            refreshed_token = None
                                        if not refreshed_token:
                                            try:
                                                refreshed_token = await refresh_arena_auth_token_via_supabase(current_token)
                                            except Exception:
                                                refreshed_token = None

                                    if refreshed_token:
                                        global EPHEMERAL_ARENA_AUTH_TOKEN
                                        EPHEMERAL_ARENA_AUTH_TOKEN = refreshed_token
                                        current_token = refreshed_token
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        # Ensure the next browser attempt mints a fresh token for the refreshed session.
                                        if isinstance(payload, dict):
                                            payload["recaptchaV3Token"] = ""
                                        debug_print("🔄 Refreshed arena-auth-prod-v1 session after 401. Retrying...")
                                        async for ka in wait_with_keepalive(1.0):
                                            yield ka
                                        continue
                                    
                                    try:
                                        # Try with next available token (excluding failed ones)
                                        current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        debug_print(f"🔄 Retrying stream with next token: {current_token[:20]}...")
                                        async for ka in wait_with_keepalive(1.0):
                                            yield ka
                                        continue
                                    except HTTPException:
                                        debug_print("No more tokens available for streaming request.")
                                        error_chunk = {
                                            "error": {
                                                "message": (
                                                    "Unauthorized: Your LMArena auth token has expired or is invalid. "
                                                    "Please get a new auth token from the dashboard."
                                                ),
                                                "type": "authentication_error",
                                                "code": HTTPStatus.UNAUTHORIZED,
                                            }
                                        }
                                        yield f"data: {json.dumps(error_chunk)}\n\n"
                                        yield "data: [DONE]\n\n"
                                        return
                                
                                log_http_status(response.status_code, "Stream Connection")
                                response.raise_for_status()
                                
                                # Wrapped iterator to yield keep-alives while waiting for upstream lines.
                                # NOTE: Avoid asyncio.wait_for() here; cancelling __anext__ can break the iterator.
                                async def _aiter_with_keepalive(it):
                                    pending: Optional[asyncio.Task] = asyncio.create_task(it.__anext__())
                                    try:
                                        while True:
                                            done, _ = await asyncio.wait({pending}, timeout=1.0)
                                            if pending not in done:
                                                yield None
                                                continue
                                            try:
                                                item = pending.result()
                                            except StopAsyncIteration:
                                                break
                                            pending = asyncio.create_task(it.__anext__())
                                            yield item
                                    finally:
                                        if pending is not None and not pending.done():
                                            pending.cancel()

                                async for maybe_line in _aiter_with_keepalive(response.aiter_lines().__aiter__()):
                                    if maybe_line is None:
                                        yield ": keep-alive\n\n"
                                        continue

                                    line = str(maybe_line).strip()
                                    # Normalize possible SSE framing (e.g. `data: a0:"..."`).
                                    if line.startswith("data:"):
                                        line = line[5:].lstrip()
                                    if not line:
                                        continue
                                    
                                    # Parse thinking/reasoning chunks: ag:"thinking text"
                                    if line.startswith("ag:"):
                                        chunk_data = line[3:]
                                        try:
                                            reasoning_chunk = json.loads(chunk_data)
                                            reasoning_text += reasoning_chunk
                                            
                                            # Send SSE-formatted chunk with reasoning_content
                                            chunk_response = {
                                                "id": chunk_id,
                                                "object": "chat.completion.chunk",
                                                "created": int(time.time()),
                                                "model": model_public_name,
                                                "choices": [{
                                                    "index": 0,
                                                    "delta": {
                                                        "reasoning_content": reasoning_chunk
                                                    },
                                                    "finish_reason": None
                                                }]
                                            }
                                            yield f"data: {json.dumps(chunk_response)}\n\n"
                                            
                                        except json.JSONDecodeError:
                                            continue
                                    
                                    # Parse text chunks: a0:"Hello "
                                    elif line.startswith("a0:"):
                                        chunk_data = line[3:]
                                        try:
                                            text_chunk = json.loads(chunk_data)
                                            response_text += text_chunk
                                            
                                            # Send SSE-formatted chunk
                                            chunk_response = {
                                                "id": chunk_id,
                                                "object": "chat.completion.chunk",
                                                "created": int(time.time()),
                                                "model": model_public_name,
                                                "choices": [{
                                                    "index": 0,
                                                    "delta": {
                                                        "content": text_chunk
                                                    },
                                                    "finish_reason": None
                                                }]
                                            }
                                            yield f"data: {json.dumps(chunk_response)}\n\n"
                                            
                                        except json.JSONDecodeError:
                                            continue
                                    
                                    # Parse image generation: a2:[{...}] (for image models)
                                    elif line.startswith("a2:"):
                                        image_data = line[3:]
                                        try:
                                            image_list = json.loads(image_data)
                                            # OpenAI format: return URL in content
                                            if isinstance(image_list, list) and len(image_list) > 0:
                                                image_obj = image_list[0]
                                                if image_obj.get('type') == 'image':
                                                    image_url = image_obj.get('image', '')
                                                    # Format as markdown for streaming
                                                    response_text = f"![Generated Image]({image_url})"
                                                    
                                                    # Send the markdown-formatted image in a chunk
                                                    chunk_response = {
                                                        "id": chunk_id,
                                                        "object": "chat.completion.chunk",
                                                        "created": int(time.time()),
                                                        "model": model_public_name,
                                                        "choices": [{
                                                            "index": 0,
                                                            "delta": {
                                                                "content": response_text
                                                            },
                                                            "finish_reason": None
                                                        }]
                                                    }
                                                    yield f"data: {json.dumps(chunk_response)}\n\n"
                                        except json.JSONDecodeError:
                                            pass
                                    
                                    # Parse citations/tool calls: ac:{...} (for search models)
                                    elif line.startswith("ac:"):
                                        citation_data = line[3:]
                                        try:
                                            citation_obj = json.loads(citation_data)
                                            # Extract source information from argsTextDelta
                                            if 'argsTextDelta' in citation_obj:
                                                args_data = json.loads(citation_obj['argsTextDelta'])
                                                if 'source' in args_data:
                                                    source = args_data['source']
                                                    # Can be a single source or array of sources
                                                    if isinstance(source, list):
                                                        citations.extend(source)
                                                    elif isinstance(source, dict):
                                                        citations.append(source)
                                            debug_print(f"  🔗 Citation added: {citation_obj.get('toolCallId')}")
                                        except json.JSONDecodeError:
                                            pass
                                    
                                    # Parse error messages
                                    elif line.startswith("a3:"):
                                        error_data = line[3:]
                                        try:
                                            error_message = json.loads(error_data)
                                            print(f"  ❌ Error in stream: {error_message}")
                                        except json.JSONDecodeError:
                                            pass
                                    
                                    # Parse metadata for finish
                                    elif line.startswith("ad:"):
                                        metadata_data = line[3:]
                                        try:
                                            metadata = json.loads(metadata_data)
                                            finish_reason = metadata.get("finishReason", "stop")
                                            
                                            # Send final chunk with finish_reason
                                            final_chunk = {
                                                "id": chunk_id,
                                                "object": "chat.completion.chunk",
                                                "created": int(time.time()),
                                                "model": model_public_name,
                                                "choices": [{
                                                    "index": 0,
                                                    "delta": {},
                                                    "finish_reason": finish_reason
                                                }]
                                            }
                                            yield f"data: {json.dumps(final_chunk)}\n\n"
                                        except json.JSONDecodeError:
                                            continue
                                    
                                    # Support for standard OpenAI-style JSON chunks (some proxies or new LMArena endpoints)
                                    elif line.startswith("{"):
                                        try:
                                            chunk_obj = json.loads(line)
                                            # If it looks like an OpenAI chunk, extract the delta content
                                            if "choices" in chunk_obj and isinstance(chunk_obj["choices"], list) and len(chunk_obj["choices"]) > 0:
                                                delta = chunk_obj["choices"][0].get("delta", {})
                                                
                                                # Handle thinking/reasoning
                                                if "reasoning_content" in delta:
                                                    r_chunk = str(delta["reasoning_content"] or "")
                                                    reasoning_text += r_chunk
                                                    chunk_response = {
                                                        "id": chunk_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_public_name,
                                                        "choices": [{"index": 0, "delta": {"reasoning_content": r_chunk}, "finish_reason": None}]
                                                    }
                                                    yield f"data: {json.dumps(chunk_response)}\n\n"

                                                # Handle text content
                                                if "content" in delta:
                                                    c_chunk = str(delta["content"] or "")
                                                    response_text += c_chunk
                                                    chunk_response = {
                                                        "id": chunk_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_public_name,
                                                        "choices": [{"index": 0, "delta": {"content": c_chunk}, "finish_reason": None}]
                                                    }
                                                    yield f"data: {json.dumps(chunk_response)}\n\n"
                                        except Exception:
                                            pass

                                    else:
                                        # Capture a small preview of unhandled upstream lines for troubleshooting.
                                        if len(unhandled_preview) < 5:
                                            unhandled_preview.append(line)
                                        continue
                            
                            # If we got no usable deltas, treat it as an upstream failure and retry.
                            if (not response_text.strip()) and (not reasoning_text.strip()) and (not citations):
                                upstream_hint: Optional[str] = None
                                proxy_status: Optional[int] = None
                                proxy_headers: Optional[dict] = None
                                if transport_used == "userscript":
                                    try:
                                        proxy_job_id = str(getattr(stream_context, "job_id", "") or "").strip()
                                        proxy_job = _USERSCRIPT_PROXY_JOBS.get(proxy_job_id)
                                        if isinstance(proxy_job, dict):
                                            if proxy_job.get("error"):
                                                upstream_hint = str(proxy_job.get("error") or "")
                                            status = proxy_job.get("status_code")
                                            headers = proxy_job.get("headers")
                                            if isinstance(headers, dict):
                                                proxy_headers = headers
                                            if isinstance(status, int) and int(status) >= 400:
                                                proxy_status = int(status)
                                                upstream_hint = upstream_hint or f"Userscript proxy upstream HTTP {int(status)}"
                                    except Exception:
                                        pass

                                if not upstream_hint and unhandled_preview:
                                    # Common case: upstream returns a JSON error body (not a0:/ad: lines).
                                    try:
                                        obj = json.loads(unhandled_preview[0])
                                        if isinstance(obj, dict):
                                            upstream_hint = str(obj.get("error") or obj.get("message") or "")
                                    except Exception:
                                        pass
                                    
                                    if not upstream_hint:
                                        upstream_hint = unhandled_preview[0][:500]

                                debug_print(f"⚠️ Stream produced no content deltas (transport={transport_used}, attempt {attempt}). Retrying...")
                                if upstream_hint:
                                    debug_print(f"   Upstream hint: {upstream_hint[:200]}")
                                    if "recaptcha" in upstream_hint.lower():
                                        recaptcha_403_failures += 1
                                        if recaptcha_403_failures >= 5:
                                            debug_print("❌ Too many reCAPTCHA failures (detected in body). Failing fast.")
                                            error_chunk = {
                                                "error": {
                                                    "message": f"Forbidden: reCAPTCHA validation failed. Upstream hint: {upstream_hint[:200]}",
                                                    "type": "recaptcha_error",
                                                    "code": HTTPStatus.FORBIDDEN,
                                                }
                                            }
                                            yield f"data: {json.dumps(error_chunk)}\n\n"
                                            yield "data: [DONE]\n\n"
                                            return
                                elif unhandled_preview:
                                    debug_print(f"   Upstream preview: {unhandled_preview[0][:200]}")
                                
                                no_delta_failures += 1
                                if no_delta_failures >= 10:
                                    debug_print("❌ Too many attempts with no content produced. Failing fast.")
                                    error_chunk = {
                                        "error": {
                                            "message": f"Upstream failure: The request produced no content after multiple retries. Last hint: {upstream_hint[:200] if upstream_hint else 'None'}",
                                            "type": "upstream_error",
                                            "code": HTTPStatus.BAD_GATEWAY,
                                        }
                                    }
                                    yield f"data: {json.dumps(error_chunk)}\n\n"
                                    yield "data: [DONE]\n\n"
                                    return

                                # If the userscript proxy actually returned an upstream HTTP error, don't spin forever
                                # sending keep-alives: treat them as the equivalent upstream status and fall back.
                                if transport_used == "userscript" and proxy_status in (
                                    HTTPStatus.UNAUTHORIZED,
                                    HTTPStatus.FORBIDDEN,
                                ):
                                    # Mirror the regular 401/403 handling, but based on the proxy job status instead
                                    # of `response.status_code` (which can be stale for userscript jobs).
                                    if proxy_status == HTTPStatus.UNAUTHORIZED:
                                        debug_print("🔒 Userscript proxy upstream 401. Rotating auth token...")
                                        failed_tokens.add(current_token)
                                        # (Pruning disabled)

                                        try:
                                            current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                            headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        except HTTPException:
                                            error_chunk = {
                                                "error": {
                                                    "message": (
                                                        "Unauthorized: Your LMArena auth token has expired or is invalid. "
                                                        "Please get a new auth token from the dashboard."
                                                    ),
                                                    "type": "authentication_error",
                                                    "code": HTTPStatus.UNAUTHORIZED,
                                                }
                                            }
                                            yield f"data: {json.dumps(error_chunk)}\n\n"
                                            yield "data: [DONE]\n\n"
                                            return

                                    if proxy_status == HTTPStatus.FORBIDDEN:
                                        recaptcha_403_failures += 1
                                        if recaptcha_403_failures >= 5:
                                            debug_print("❌ Too many reCAPTCHA failures in userscript proxy. Failing fast.")
                                            error_chunk = {
                                                "error": {
                                                    "message": "Forbidden: reCAPTCHA validation failed repeatedly in userscript proxy.",
                                                    "type": "recaptcha_error",
                                                    "code": HTTPStatus.FORBIDDEN,
                                                }
                                            }
                                            yield f"data: {json.dumps(error_chunk)}\n\n"
                                            yield "data: [DONE]\n\n"
                                            return

                                        # Common case: the proxy session gets flagged (reCAPTCHA). Retry with a fresh
                                        # in-page token mint rather than switching to buffered browser fetch fallbacks.
                                        force_proxy_recaptcha_mint = True
                                        debug_print("🚫 Userscript proxy upstream 403: retrying userscript (fresh reCAPTCHA).")
                                        if isinstance(payload, dict):
                                            payload["recaptchaV3Token"] = ""
                                            payload.pop("recaptchaV2Token", None)

                                    yield ": keep-alive\n\n"
                                    continue

                                # If the proxy upstream is rate-limited, respect Retry-After/backoff.
                                if transport_used == "userscript" and proxy_status == HTTPStatus.TOO_MANY_REQUESTS:
                                    retry_after = None
                                    if isinstance(proxy_headers, dict):
                                        retry_after = proxy_headers.get("retry-after") or proxy_headers.get("Retry-After")
                                    retry_after_value = 0.0
                                    if isinstance(retry_after, str):
                                        try:
                                            retry_after_value = float(retry_after.strip())
                                        except Exception:
                                            retry_after_value = 0.0
                                    sleep_seconds = get_rate_limit_sleep_seconds(retry_after, attempt)
                                    debug_print(f"⏱️  Userscript proxy upstream 429. Waiting {sleep_seconds}s...")
                                    
                                    # Rotate token on userscript rate limit too.
                                    old_token = current_token
                                    token_rotated = False
                                    try:
                                        rotation_exclude = set(failed_tokens)
                                        if current_token:
                                            rotation_exclude.add(current_token)
                                        current_token = get_next_auth_token(
                                            exclude_tokens=rotation_exclude, allow_ephemeral_fallback=False
                                        )
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        token_rotated = True
                                        debug_print(f"🔄 Retrying stream with next token (after proxy 429): {current_token[:20]}...")
                                    except HTTPException:
                                        # Only one token (or all tokens excluded). Keep the current token and retry
                                        # after backoff instead of failing fast.
                                        debug_print(
                                            "⚠️ No alternative token available after userscript proxy rate limit; retrying with same token after backoff."
                                        )

                                    # reCAPTCHA v3 tokens can be single-use and may expire while we back off.
                                    # Clear it so the next proxy attempt mints a fresh token in-page.
                                    if isinstance(payload, dict):
                                        payload["recaptchaV3Token"] = ""

                                    # If we rotated tokens, allow a fast retry when waiting would blow past the remaining
                                    # stream deadline (common when one token is rate-limited but another isn't).
                                    if token_rotated and current_token and current_token != old_token:
                                        remaining_budget = float(stream_total_timeout_seconds) - float(
                                            time.monotonic() - stream_started_at
                                        )
                                        if float(sleep_seconds) > max(0.0, remaining_budget):
                                            sleep_seconds = min(float(sleep_seconds), 1.0)

                                    # If we still can't wait within the remaining deadline, fail now instead of sending
                                    # keep-alives indefinitely.
                                    if (time.monotonic() - stream_started_at + float(sleep_seconds)) > stream_total_timeout_seconds:
                                        error_chunk = {
                                            "error": {
                                                "message": f"Upstream rate limit (429) would exceed stream deadline ({int(sleep_seconds)}s backoff).",
                                                "type": "rate_limit_error",
                                                "code": HTTPStatus.TOO_MANY_REQUESTS,
                                            }
                                        }
                                        yield f"data: {json.dumps(error_chunk)}\n\n"
                                        yield "data: [DONE]\n\n"
                                        return

                                    async for ka in wait_with_keepalive(sleep_seconds):
                                        yield ka
                                else:
                                    async for ka in wait_with_keepalive(1.5):
                                        yield ka
                                continue

                            # Update session - Store message history with IDs (including reasoning and citations if present)
                            assistant_message = {
                                "id": model_msg_id, 
                                "role": "assistant", 
                                "content": response_text.strip()
                            }
                            if reasoning_text:
                                assistant_message["reasoning_content"] = reasoning_text.strip()
                            if citations:
                                # Deduplicate citations by URL
                                unique_citations = []
                                seen_urls = set()
                                for citation in citations:
                                    citation_url = citation.get('url')
                                    if citation_url and citation_url not in seen_urls:
                                        seen_urls.add(citation_url)
                                        unique_citations.append(citation)
                                assistant_message["citations"] = unique_citations
                            
                            if not session:
                                chat_sessions[api_key_str][conversation_id] = {
                                    "conversation_id": session_id,
                                    "model": model_public_name,
                                    "messages": [
                                        {"id": user_msg_id, "role": "user", "content": prompt},
                                        assistant_message
                                    ]
                                }
                                debug_print(f"💾 Saved new session for conversation {conversation_id}")
                            else:
                                # Append new messages to history
                                chat_sessions[api_key_str][conversation_id]["messages"].append(
                                    {"id": user_msg_id, "role": "user", "content": prompt}
                                )
                                chat_sessions[api_key_str][conversation_id]["messages"].append(
                                    assistant_message
                                )
                                debug_print(f"💾 Updated existing session for conversation {conversation_id}")
                            
                            yield "data: [DONE]\n\n"
                            debug_print(f"✅ Stream completed - {len(response_text)} chars sent")
                            return  # Success, exit retry loop
                                
                    except asyncio.CancelledError:
                        # Client disconnected or server shutdown. Avoid leaking proxy jobs or surfacing noisy uvicorn
                        # "response not completed" warnings on cancellation.
                        try:
                            if transport_used == "userscript":
                                jid = str(getattr(stream_context, "job_id", "") or "").strip()
                                if jid:
                                    await _finalize_userscript_proxy_job(jid, error="client disconnected", remove=True)
                        except Exception:
                            pass
                        return
                    except httpx.HTTPStatusError as e:
                        # Handle retry-able errors
                        if e.response.status_code == 429:
                            current_retry_attempt += 1
                            if current_retry_attempt > max_retries:
                                error_msg = "LMArena API error 429: Too many requests. Max retries exceeded. Terminating stream."
                                debug_print(f"❌ {error_msg}")
                                error_chunk = {
                                    "error": {
                                        "message": error_msg,
                                        "type": "api_error",
                                        "code": e.response.status_code,
                                    }
                                }
                                yield f"data: {json.dumps(error_chunk)}\n\n"
                                yield "data: [DONE]\n\n"
                                return

                            retry_after_header = e.response.headers.get("Retry-After")
                            sleep_seconds = get_rate_limit_sleep_seconds(
                                retry_after_header, current_retry_attempt
                            )
                            debug_print(
                                f"⏱️ LMArena API returned 429 (Too Many Requests). "
                                f"Retrying in {sleep_seconds} seconds (attempt {current_retry_attempt}/{max_retries})."
                            )
                            async for ka in wait_with_keepalive(sleep_seconds):
                                yield ka
                            continue # Continue to the next iteration of the while True loop
                        elif e.response.status_code == 403:
                            current_retry_attempt += 1
                            if current_retry_attempt > max_retries:
                                error_msg = "LMArena API error 403: Forbidden. Max retries exceeded. Terminating stream."
                                debug_print(f"❌ {error_msg}")
                                error_chunk = {
                                    "error": {
                                        "message": error_msg,
                                        "type": "api_error",
                                        "code": e.response.status_code,
                                    }
                                }
                                yield f"data: {json.dumps(error_chunk)}\n\n"
                                yield "data: [DONE]\n\n"
                                return
                            
                            debug_print(
                                f"🚫 LMArena API returned 403 (Forbidden). "
                                f"Retrying with exponential backoff (attempt {current_retry_attempt}/{max_retries})."
                            )
                            sleep_seconds = get_general_backoff_seconds(current_retry_attempt)
                            async for ka in wait_with_keepalive(sleep_seconds):
                                yield ka
                            continue # Continue to the next iteration of the while True loop
                        elif e.response.status_code == 401:
                            # Existing 401 handling (token rotation) will implicitly use the retry loop.
                            # We need to ensure max_retries applies here too.
                            current_retry_attempt += 1
                            if current_retry_attempt > max_retries:
                                error_msg = "LMArena API error 401: Unauthorized. Max retries exceeded. Terminating stream."
                                debug_print(f"❌ {error_msg}")
                                error_chunk = {
                                    "error": {
                                        "message": error_msg,
                                        "type": "api_error",
                                        "code": e.response.status_code,
                                    }
                                }
                                yield f"data: {json.dumps(error_chunk)}\n\n"
                                yield "data: [DONE]\n\n"
                                return
                            # The original code has `continue` here, which leads to `async for ka in wait_with_keepalive(2.0): yield ka`.
                            # This is fine for 401 to allow token rotation and retry.
                            async for ka in wait_with_keepalive(2.0):
                                yield ka
                            continue
                        else:
                            # Provide user-friendly error messages for non-retryable errors
                            try:
                                body_text = ""
                                try:
                                    raw = await e.response.aread()
                                    if isinstance(raw, (bytes, bytearray)):
                                        body_text = raw.decode("utf-8", errors="replace")
                                    else:
                                        body_text = str(raw)
                                except Exception:
                                    body_text = ""
                                body_text = str(body_text or "").strip()
                                if body_text:
                                    preview = body_text[:800]
                                    error_msg = f"LMArena API error {e.response.status_code}: {preview}"
                                else:
                                    error_msg = f"LMArena API error: {e.response.status_code}"
                            except Exception:
                                error_msg = f"LMArena API error: {e.response.status_code}"
                            
                            error_type = "api_error"
                            
                            debug_print(f"❌ {error_msg}")
                            error_chunk = {
                                "error": {
                                    "message": error_msg,
                                    "type": error_type,
                                    "code": e.response.status_code
                                }
                            }
                            yield f"data: {json.dumps(error_chunk)}\n\n"
                            yield "data: [DONE]\n\n"
                            return
                    except Exception as e:
                        debug_print(f"❌ Stream error: {str(e)}")
                        # If it's a connection error, we might want to retry indefinitely too? 
                        # For now, let's treat generic exceptions as transient if possible, or just fail safely.
                        # Given "until real content deltas arrive", we should probably be aggressive with retries.
                        # But legitimate internal errors should probably surface.
                        # Let's retry on network-like errors if we can distinguish them.
                        # For now, yield error.
                        error_chunk = {
                            "error": {
                                "message": str(e),
                                "type": "internal_error"
                            }
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        yield "data: [DONE]\n\n"
                        return
            return StreamingResponse(generate_stream(), media_type="text/event-stream")
        
        # Handle non-streaming mode with retry
        try:
            response = None
            if time.time() - last_userscript_poll < 15:
                debug_print(f"🌐 Userscript Proxy is ACTIVE. Delegating non-streaming request...")
                response = await fetch_via_proxy_queue(
                    url=url,
                    payload=payload if isinstance(payload, dict) else {},
                    http_method=http_method,
                    timeout_seconds=120,
                    auth_token=current_token,
                )
                if response:
                    # Raise for status to trigger the standard error handling block below if needed
                    response.raise_for_status()
                else:
                    debug_print("⚠️ Userscript Proxy returned None. Falling back...")

            if response is None:
                if use_chrome_fetch_for_model:
                    debug_print(f"🌐 Using Chrome fetch transport for non-streaming strict model ({model_public_name})...")
                    # Chrome fetch transport has its own internal reCAPTCHA retries, 
                    # but we add an outer loop here to handle token rotation (401) and rate limits (429).
                    max_chrome_retries = 3
                    for chrome_attempt in range(max_chrome_retries):
                        response = await fetch_lmarena_stream_via_chrome(
                            http_method=http_method,
                            url=url,
                            payload=payload if isinstance(payload, dict) else {},
                            auth_token=current_token,
                            timeout_seconds=120,
                        )
                        
                        if response is None:
                            debug_print(f"⚠️ Chrome fetch transport failed (attempt {chrome_attempt+1}). Trying Camoufox...")
                            response = await fetch_lmarena_stream_via_camoufox(
                                http_method=http_method,
                                url=url,
                                payload=payload if isinstance(payload, dict) else {},
                                auth_token=current_token,
                                timeout_seconds=120,
                            )
                            if response is None:
                                break # Critical error
                        
                        if response.status_code == HTTPStatus.UNAUTHORIZED:
                            debug_print(f"🔒 Token {current_token[:20]}... expired in Chrome fetch (attempt {chrome_attempt+1})")
                            failed_tokens.add(current_token)
                            # (Pruning disabled)
                            if chrome_attempt < max_chrome_retries - 1:
                                try:
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    debug_print(f"🔄 Rotating to next token: {current_token[:20]}...")
                                    continue
                                except HTTPException:
                                    break
                        elif response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                            debug_print(f"⏱️  Rate limit in Chrome fetch (attempt {chrome_attempt+1})")
                            if chrome_attempt < max_chrome_retries - 1:
                                sleep_seconds = get_rate_limit_sleep_seconds(response.headers.get("Retry-After"), chrome_attempt)
                                await asyncio.sleep(sleep_seconds)
                                continue
                        
                        # If success or non-retryable error, break and use this response
                        break
                else:
                    response = await make_request_with_retry(url, payload, http_method)
            
            if response is None:
                debug_print("⚠️ Browser transports returned None; falling back to direct httpx.")
                response = await make_request_with_retry(url, payload, http_method)

            if response is None:
                raise HTTPException(
                    status_code=502,
                    detail="Failed to fetch response from LMArena (transport returned None)",
                )
                
            log_http_status(response.status_code, "LMArena API Response")
            
            # Use aread() to ensure we buffer streaming-capable responses (like BrowserFetchStreamResponse)
            response_bytes = await response.aread()
            response_text_body = response_bytes.decode("utf-8", errors="replace")
            
            debug_print(f"📏 Response length: {len(response_text_body)} characters")
            debug_print(f"📋 Response headers: {dict(response.headers)}")
            
            debug_print(f"🔍 Processing response...")
            debug_print(f"📄 First 500 chars of response:\n{response_text_body[:500]}")
            
            # Process response in lmarena format
            # Format: ag:"thinking" for reasoning, a0:"text chunk" for content, ac:{...} for citations, ad:{...} for metadata
            response_text = ""
            reasoning_text = ""
            citations = []
            finish_reason = None
            line_count = 0
            text_chunks_found = 0
            reasoning_chunks_found = 0
            citation_chunks_found = 0
            metadata_found = 0
            
            debug_print(f"📊 Parsing response lines...")
            
            error_message = None
            for line in response_text_body.splitlines():
                line_count += 1
                line = line.strip()
                if line.startswith("data: "):
                    line = line[6:].strip()
                if not line:
                    continue
                
                # Parse thinking/reasoning chunks: ag:"thinking text"
                if line.startswith("ag:"):
                    chunk_data = line[3:]  # Remove "ag:" prefix
                    reasoning_chunks_found += 1
                    try:
                        # Parse as JSON string (includes quotes)
                        reasoning_chunk = json.loads(chunk_data)
                        reasoning_text += reasoning_chunk
                        if reasoning_chunks_found <= 3:  # Log first 3 reasoning chunks
                            debug_print(f"  🧠 Reasoning chunk {reasoning_chunks_found}: {repr(reasoning_chunk[:50])}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse reasoning chunk on line {line_count}: {chunk_data[:100]} - {e}")
                        continue
                
                # Parse text chunks: a0:"Hello "
                elif line.startswith("a0:"):
                    chunk_data = line[3:]  # Remove "a0:" prefix
                    text_chunks_found += 1
                    try:
                        # Parse as JSON string (includes quotes)
                        text_chunk = json.loads(chunk_data)
                        response_text += text_chunk
                        if text_chunks_found <= 3:  # Log first 3 chunks
                            debug_print(f"  ✅ Chunk {text_chunks_found}: {repr(text_chunk[:50])}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse text chunk on line {line_count}: {chunk_data[:100]} - {e}")
                        continue
                
                # Parse image generation: a2:[{...}] (for image models)
                elif line.startswith("a2:"):
                    image_data = line[3:]  # Remove "a2:" prefix
                    try:
                        image_list = json.loads(image_data)
                        # OpenAI format expects URL in content
                        if isinstance(image_list, list) and len(image_list) > 0:
                            image_obj = image_list[0]
                            if image_obj.get('type') == 'image':
                                image_url = image_obj.get('image', '')
                                # Format as markdown
                                response_text = f"![Generated Image]({image_url})"
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse image data on line {line_count}: {image_data[:100]} - {e}")
                        continue
                
                # Parse citations/tool calls: ac:{...} (for search models)
                elif line.startswith("ac:"):
                    citation_data = line[3:]  # Remove "ac:" prefix
                    citation_chunks_found += 1
                    try:
                        citation_obj = json.loads(citation_data)
                        # Extract source information from argsTextDelta
                        if 'argsTextDelta' in citation_obj:
                            args_data = json.loads(citation_obj['argsTextDelta'])
                            if 'source' in args_data:
                                source = args_data['source']
                                # Can be a single source or array of sources
                                if isinstance(source, list):
                                    citations.extend(source)
                                elif isinstance(source, dict):
                                    citations.append(source)
                        if citation_chunks_found <= 3:  # Log first 3 citations
                            debug_print(f"  🔗 Citation chunk {citation_chunks_found}: {citation_obj.get('toolCallId')}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse citation chunk on line {line_count}: {citation_data[:100]} - {e}")
                        continue
                
                # Parse error messages: a3:"An error occurred"
                elif line.startswith("a3:"):
                    error_data = line[3:]  # Remove "a3:" prefix
                    try:
                        error_message = json.loads(error_data)
                        debug_print(f"  ❌ Error message received: {error_message}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse error message on line {line_count}: {error_data[:100]} - {e}")
                        error_message = error_data
                
                # Parse metadata: ad:{"finishReason":"stop"}
                elif line.startswith("ad:"):
                    metadata_data = line[3:]  # Remove "ad:" prefix
                    metadata_found += 1
                    try:
                        metadata = json.loads(metadata_data)
                        finish_reason = metadata.get("finishReason")
                        debug_print(f"  📋 Metadata found: finishReason={finish_reason}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse metadata on line {line_count}: {metadata_data[:100]} - {e}")
                        continue
                elif line.strip():  # Non-empty line that doesn't match expected format
                    if line_count <= 5:  # Log first 5 unexpected lines
                        debug_print(f"  ❓ Unexpected line format {line_count}: {line[:100]}")

            debug_print(f"\n📊 Parsing Summary:")
            debug_print(f"  - Total lines: {line_count}")
            debug_print(f"  - Reasoning chunks found: {reasoning_chunks_found}")
            debug_print(f"  - Text chunks found: {text_chunks_found}")
            debug_print(f"  - Citation chunks found: {citation_chunks_found}")
            debug_print(f"  - Metadata entries: {metadata_found}")
            debug_print(f"  - Final response length: {len(response_text)} chars")
            debug_print(f"  - Final reasoning length: {len(reasoning_text)} chars")
            debug_print(f"  - Citations found: {len(citations)}")
            debug_print(f"  - Finish reason: {finish_reason}")
            
            if not response_text:
                debug_print(f"\n⚠️  WARNING: Empty response text!")
                debug_print(f"📄 Full raw response:\n{response_text_body}")
                if error_message:
                    error_detail = f"LMArena API error: {error_message}"
                    print(f"❌ {error_detail}")
                    # Return OpenAI-compatible error response
                    return {
                        "error": {
                            "message": error_detail,
                            "type": "upstream_error",
                            "code": "lmarena_error"
                        }
                    }
                else:
                    error_detail = "LMArena API returned empty response. This could be due to: invalid auth token, expired cf_clearance, model unavailable, or API rate limiting."
                    debug_print(f"❌ {error_detail}")
                    # Return OpenAI-compatible error response
                    return {
                        "error": {
                            "message": error_detail,
                            "type": "upstream_error",
                            "code": "empty_response"
                        }
                    }
            else:
                debug_print(f"✅ Response text preview: {response_text[:200]}...")
            
            # Update session - Store message history with IDs (including reasoning and citations if present)
            assistant_message = {
                "id": model_msg_id, 
                "role": "assistant", 
                "content": response_text.strip()
            }
            if reasoning_text:
                assistant_message["reasoning_content"] = reasoning_text.strip()
            if citations:
                # Deduplicate citations by URL
                unique_citations = []
                seen_urls = set()
                for citation in citations:
                    citation_url = citation.get('url')
                    if citation_url and citation_url not in seen_urls:
                        seen_urls.add(citation_url)
                        unique_citations.append(citation)
                assistant_message["citations"] = unique_citations
            
            if not session:
                chat_sessions[api_key_str][conversation_id] = {
                    "conversation_id": session_id,
                    "model": model_public_name,
                    "messages": [
                        {"id": user_msg_id, "role": "user", "content": prompt},
                        assistant_message
                    ]
                }
                debug_print(f"💾 Saved new session for conversation {conversation_id}")
            else:
                # Append new messages to history
                chat_sessions[api_key_str][conversation_id]["messages"].append(
                    {"id": user_msg_id, "role": "user", "content": prompt}
                )
                chat_sessions[api_key_str][conversation_id]["messages"].append(
                    assistant_message
                )
                debug_print(f"💾 Updated existing session for conversation {conversation_id}")

            # Build message object with reasoning and citations if present
            message_obj = {
                "role": "assistant",
                "content": response_text.strip(),
            }
            if reasoning_text:
                message_obj["reasoning_content"] = reasoning_text.strip()
            if citations:
                # Deduplicate citations by URL
                unique_citations = []
                seen_urls = set()
                for citation in citations:
                    citation_url = citation.get('url')
                    if citation_url and citation_url not in seen_urls:
                        seen_urls.add(citation_url)
                        unique_citations.append(citation)
                message_obj["citations"] = unique_citations
                
                # Add citations as markdown footnotes
                if unique_citations:
                    footnotes = "\n\n---\n\n**Sources:**\n\n"
                    for i, citation in enumerate(unique_citations, 1):
                        title = citation.get('title', 'Untitled')
                        url = citation.get('url', '')
                        footnotes += f"{i}. [{title}]({url})\n"
                    message_obj["content"] = response_text.strip() + footnotes
            
            # Image models already have markdown formatting from parsing
            # No additional conversion needed
            
            # Calculate token counts (including reasoning tokens)
            prompt_tokens = len(prompt)
            completion_tokens = len(response_text)
            reasoning_tokens = len(reasoning_text)
            total_tokens = prompt_tokens + completion_tokens + reasoning_tokens
            
            # Build usage object with reasoning tokens if present
            usage_obj = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
            if reasoning_tokens > 0:
                usage_obj["reasoning_tokens"] = reasoning_tokens
            
            final_response = {
                "id": f"chatcmpl-{uuid.uuid4()}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model_public_name,
                "conversation_id": conversation_id,
                "choices": [{
                    "index": 0,
                    "message": message_obj,
                    "finish_reason": "stop"
                }],
                "usage": usage_obj
            }
            
            debug_print(f"\n✅ REQUEST COMPLETED SUCCESSFULLY")
            debug_print("="*80 + "\n")
            
            return final_response

        except httpx.HTTPStatusError as e:
            # Log error status
            log_http_status(e.response.status_code, "Error Response")
            
            # Try to parse JSON error response from LMArena
            lmarena_error = None
            try:
                error_body = e.response.json()
                if isinstance(error_body, dict) and "error" in error_body:
                    lmarena_error = error_body["error"]
                    debug_print(f"📛 LMArena error message: {lmarena_error}")
            except:
                pass
            
            # Provide user-friendly error messages
            if e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                error_detail = "Rate limit exceeded on LMArena. Please try again in a few moments."
                error_type = "rate_limit_error"
            elif e.response.status_code == HTTPStatus.UNAUTHORIZED:
                error_detail = "Unauthorized: Your LMArena auth token has expired or is invalid. Please get a new auth token from the dashboard."
                error_type = "authentication_error"
            elif e.response.status_code == HTTPStatus.FORBIDDEN:
                error_detail = f"Forbidden: Access to this resource is denied. {e.response.text}"
                error_type = "forbidden_error"
            elif e.response.status_code == HTTPStatus.NOT_FOUND:
                error_detail = "Not Found: The requested resource doesn't exist."
                error_type = "not_found_error"
            elif e.response.status_code == HTTPStatus.BAD_REQUEST:
                # Use LMArena's error message if available
                if lmarena_error:
                    error_detail = f"Bad Request: {lmarena_error}"
                else:
                    error_detail = f"Bad Request: Invalid request parameters. {e.response.text}"
                error_type = "bad_request_error"
            elif e.response.status_code >= 500:
                error_detail = f"Server Error: LMArena API returned {e.response.status_code}"
                error_type = "server_error"
            else:
                error_detail = f"LMArena API error {e.response.status_code}: {e.response.text}"
                error_type = "upstream_error"
            
            print(f"\n❌ HTTP STATUS ERROR")
            print(f"📛 Error detail: {error_detail}")
            print(f"📤 Request URL: {url}")
            debug_print(f"📤 Request payload (truncated): {json.dumps(payload, indent=2)[:500]}")
            debug_print(f"📥 Response text: {e.response.text[:500]}")
            print("="*80 + "\n")
            
            # Return OpenAI-compatible error response
            return {
                "error": {
                    "message": error_detail,
                    "type": error_type,
                    "code": f"http_{e.response.status_code}"
                }
            }
        
        except httpx.TimeoutException as e:
            print(f"\n⏱️  TIMEOUT ERROR")
            print(f"📛 Request timed out after 120 seconds")
            print(f"📤 Request URL: {url}")
            print("="*80 + "\n")
            # Return OpenAI-compatible error response
            return {
                "error": {
                    "message": "Request to LMArena API timed out after 120 seconds",
                    "type": "timeout_error",
                    "code": "request_timeout"
                }
            }
        
        except Exception as e:
            print(f"\n❌ UNEXPECTED ERROR IN HTTP CLIENT")
            print(f"📛 Error type: {type(e).__name__}")
            print(f"📛 Error message: {str(e)}")
            print(f"📤 Request URL: {url}")
            print("="*80 + "\n")
            # Return OpenAI-compatible error response
            return {
                "error": {
                    "message": f"Unexpected error: {str(e)}",
                    "type": "internal_error",
                    "code": type(e).__name__.lower()
                }
            }
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ TOP-LEVEL EXCEPTION")
        print(f"📛 Error type: {type(e).__name__}")
        print(f"📛 Error message: {str(e)}")
        print("="*80 + "\n")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

if __name__ == "__main__":
    # Avoid crashes on Windows consoles with non-UTF8 code pages (e.g., GBK) when printing emojis.
    try:
        import sys

        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 60)
    print("🚀 LMArena Bridge Server Starting...")
    print("=" * 60)
    print(f"📍 Dashboard: http://localhost:{PORT}/dashboard")
    print(f"🔐 Login: http://localhost:{PORT}/login")
    print(f"📚 API Base URL: http://localhost:{PORT}/api/v1")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=PORT)
