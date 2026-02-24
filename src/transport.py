"""
Transport layer for LMArenaBridge.

Contains the stream response classes, arena origin/cookie utilities, and the three fetch
transport implementations (userscript proxy, Chrome/Playwright, Camoufox), plus the
Camoufox proxy worker and push_proxy_chunk helper.

Cross-module globals (from main.py) are accessed via _m() late-import so test patches
on main.X remain effective.
"""

import asyncio
import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException, Request
from . import constants as _constants

HTTPStatus = _constants.HTTPStatus


def _m():
    """Late import of main module so tests can patch main.X and it is reflected here."""
    from . import main
    return main


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




def _touch_userscript_poll(now: Optional[float] = None) -> None:
    """
    Update userscript-proxy "last seen" timestamps.

    The bridge supports both an external userscript poller and an internal Camoufox-backed poller.
    Keep both timestamps in sync so strict-model routing can reliably detect proxy availability.
    """
    ts = float(now if now is not None else _m().time.time())
    _m().USERSCRIPT_PROXY_LAST_POLL_AT = ts
    # Legacy timestamp used by older code paths/tests.
    _m().last_userscript_poll = ts


def _get_userscript_proxy_queue() -> asyncio.Queue:
    if _m()._USERSCRIPT_PROXY_QUEUE is None:
        _m()._USERSCRIPT_PROXY_QUEUE = asyncio.Queue()
    return _m()._USERSCRIPT_PROXY_QUEUE


def _userscript_proxy_is_active(config: Optional[dict] = None) -> bool:
    cfg = config or _m().get_config()
    poll_timeout = 25
    try:
        poll_timeout = int(cfg.get("userscript_proxy_poll_timeout_seconds", 25))
    except Exception:
        poll_timeout = 25
    active_window = max(10, min(poll_timeout + 10, 90))
    # Back-compat: some callers/tests still update the legacy `_m().last_userscript_poll` timestamp.
    try:
        last = max(float(_m().USERSCRIPT_PROXY_LAST_POLL_AT or 0.0), float(_m().last_userscript_poll or 0.0))
    except Exception:
        last = float(_m().USERSCRIPT_PROXY_LAST_POLL_AT or 0.0)
    try:
        delta = float(_m().time.time()) - float(last)
    except Exception:
        delta = 999999.0
    # Guard against clock skew / patched clocks in tests: a "last poll" timestamp in the future is not active.
    if delta < 0:
        return False
    return delta <= float(active_window)


def _userscript_proxy_check_secret(request: Request) -> None:
    cfg = _m().get_config()
    secret = str(cfg.get("userscript_proxy_secret") or "").strip()
    if secret and request.headers.get("X-LMBridge-Secret") != secret:
        raise HTTPException(status_code=401, detail="Invalid userscript proxy secret")


def _cleanup_userscript_proxy_jobs(config: Optional[dict] = None) -> None:
    cfg = config or _m().get_config()
    ttl_seconds = 90
    try:
        ttl_seconds = int(cfg.get("userscript_proxy_job_ttl_seconds", 90))
    except Exception:
        ttl_seconds = 90
    ttl_seconds = max(10, min(ttl_seconds, 600))

    now = _m().time.time()
    expired: list[str] = []
    for job_id, job in list(_m()._USERSCRIPT_PROXY_JOBS.items()):
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
        _m()._USERSCRIPT_PROXY_JOBS.pop(job_id, None)


def _mark_userscript_proxy_inactive() -> None:
    """
    Mark the userscript-proxy as inactive.

    Do this when we detect proxy health/timeouts so strict-model routing stops preferring a proxy that is not
    responding. The proxy becomes active again once a real poll/push updates the timestamps.
    """
    _m().USERSCRIPT_PROXY_LAST_POLL_AT = 0.0
    _m().last_userscript_poll = 0.0


async def _finalize_userscript_proxy_job(job_id: str, *, error: Optional[str] = None, remove: bool = False) -> None:
    """
    Finalize a userscript-proxy job without touching proxy "last seen" timestamps.

    This is intentionally separate from `push_proxy_chunk()`: server-side timeouts must not keep the proxy
    marked as "active" because that would route future requests back into a dead proxy.
    """
    jid = str(job_id or "").strip()
    if not jid:
        return
    job = _m()._USERSCRIPT_PROXY_JOBS.get(jid)
    if not isinstance(job, dict):
        return

    if error and not job.get("error"):
        job["error"] = str(error)

    if job.get("_finalized"):
        if remove:
            _m()._USERSCRIPT_PROXY_JOBS.pop(jid, None)
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
        _m()._USERSCRIPT_PROXY_JOBS.pop(jid, None)


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
        job = _m()._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
        job = _m()._USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if isinstance(job, dict):
            headers = job.get("headers")
            if isinstance(headers, dict):
                return headers
        return self._headers

    @headers.setter
    def headers(self, value: dict) -> None:
        self._headers = value if isinstance(value, dict) else {}

    async def __aenter__(self):
        job = _m()._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
        job = _m()._USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if not isinstance(job, dict):
            return
        q = job.get("lines_queue")
        done_event = job.get("done_event")
        if not isinstance(q, asyncio.Queue) or not isinstance(done_event, asyncio.Event):
            return

        deadline = _m().time.time() + float(max(5, self._timeout_seconds))
        while True:
            if done_event.is_set() and q.empty():
                break
            remaining = deadline - _m().time.time()
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
        job = _m()._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
        job = _m()._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
    config = _m().get_config()
    _cleanup_userscript_proxy_jobs(config)

    job_id = str(uuid.uuid4())
    lines_queue: asyncio.Queue = asyncio.Queue()
    done_event: asyncio.Event = asyncio.Event()
    status_event: asyncio.Event = asyncio.Event()
    picked_up_event: asyncio.Event = asyncio.Event()

    proxy_url = _normalize_userscript_proxy_url(str(url))
    sitekey, action = _m().get_recaptcha_settings(config)
    job = {
        "created_at": _m().time.time(),
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
    _m()._USERSCRIPT_PROXY_JOBS[job_id] = job
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

    chrome_path = _m().find_chrome_executable()
    if not chrome_path:
        return None

    config = _m().get_config()
    recaptcha_sitekey, recaptcha_action = _m().get_recaptcha_settings(config)

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

    user_agent = _m().normalize_user_agent_value(config.get("user_agent"))

    fetch_url = _normalize_userscript_proxy_url(url)

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

    profile_dir = Path(_m().CONFIG_FILE).with_name("chrome_grecaptcha")
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
            await _m()._maybe_apply_camoufox_window_mode(
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
                    _m().debug_print(f"  ⏳ Waiting for Cloudflare challenge in Chrome... (attempt {i+1}/10)")
                    await _m().click_turnstile(page)
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
                _m()._capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if _m()._upsert_browser_session_into_config(config, fresh_cookies, user_agent=ua_now):
                    _m().save_config(config)
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
                    {"sitekey": _m().RECAPTCHA_V2_SITEKEY, "timeoutMs": 60000},
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
                    sleep_seconds = _m().get_rate_limit_sleep_seconds(
                        str(retry_after) if retry_after is not None else None,
                        attempt,
                    )
                    await _m()._cancel_background_task(fetch_task)
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
                            _m()._consume_background_task_exception(task)
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
                    await _m()._cancel_background_task(fetch_task)
                    break

                await _m()._cancel_background_task(fetch_task)
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
                        await _m().click_turnstile(page)
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
            _m().debug_print(f"??? Chrome fetch transport failed: {e}")
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
    _m().debug_print("🦊 Attempting Camoufox fetch transport...")
    
    config = _m().get_config()
    recaptcha_sitekey, recaptcha_action = _m().get_recaptcha_settings(config)
    
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

    user_agent = _m().normalize_user_agent_value(config.get("user_agent"))

    fetch_url = _normalize_userscript_proxy_url(url)

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

        async with _m().AsyncCamoufox(headless=headless, main_world_eval=True) as browser:
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
            await _m()._maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="camoufox_fetch_window_mode",
                marker="LMArenaBridge Camoufox Fetch",
                headless=headless,
            )
              
            _m().debug_print(f"  🦊 Navigating to lmarena.ai...")
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
                    await _m().click_turnstile(page)
                    await asyncio.sleep(2)
            except Exception:
                pass
            
            # Persist cookies
            try:
                fresh_cookies = await _get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                _m()._capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if _m()._upsert_browser_session_into_config(config, fresh_cookies, user_agent=ua_now):
                    _m().save_config(config)
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
                await _m().safe_page_evaluate(page, "() => { (window.wrappedJSObject || window).__token_result = 'PENDING'; }")

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
                await _m().safe_page_evaluate(page, trigger_script)

                # 3. Poll for result
                for _ in range(40): # 20 seconds max (0.5s interval)
                    val = await _m().safe_page_evaluate(page, "() => (window.wrappedJSObject || window).__token_result")
                    if val != 'PENDING':
                        if isinstance(val, str) and (val.startswith('ERROR') or val.startswith('SYNC_ERROR')):
                            _m().debug_print(f"  ⚠️ Camoufox token mint error: {val}")
                            return None
                        return val
                    await asyncio.sleep(0.5)
                
                _m().debug_print("  ⚠️ Camoufox token mint timed out.")
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
                            sitekey: {json.dumps(_m().RECAPTCHA_V2_SITEKEY)},
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
                    token = await _m().safe_page_evaluate(page, v2_script)
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
                        _m().debug_print(f"  ⚠️ Error minting token in Camoufox: {e}")

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
                    await _m()._cancel_background_task(fetch_task)
                    await asyncio.sleep(5)
                    continue

                if not _is_recaptcha_validation_failed(status_code, result.get("text")):
                    if status_code < 400:
                        def _on_fetch_task_done(task: "asyncio.Task") -> None:
                            _m()._consume_background_task_exception(task)
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
                    await _m()._cancel_background_task(fetch_task)
                    break

                await _m()._cancel_background_task(fetch_task)
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
        _m().debug_print(f"❌ Camoufox fetch transport failed: {e}")
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
    proxy_stream = await _m().fetch_lmarena_stream_via_userscript_proxy(
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
    
    _m().debug_print(f"📫 Added task {task_id} to Proxy Queue. Waiting for Userscript...")

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
                _m().debug_print(f"❌ Proxy Task Error: {result['error']}")
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
        _m().debug_print(f"❌ Proxy Task {task_id} timed out. Is the Userscript running?")
        if task_id in proxy_pending_tasks:
            del proxy_pending_tasks[task_id]
        if task_id in [t['id'] for t in proxy_task_queue]:
            # Remove from queue if not picked up
            proxy_task_queue[:] = [t for t in proxy_task_queue if t['id'] != task_id]
        return None
    except Exception as e:
        _m().debug_print(f"❌ Proxy Task Exception: {e}")
        return None

    return None

async def push_proxy_chunk(jid, d) -> None:
    _touch_userscript_poll()

    job_id = str(jid or "").strip()
    job = _m()._USERSCRIPT_PROXY_JOBS.get(job_id)
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
                    job["upstream_fetch_started_at_monotonic"] = _m().time.monotonic()
            except Exception:
                pass

        if isinstance(status, int):
            job["status_code"] = int(status)
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()
            if not job.get("_proxy_status_logged"):
                job["_proxy_status_logged"] = True
                _m().debug_print(f"🦊 Camoufox proxy job {job_id[:8]} upstream status: {int(status)}")
        headers = d.get("headers")
        if isinstance(headers, dict):
            job["headers"] = headers
        error = d.get("error")
        if error:
            job["error"] = str(error)
            _m().debug_print(f"⚠️ Camoufox proxy job {job_id[:8]} error: {str(error)[:200]}")

        debug_obj = d.get("debug")
        if debug_obj and os.environ.get("LM_BRIDGE_PROXY_DEBUG"):
            try:
                dbg_text = json.dumps(debug_obj, ensure_ascii=False)
            except Exception:
                dbg_text = str(debug_obj)
            _m().debug_print(f"🦊 Camoufox proxy debug {job_id[:8]}: {dbg_text[:300]}")

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
            _m().debug_print(f"🦊 Camoufox proxy job {job_id[:8]} done")


async def camoufox_proxy_worker():
    """
    Internal Userscript-Proxy client backed by Camoufox.
    Maintains a SINGLE persistent browser instance to avoid crash loops and resource exhaustion.
    """
    # Mark the proxy as alive immediately
    _touch_userscript_poll()
    _m().debug_print("🦊 Camoufox proxy worker started (Singleton Mode).")

    browser_cm = None
    browser = None
    context = None
    page = None

    proxy_recaptcha_sitekey = _m().RECAPTCHA_SITEKEY
    proxy_recaptcha_action = _m().RECAPTCHA_ACTION
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
                        _m().debug_print("⚠️ Camoufox proxy page closed. Relaunching...")
                        needs_launch = True
                    elif not context.pages:
                        _m().debug_print("⚠️ Camoufox proxy context has no pages. Relaunching...")
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

                cfg = _m().get_config()
                recaptcha_sitekey, recaptcha_action = _m().get_recaptcha_settings(cfg)
                proxy_recaptcha_sitekey = recaptcha_sitekey
                proxy_recaptcha_action = recaptcha_action
                user_agent = _m().normalize_user_agent_value(cfg.get("user_agent"))
                
                headless_value = cfg.get("camoufox_proxy_headless", None)
                headless = bool(headless_value) if headless_value is not None else False
                launch_timeout = float(cfg.get("camoufox_proxy_launch_timeout_seconds", 90))
                launch_timeout = max(20.0, min(launch_timeout, 300.0))

                _m().debug_print(f"🦊 Camoufox proxy: launching browser (headless={headless})...")

                profile_dir = None
                try:
                    profile_dir_value = cfg.get("camoufox_proxy_user_data_dir")
                    if profile_dir_value:
                        profile_dir = Path(str(profile_dir_value)).expanduser()
                except Exception:
                    pass
                if profile_dir is None:
                    try:
                        profile_dir = Path(_m().CONFIG_FILE).with_name("grecaptcha")
                    except Exception:
                        pass

                persistent_pref = cfg.get("camoufox_proxy_persistent_context", None)
                want_persistent = bool(persistent_pref) if persistent_pref is not None else False
                
                persistent_context_enabled = False
                if want_persistent and isinstance(profile_dir, Path) and profile_dir.exists():
                    persistent_context_enabled = True
                    browser_cm = _m().AsyncCamoufox(
                        headless=headless,
                        main_world_eval=True,
                        persistent_context=True,
                        user_data_dir=str(profile_dir),
                    )
                else:
                    browser_cm = _m().AsyncCamoufox(headless=headless, main_world_eval=True)

                try:
                    browser = await asyncio.wait_for(browser_cm.__aenter__(), timeout=launch_timeout)
                except Exception as e:
                    _m().debug_print(f"⚠️ Camoufox launch failed ({type(e).__name__}): {e}")
                    if persistent_context_enabled:
                        _m().debug_print("⚠️ Retrying without persistence...")
                        try:
                            await browser_cm.__aexit__(None, None, None)
                        except Exception:
                            pass
                        persistent_context_enabled = False
                        browser_cm = _m().AsyncCamoufox(headless=headless, main_world_eval=True)
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
                            has_fresh_existing = not _m().is_arena_auth_token_expired(existing_auth, skew_seconds=0)
                        except Exception:
                            has_fresh_existing = True
                    
                    if not has_fresh_existing:
                        candidate = ""
                        try:
                            if _m().EPHEMERAL_ARENA_AUTH_TOKEN and not _m().is_arena_auth_token_expired(
                                _m().EPHEMERAL_ARENA_AUTH_TOKEN, skew_seconds=0
                            ):
                                candidate = str(_m().EPHEMERAL_ARENA_AUTH_TOKEN).strip()
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
                                    if _m().is_probably_valid_arena_auth_token(t) and not _m().is_arena_auth_token_expired(
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
                await _m()._maybe_apply_camoufox_window_mode(
                    page,
                    cfg,
                    mode_key="camoufox_proxy_window_mode",
                    marker="LMArenaBridge Camoufox Proxy",
                    headless=headless,
                )

                try:
                    _m().debug_print("🦊 Camoufox proxy: navigating to https://lmarena.ai/?mode=direct ...")
                    await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)
                    _m().debug_print("🦊 Camoufox proxy: navigation complete.")
                except Exception as e:
                    _m().debug_print(f"⚠️ Navigation warning: {e}")

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
                        _m().debug_print("🦊 Cloudflare challenge detected.")
                        await _m().click_turnstile(page)
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
                    _m()._capture_ephemeral_arena_auth_token_from_cookies(fresh_cookies)
                    _cfg = _m().get_config()
                    if _m()._upsert_browser_session_into_config(_cfg, fresh_cookies):
                        _m().save_config(_cfg)
                        _m().debug_print("🦊 Camoufox proxy: initial cookies saved to config.")
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
                    _m()._capture_ephemeral_arena_auth_token_from_cookies(cookies or [])
                    # Also persist cookies to config.json when capturing
                    _cfg = _m().get_config()
                    if _m()._upsert_browser_session_into_config(_cfg, cookies):
                        _m().save_config(_cfg)
                except Exception:
                    pass
                candidates: list[str] = []

                # First check for combined split cookies (.0 and .1)
                combined = _m()._combine_split_arena_auth_cookies(cookies)
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
                        if not _m().is_arena_auth_token_expired(value, skew_seconds=0):
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
                now = _m().time.time()
                if (now - float(last_signup_attempt_at or 0.0)) < float(min_interval_seconds):
                    return
                last_signup_attempt_at = now

                # First, give LMArena a chance to create an anonymous user itself (it already ships a
                # Turnstile-backed sign-up flow in the app). We just wait/poll for the auth cookie.
                try:
                    for _ in range(20):
                        cur = await _get_auth_cookie_value()
                        if cur and not _m().is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        try:
                            await _m().click_turnstile(page)
                        except Exception:
                            pass
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

                # If the cookie is missing but an auth session is still present in localStorage, recover it now.
                try:
                    recovered = await _m()._maybe_inject_arena_auth_cookie_from_localstorage(page, context)
                    if recovered and not _m().is_arena_auth_token_expired(recovered, skew_seconds=0):
                        return
                except Exception:
                    pass

                try:
                    cfg_now = _m().get_config()
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
                    await _m()._set_provisional_user_id_in_browser(
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
                        if cur and not _m().is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        try:
                            await _m().click_turnstile(page)
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
                        page.evaluate(render_turnstile_js, {"sitekey": _m().TURNSTILE_SITEKEY}),
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
                    _m().debug_print(f"⚠️ Camoufox proxy: Turnstile render failed (stage={stage} err={err[:120]})")
                    return

                started = _m().time.monotonic()
                try:
                    while (_m().time.monotonic() - started) < 130.0:
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
                            await _m().click_turnstile(page)
                        except Exception:
                            pass
                        await asyncio.sleep(1.0)
                finally:
                    try:
                        await page.evaluate(cleanup_turnstile_js, {"widgetId": widget_id})
                    except Exception:
                        pass

                if not token_value:
                    _m().debug_print("⚠️ Camoufox proxy: Turnstile mint failed (timeout).")
                    return

                try:
                    if provisional_user_id:
                        _m().debug_print(
                            f"🦊 Camoufox proxy: provisional_user_id (trunc): {provisional_user_id[:8]}...{provisional_user_id[-4:]}"
                        )
                    resp = await _m()._camoufox_proxy_signup_anonymous_user(
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
                _m().debug_print(f"🦊 Camoufox proxy: /nextjs-api/sign-up status {status}")

                # Some sign-up responses return the Supabase session JSON in the body instead of setting a cookie.
                # When that happens, encode it into the `arena-auth-prod-v1` cookie format and inject it.
                try:
                    body_text = str((resp or {}).get("body") or "") if isinstance(resp, dict) else ""
                except Exception:
                    body_text = ""
                if status >= 400 and body_text:
                    _m().debug_print(f"🦊 Camoufox proxy: /nextjs-api/sign-up body (trunc): {body_text[:200]}")
                if status == 400 and "User already exists" in body_text:
                    try:
                        await _m()._maybe_inject_arena_auth_cookie_from_localstorage(page, context)
                    except Exception:
                        pass
                try:
                    derived_cookie = _m().maybe_build_arena_auth_cookie_from_signup_response_body(body_text)
                except Exception:
                    derived_cookie = None
                if derived_cookie:
                    try:
                        if not _m().is_arena_auth_token_expired(derived_cookie, skew_seconds=0):
                            await context.add_cookies(
                                _arena_auth_cookie_specs(
                                    derived_cookie,
                                    page_url=str(getattr(page, "url", "") or ""),
                                )
                            )
                            _m()._capture_ephemeral_arena_auth_token_from_cookies(
                                [{"name": "arena-auth-prod-v1", "value": derived_cookie}]
                            )
                            _m().debug_print("🦊 Camoufox proxy: injected arena-auth cookie from sign-up response body.")
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
                        if cur and not _m().is_arena_auth_token_expired(cur, skew_seconds=0):
                            _m().debug_print("🦊 Camoufox proxy: acquired arena-auth-prod-v1 cookie (anonymous user).")
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
            job = _m()._USERSCRIPT_PROXY_JOBS.get(job_id)
            if not isinstance(job, dict):
                continue
            
            # Signal that a proxy worker picked up this job (used to avoid long hangs when no worker is running).
            try:
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
                if not job.get("picked_up_at_monotonic"):
                    job["picked_up_at_monotonic"] = _m().time.monotonic()
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

            _m().debug_print(f"🦊 Camoufox proxy: running job {job_id[:8]}...")
            
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
                            if _m().is_arena_auth_token_expired(browser_auth_cookie, skew_seconds=60):
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
                    _m().debug_print("🦊 Camoufox proxy: using valid browser auth cookie (job token is empty or invalid).")
            except Exception:
                pass

            # If the job did not provide a usable auth cookie, ensure the browser session has one.
            try:
                current_cookie = await _get_auth_cookie_value()
            except Exception:
                current_cookie = ""
            if current_cookie:
                try:
                    expired = _m().is_arena_auth_token_expired(current_cookie, skew_seconds=0)
                except Exception:
                    expired = False
                _m().debug_print(f"🦊 Camoufox proxy: arena-auth cookie present (len={len(current_cookie)} expired={expired})")
            else:
                _m().debug_print("🦊 Camoufox proxy: arena-auth cookie missing")
            try:
                needs_signup = (not current_cookie) or _m().is_arena_auth_token_expired(current_cookie, skew_seconds=0)
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
                        job["upstream_started_at_monotonic"] = _m().time.monotonic()
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
                            "sitekeyV2": _m().RECAPTCHA_V2_SITEKEY,
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
            _m().debug_print("🦊 Camoufox proxy worker cancelled.")
            if browser_cm:
                try:
                    await browser_cm.__aexit__(None, None, None)
                except Exception:
                    pass
            return
        except Exception as e:
            _m().debug_print(f"⚠️ Camoufox proxy worker exception: {e}")
            await asyncio.sleep(5.0)
            # Mark for relaunch
            browser = None
            page = None
