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
            request = httpx.Request(self._method, self._url or "https://arena.ai/")
            response = httpx.Response(self.status_code or 502, request=request, content=self._text.encode("utf-8"))
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=request, response=response)


def _touch_userscript_poll(now: Optional[float] = None) -> None:
    """
    Update userscript-proxy "last seen" timestamps.
    """
    ts = float(now if now is not None else _m().time.time())
    _m().USERSCRIPT_PROXY_LAST_POLL_AT = ts
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
    try:
        last = max(float(_m().USERSCRIPT_PROXY_LAST_POLL_AT or 0.0), float(_m().last_userscript_poll or 0.0))
    except Exception:
        last = float(_m().USERSCRIPT_PROXY_LAST_POLL_AT or 0.0)
    try:
        delta = float(_m().time.time()) - float(last)
    except Exception:
        delta = 999999.0
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
        elif (not done) and (not picked_up) and (now - created_at) > ttl_seconds:
            expired.append(job_id)
        elif (not done) and picked_up and (now - created_at) > (ttl_seconds * 5):
            expired.append(job_id)
    for job_id in expired:
        _m()._USERSCRIPT_PROXY_JOBS.pop(job_id, None)


def _mark_userscript_proxy_inactive() -> None:
    _m().USERSCRIPT_PROXY_LAST_POLL_AT = 0.0
    _m().last_userscript_poll = 0.0


async def _finalize_userscript_proxy_job(job_id: str, *, error: Optional[str] = None, remove: bool = False) -> None:
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
        self._url = "https://arena.ai/"

    @property
    def status_code(self) -> int:
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
    """
    text = str(url or "").strip()
    if not text:
        return _ARENA_ORIGIN
    try:
        parts = urlsplit(text)
    except Exception:
        parts = None

    host = ""
    if parts and parts.scheme and parts.netloc:
        host = str(parts.netloc or "").split("@")[-1].split(":")[0].lower()
    if not host:
        host = text.split("/")[0].split("@")[-1].split(":")[0].lower()
    return _ARENA_HOST_TO_ORIGIN.get(host, _ARENA_ORIGIN)


def _arena_origin_candidates(url: Optional[str] = None) -> list[str]:
    """Return `[primary, secondary]` origins, preferring the detected origin but always including both."""
    primary = _detect_arena_origin(url)
    secondary = _LMARENA_ORIGIN if primary == _ARENA_ORIGIN else _ARENA_ORIGIN
    return [primary, secondary]


def _arena_auth_cookie_specs(token: str, *, page_url: Optional[str] = None) -> list[dict]:
    """
    Build host-only `arena-auth-prod-v1` cookie specs for both arena.ai and lmarena.ai.
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
    """
    value = str(provisional_user_id or "").strip()
    if not value:
        return []
    specs: list[dict] = []
    for origin in _arena_origin_candidates(page_url):
        specs.append({"name": "provisional_user_id", "value": value, "url": origin, "path": "/"})
    for domain in (".lmarena.ai", ".arena.ai"):
        specs.append({"name": "provisional_user_id", "value": value, "domain": domain})
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
        "phase": "queued",
        "picked_up_at_monotonic": None,
        "upstream_started_at_monotonic": None,
        "upstream_fetch_started_at_monotonic": None,
        "url": str(url),
        "method": str(http_method or "POST"),
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
    headless: bool = False,
) -> Optional[BrowserFetchStreamResponse]:
    # Placeholder for the actual implementation in main.py
    pass


async def fetch_lmarena_stream_via_camoufox(
    http_method: str,
    url: str,
    payload: dict,
    auth_token: str,
    timeout_seconds: int = 120,
) -> Optional[BrowserFetchStreamResponse]:
    # Placeholder for the actual implementation in main.py
    pass
