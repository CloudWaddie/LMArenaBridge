import time
import asyncio
import uuid
import json
import httpx
import os
from typing import Optional
from fastapi import Request, HTTPException

try:
    from . import globals
    from . import config
    from . import auth
    from .utils import debug_print, BrowserFetchStreamResponse
except ImportError:
    import globals
    import config
    import auth
    from utils import debug_print, BrowserFetchStreamResponse


def _touch_userscript_poll(now: Optional[float] = None) -> None:
    """
    Update userscript-proxy "last seen" timestamps.

    The bridge supports both an external userscript poller and an internal Camoufox-backed poller.
    Keep both timestamps in sync so strict-model routing can reliably detect proxy availability.
    """
    ts = float(now if now is not None else time.time())
    globals.USERSCRIPT_PROXY_LAST_POLL_AT = ts
    # Legacy timestamp used by older code paths/tests.
    globals.last_userscript_poll = ts


def _get_userscript_proxy_queue() -> asyncio.Queue:
    if globals._USERSCRIPT_PROXY_QUEUE is None:
        globals._USERSCRIPT_PROXY_QUEUE = asyncio.Queue()
    return globals._USERSCRIPT_PROXY_QUEUE


def _userscript_proxy_is_active(cfg: Optional[dict] = None) -> bool:
    cfg = cfg or config.get_config()
    poll_timeout = 25
    try:
        poll_timeout = int(cfg.get("userscript_proxy_poll_timeout_seconds", 25))
    except Exception:
        poll_timeout = 25
    active_window = max(10, min(poll_timeout + 10, 90))
    # Back-compat: some callers/tests still update the legacy `last_userscript_poll` timestamp.
    try:
        last = max(float(globals.USERSCRIPT_PROXY_LAST_POLL_AT or 0.0), float(globals.last_userscript_poll or 0.0))
    except Exception:
        last = float(globals.USERSCRIPT_PROXY_LAST_POLL_AT or 0.0)
    try:
        delta = float(time.time()) - float(last)
    except Exception:
        delta = 999999.0
    # Guard against clock skew / patched clocks in tests: a "last poll" timestamp in the future is not active.
    if delta < 0:
        return False
    return delta <= float(active_window)


def _userscript_proxy_check_secret(request: Request) -> None:
    cfg = config.get_config()
    secret = str(cfg.get("userscript_proxy_secret") or "").strip()
    if secret and request.headers.get("X-LMBridge-Secret") != secret:
        raise HTTPException(status_code=401, detail="Invalid userscript proxy secret")


def _cleanup_userscript_proxy_jobs(cfg: Optional[dict] = None) -> None:
    cfg = cfg or config.get_config()
    ttl_seconds = 90
    try:
        ttl_seconds = int(cfg.get("userscript_proxy_job_ttl_seconds", 90))
    except Exception:
        ttl_seconds = 90
    ttl_seconds = max(10, min(ttl_seconds, 600))

    now = time.time()
    expired: list[str] = []
    for job_id, job in list(globals._USERSCRIPT_PROXY_JOBS.items()):
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
        globals._USERSCRIPT_PROXY_JOBS.pop(job_id, None)


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
        job = globals._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
        job = globals._USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if isinstance(job, dict):
            headers = job.get("headers")
            if isinstance(headers, dict):
                return headers
        return self._headers

    @headers.setter
    def headers(self, value: dict) -> None:
        self._headers = value if isinstance(value, dict) else {}

    async def __aenter__(self):
        job = globals._USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if not isinstance(job, dict):
            self.status_code = 503
            return self
        # Give the proxy a window to report the upstream HTTP status before we snapshot it.
        status_event = job.get("status_event")
        if isinstance(status_event, asyncio.Event) and not status_event.is_set():
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
        job = globals._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
        job = globals._USERSCRIPT_PROXY_JOBS.get(self.job_id)
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
        job = globals._USERSCRIPT_PROXY_JOBS.get(self.job_id)
        if isinstance(job, dict) and job.get("error"):
            request = httpx.Request(self._method, self._url)
            response = httpx.Response(503, request=request, content=str(job.get("error")).encode("utf-8"))
            raise httpx.HTTPStatusError("Userscript proxy error", request=request, response=response)
        status = int(self.status_code or 0)
        if status == 0 or status >= 400:
            request = httpx.Request(self._method, self._url)
            response = httpx.Response(status or 502, request=request)
            raise httpx.HTTPStatusError(f"HTTP {status}", request=request, response=response)


async def fetch_lmarena_stream_via_userscript_proxy(
    http_method: str,
    url: str,
    payload: dict,
    timeout_seconds: int = 120,
    auth_token: str = "",
) -> Optional[UserscriptProxyStreamResponse]:
    cfg = config.get_config()
    _cleanup_userscript_proxy_jobs(cfg)

    job_id = str(uuid.uuid4())
    lines_queue: asyncio.Queue = asyncio.Queue()
    done_event: asyncio.Event = asyncio.Event()
    status_event: asyncio.Event = asyncio.Event()
    picked_up_event: asyncio.Event = asyncio.Event()

    sitekey, action = auth.get_recaptcha_settings(cfg)
    job = {
        "created_at": time.time(),
        "job_id": job_id,
        "url": str(url),
        "method": str(http_method or "POST"),
        # Per-request auth token (do not mutate persisted config). The proxy worker uses this to set
        # the `arena-auth-prod-v1` cookie before executing the in-page fetch.
        "arena_auth_token": str(auth_token or "").strip(),
        "recaptcha_sitekey": sitekey,
        "recaptcha_action": action,
        "payload": {
            "url": str(url),
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
    globals._USERSCRIPT_PROXY_JOBS[job_id] = job
    await _get_userscript_proxy_queue().put(job_id)
    return UserscriptProxyStreamResponse(job_id, timeout_seconds=timeout_seconds)


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
    return None

async def push_proxy_chunk(jid, d) -> None:
    _touch_userscript_poll()

    job_id = str(jid or "").strip()
    job = globals._USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        return

    if isinstance(d, dict):
        status = d.get("status")
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
