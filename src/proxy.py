import asyncio
import json
import time
import uuid
from typing import Any, Optional

import httpx

from .stream_response import iter_queue_lines, raise_for_status_like_httpx


class UserscriptProxyStreamResponse:
    """httpx-like streaming response wrapper backed by an in-memory job queue."""

    def __init__(self, service: "ProxyService", job_id: str, timeout_seconds: int = 120) -> None:
        self._service = service
        self.job_id = str(job_id)
        self._status_code: int = 200
        self._headers: dict = {}
        self._timeout_seconds = int(timeout_seconds or 120)
        self._method = "POST"
        self._url = "https://lmarena.ai/"

    @property
    def status_code(self) -> int:
        job = self._service.get_job(self.job_id)
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
        job = self._service.get_job(self.job_id)
        if isinstance(job, dict):
            headers = job.get("headers")
            if isinstance(headers, dict):
                return headers
        return self._headers

    @headers.setter
    def headers(self, value: dict) -> None:
        self._headers = value if isinstance(value, dict) else {}

    async def __aenter__(self) -> "UserscriptProxyStreamResponse":
        job = self._service.get_job(self.job_id)
        if not isinstance(job, dict):
            self.status_code = 503
            return self

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

    async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        await self.aclose()
        return False

    async def aclose(self) -> None:
        return None

    async def aiter_lines(self):
        job = self._service.get_job(self.job_id)
        if not isinstance(job, dict):
            return

        q = job.get("lines_queue")
        done_event = job.get("done_event")
        if not isinstance(q, asyncio.Queue) or not isinstance(done_event, asyncio.Event):
            return

        deadline = time.time() + float(max(5, self._timeout_seconds))

        def _on_deadline() -> None:
            if done_event.is_set() or job.get("done"):
                return
            job["error"] = job.get("error") or "userscript proxy timeout"
            job["done"] = True
            done_event.set()

        async for line in iter_queue_lines(
            q,
            done_event=done_event,
            deadline_at=deadline,
            time_fn=time.time,
            min_wait_seconds=0.25,
            max_wait_seconds=2.0,
            on_deadline=_on_deadline,
        ):
            yield line

    async def aread(self) -> bytes:
        job = self._service.get_job(self.job_id)
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
        job = self._service.get_job(self.job_id)
        if isinstance(job, dict) and job.get("error"):
            raise_for_status_like_httpx(
                status_code=503,
                method=self._method,
                url=self._url,
                message="Userscript proxy error",
                content=str(job.get("error")).encode("utf-8"),
            )
        status = int(self.status_code or 0)
        if status == 0 or status >= 400:
            raise_for_status_like_httpx(
                status_code=status,
                method=self._method,
                url=self._url,
                message=f"HTTP {status}",
            )


class ProxyService:
    """
    Userscript proxy job queue + lifecycle.

    This module intentionally has no FastAPI imports; route handlers should live elsewhere and call these methods.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._jobs: dict[str, dict[str, Any]] = {}
        self.last_poll_at: float = 0.0

    @property
    def queue(self) -> asyncio.Queue[str]:
        return self._queue

    @property
    def jobs(self) -> dict[str, dict[str, Any]]:
        return self._jobs

    def touch_poll(self, now: Optional[float] = None) -> None:
        self.last_poll_at = float(now if now is not None else time.time())

    def is_active(self, config: Optional[dict] = None, *, now: Optional[float] = None) -> bool:
        cfg = config or {}
        poll_timeout = 25
        try:
            poll_timeout = int(cfg.get("userscript_proxy_poll_timeout_seconds", 25))
        except Exception:
            poll_timeout = 25
        active_window = max(10, min(poll_timeout + 10, 90))

        last = float(self.last_poll_at or 0.0)
        ts_now = float(now if now is not None else time.time())
        delta = ts_now - last
        if delta < 0:
            return False
        return delta <= float(active_window)

    def get_job(self, job_id: str) -> Optional[dict]:
        return self._jobs.get(str(job_id))

    def cleanup_jobs(self, config: Optional[dict] = None, *, now: Optional[float] = None) -> None:
        cfg = config or {}
        ttl_seconds = 90
        try:
            ttl_seconds = int(cfg.get("userscript_proxy_job_ttl_seconds", 90))
        except Exception:
            ttl_seconds = 90
        ttl_seconds = max(10, min(ttl_seconds, 600))

        ts_now = float(now if now is not None else time.time())
        expired: list[str] = []
        for job_id, job in list(self._jobs.items()):
            created_at = float(job.get("created_at") or 0.0)
            done = bool(job.get("done"))
            picked_up = False
            try:
                picked_up_event = job.get("picked_up_event")
                if isinstance(picked_up_event, asyncio.Event):
                    picked_up = bool(picked_up_event.is_set())
            except Exception:
                picked_up = False

            if done and (ts_now - created_at) > ttl_seconds:
                expired.append(job_id)
            elif (not done) and (not picked_up) and (ts_now - created_at) > ttl_seconds:
                expired.append(job_id)
            elif (not done) and picked_up and (ts_now - created_at) > (ttl_seconds * 5):
                expired.append(job_id)

        for job_id in expired:
            self._jobs.pop(job_id, None)

    async def enqueue_stream_job(
        self,
        *,
        url: str,
        http_method: str,
        payload: dict,
        auth_token: str,
        timeout_seconds: int = 120,
        config: Optional[dict] = None,
    ) -> UserscriptProxyStreamResponse:
        cfg = config or {}
        self.cleanup_jobs(cfg)

        job_id = str(uuid.uuid4())
        lines_queue: asyncio.Queue = asyncio.Queue()
        done_event: asyncio.Event = asyncio.Event()
        status_event: asyncio.Event = asyncio.Event()
        picked_up_event: asyncio.Event = asyncio.Event()

        sitekey = str(cfg.get("recaptcha_sitekey") or "").strip()
        action = str(cfg.get("recaptcha_action") or "").strip()

        job = {
            "created_at": time.time(),
            "job_id": job_id,
            "url": str(url),
            "method": str(http_method or "POST"),
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
            "_proxy_buffer": "",
        }
        self._jobs[job_id] = job
        await self._queue.put(job_id)
        return UserscriptProxyStreamResponse(self, job_id, timeout_seconds=timeout_seconds)

    async def poll_next_job(self, *, timeout_seconds: float) -> Optional[dict[str, Any]]:
        end = time.time() + float(timeout_seconds)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                return None
            try:
                job_id = await asyncio.wait_for(self._queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                return None

            job = self._jobs.get(str(job_id))
            if not isinstance(job, dict):
                continue
            try:
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
            except Exception:
                pass
            return {"job_id": str(job_id), "payload": job.get("payload") or {}}

    async def push_job_update(
        self,
        *,
        job_id: str,
        status: Optional[int] = None,
        headers: Optional[dict] = None,
        error: Optional[str] = None,
        lines: Optional[list[str]] = None,
        done: bool = False,
    ) -> bool:
        job = self._jobs.get(str(job_id))
        if not isinstance(job, dict):
            return False

        if isinstance(status, int):
            job["status_code"] = int(status)
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()
        if isinstance(headers, dict):
            job["headers"] = headers
        if error:
            job["error"] = str(error)

        lines_queue = job.get("lines_queue")
        if isinstance(lines_queue, asyncio.Queue) and lines:
            for line in lines:
                if line is None:
                    continue
                await lines_queue.put(str(line))

        if done:
            job["done"] = True
            done_event = job.get("done_event")
            if isinstance(done_event, asyncio.Event):
                done_event.set()
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()
            if isinstance(lines_queue, asyncio.Queue):
                await lines_queue.put(None)

        return True

    async def push_proxy_chunk(self, *, job_id: str, payload: dict) -> None:
        """
        Helper for internal proxy workers that emit arbitrary chunk strings.
        Normalizes newlines and splits into per-line entries.
        """
        job = self._jobs.get(str(job_id))
        if not isinstance(job, dict):
            return

        status = payload.get("status")
        if isinstance(status, int):
            job["status_code"] = int(status)
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()

        headers = payload.get("headers")
        if isinstance(headers, dict):
            job["headers"] = headers

        error = payload.get("error")
        if error:
            job["error"] = str(error)

        buffer = str(job.get("_proxy_buffer") or "")
        raw_lines = payload.get("lines") or []
        if isinstance(raw_lines, list):
            for raw in raw_lines:
                if raw is None:
                    continue
                buffer += f"{raw}\n"

        buffer = buffer.replace("\r\n", "\n").replace("\r", "\n")
        parts = buffer.split("\n")
        buffer = parts.pop() if parts else ""
        job["_proxy_buffer"] = buffer

        lines_queue = job.get("lines_queue")
        if isinstance(lines_queue, asyncio.Queue):
            for part in parts:
                part = str(part).strip()
                if part:
                    await lines_queue.put(part)

        if bool(payload.get("done")):
            remainder = str(job.get("_proxy_buffer") or "").strip()
            if remainder and isinstance(lines_queue, asyncio.Queue):
                await lines_queue.put(remainder)
            job["_proxy_buffer"] = ""
            job["done"] = True
            done_event = job.get("done_event")
            if isinstance(done_event, asyncio.Event):
                done_event.set()
            status_event = job.get("status_event")
            if isinstance(status_event, asyncio.Event):
                status_event.set()
            if isinstance(lines_queue, asyncio.Queue):
                await lines_queue.put(None)
 
_PROXY_SERVICE = ProxyService()
