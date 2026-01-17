import asyncio
import time
from http import HTTPStatus
from typing import AsyncIterator, Callable, Optional

import httpx


async def iter_queue_lines(
    queue: asyncio.Queue,
    *,
    done_event: Optional[asyncio.Event] = None,
    poll_timeout_seconds: float = 1.0,
    deadline_at: Optional[float] = None,
    time_fn: Optional[Callable[[], float]] = None,
    min_wait_seconds: float = 0.25,
    max_wait_seconds: float = 2.0,
    on_deadline: Optional[Callable[[], None]] = None,
) -> AsyncIterator[str]:
    """
    Yield newline-delimited chunks from an asyncio.Queue until completion.

    Completion conditions:
    - `None` item is received (sentinel)
    - `done_event` is set and the queue is empty
    - `deadline_at` is reached (optional), triggering `on_deadline` before stopping
    """
    if time_fn is None:
        time_fn = time.time

    while True:
        try:
            if isinstance(done_event, asyncio.Event) and done_event.is_set() and queue.empty():
                break
        except Exception:
            pass

        timeout = float(poll_timeout_seconds or 1.0)
        if deadline_at is not None:
            remaining = float(deadline_at) - float(time_fn())
            if remaining <= 0:
                if callable(on_deadline):
                    on_deadline()
                break
            timeout = max(float(min_wait_seconds), min(float(max_wait_seconds), remaining))

        try:
            item = await asyncio.wait_for(queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            continue

        if item is None:
            break
        yield str(item)


def raise_for_status_like_httpx(
    *,
    status_code: int,
    method: str,
    url: str,
    message: str,
    content: bytes = b"",
    fallback_status: int = HTTPStatus.BAD_GATEWAY,
    default_url: str = "https://lmarena.ai/",
) -> None:
    request = httpx.Request(str(method or "POST"), str(url or default_url))
    response = httpx.Response(int(status_code or int(fallback_status)), request=request, content=content or b"")
    raise httpx.HTTPStatusError(str(message or "HTTP error"), request=request, response=response)

