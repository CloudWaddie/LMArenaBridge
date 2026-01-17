import time
import json
import asyncio
from fastapi import APIRouter, Request, HTTPException

try:
    from .. import globals
    from .. import proxy
    from ..utils import debug_print
except ImportError:
    import globals
    import proxy
    from utils import debug_print

router = APIRouter()

@router.get("/proxy/poll")
async def get_proxy_task(request: Request):
    """
    Userscript polls this endpoint to get new tasks (LMArena fetches) to execute in-page.
    """
    proxy._userscript_proxy_check_secret(request)
    proxy._touch_userscript_poll()

    try:
        # Long poll: wait for a job to appear in the queue
        job_id = await asyncio.wait_for(proxy._get_userscript_proxy_queue().get(), timeout=25.0)
    except asyncio.TimeoutError:
        return {"job": None}

    job = globals._USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        # Job expired or invalid
        return {"job": None}

    picked_up_event = job.get("picked_up_event")
    if isinstance(picked_up_event, asyncio.Event):
        picked_up_event.set()

    debug_print(f"📫 Userscript proxy picked up job {job_id}")
    # Return the job details to the userscript
    # The userscript will execute `fetch(job.url, job.options)`
    return {
        "job": {
            "id": job_id,
            "url": job.get("url"),
            "method": job.get("method"),
            "headers": job.get("payload", {}).get("headers"),
            "body": job.get("payload", {}).get("body"),
            # Pass the auth token so the userscript can set the cookie before fetching.
            "arena_auth_token": job.get("arena_auth_token"),
            "recaptcha_sitekey": job.get("recaptcha_sitekey"),
            "recaptcha_action": job.get("recaptcha_action"),
        }
    }


@router.post("/proxy/result")
async def post_proxy_result(request: Request):
    """
    Userscript posts the final result (status, headers, body) of a job here.
    """
    proxy._userscript_proxy_check_secret(request)
    proxy._touch_userscript_poll()

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    job_id = str(data.get("id") or "").strip()
    job = globals._USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        return {"status": "ignored"}

    if job.get("done"):
        return {"status": "already_done"}

    # Update job with final status/error
    if data.get("error"):
        job["error"] = data.get("error")

    status = data.get("status")
    if isinstance(status, int):
        job["status_code"] = status

    headers = data.get("headers")
    if isinstance(headers, dict):
        job["headers"] = headers

    # Push a final chunk if body is provided (buffered mode fallback)
    body = data.get("body")
    if isinstance(body, str) and body:
        q = job.get("lines_queue")
        if isinstance(q, asyncio.Queue):
            await q.put(body)

    # Mark done
    job["done"] = True

    status_event = job.get("status_event")
    if isinstance(status_event, asyncio.Event):
        status_event.set()

    done_event = job.get("done_event")
    if isinstance(done_event, asyncio.Event):
        done_event.set()

    debug_print(f"✅ Userscript proxy finished job {job_id}")
    return {"status": "ok"}


@router.post("/proxy/chunk")
async def post_proxy_chunk(request: Request):
    """
    Userscript posts streaming chunks (text lines) here.
    """
    proxy._userscript_proxy_check_secret(request)
    proxy._touch_userscript_poll()

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    job_id = str(data.get("id") or "").strip()
    job = globals._USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        return {"status": "ignored"}

    if job.get("done"):
        return {"status": "already_done"}

    # Capture upstream status/headers from the first chunk or metadata
    if data.get("status"):
        try:
            job["status_code"] = int(data.get("status"))
        except Exception:
            pass
    if data.get("headers") and isinstance(data.get("headers"), dict):
        job["headers"] = data.get("headers")

    status_event = job.get("status_event")
    if isinstance(status_event, asyncio.Event) and not status_event.is_set():
        if job.get("status_code") or data.get("meta"):
            status_event.set()

    chunk = data.get("chunk")
    if chunk is not None:
        q = job.get("lines_queue")
        if isinstance(q, asyncio.Queue):
            await q.put(str(chunk))

    if data.get("done"):
        job["done"] = True
        if isinstance(status_event, asyncio.Event):
            status_event.set()
        done_event = job.get("done_event")
        if isinstance(done_event, asyncio.Event):
            done_event.set()

    return {"status": "ok"}
