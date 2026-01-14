import asyncio
import json
import time
import uuid
import html
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from starlette.responses import HTMLResponse, RedirectResponse, StreamingResponse

from .web_ui import render_dashboard_page, render_login_page


def build_router(core) -> APIRouter:  # noqa: ANN001
    router = APIRouter()

    # --- UI Endpoints (Login/Dashboard) ---

    @router.get("/", response_class=HTMLResponse)
    async def root_redirect():
        return RedirectResponse(url="/dashboard")

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: Optional[str] = None):
        if await core.get_current_session(request):
            return RedirectResponse(url="/dashboard")
        return render_login_page(error=bool(error))

    @router.post("/login")
    async def login_submit(response: Response, password: str = Form(...)):  # noqa: ARG001
        config = core.get_config()
        if password == config.get("password"):
            session_id = str(uuid.uuid4())
            core.dashboard_sessions[session_id] = "admin"
            response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(key="session_id", value=session_id, httponly=True)
            return response
        return RedirectResponse(url="/login?error=1", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/logout")
    async def logout(request: Request, response: Response):  # noqa: ARG001
        session_id = request.cookies.get("session_id")
        if session_id in core.dashboard_sessions:
            del core.dashboard_sessions[session_id]
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("session_id")
        return response

    @router.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(session: str = Depends(core.get_current_session)):
        if not session:
            return RedirectResponse(url="/login")

        try:
            config = core.get_config()
            models = core.get_models()
        except Exception as e:
            core.debug_print(f"❌ Error loading dashboard data: {e}")
            safe_error = html.escape(str(e))
            return HTMLResponse(
                f"""
                <html><body style="font-family: sans-serif; padding: 40px; text-align: center;">
                    <h1>⚠️ Dashboard Error</h1>
                    <p>Failed to load configuration: {safe_error}</p>
                    <p><a href="/logout">Logout</a> | <a href="/dashboard">Retry</a></p>
                </body></html>
            """,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        text_models = [m for m in models if m.get("capabilities", {}).get("outputCapabilities", {}).get("text")]

        token_status = "✅Configured" if config.get("auth_token") else "❌Not Set"
        token_class = "status-good" if config.get("auth_token") else "status-bad"

        cf_status = "✅Configured" if config.get("cf_clearance") else "❌Not Set"
        cf_class = "status-good" if config.get("cf_clearance") else "status-bad"

        return render_dashboard_page(
            config=config,
            text_models=text_models,
            model_usage_stats=core.model_usage_stats,
            token_status=token_status,
            token_class=token_class,
            cf_status=cf_status,
            cf_class=cf_class,
        )

    @router.post("/update-auth-token")
    async def update_auth_token(session: str = Depends(core.get_current_session), auth_token: str = Form(...)):
        if not session:
            return RedirectResponse(url="/login")
        config = core.get_config()
        config["auth_token"] = auth_token.strip()
        core.save_config(config, preserve_auth_tokens=False)
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/create-key")
    async def create_key(session: str = Depends(core.get_current_session), name: str = Form(...), rpm: int = Form(...)):
        if not session:
            return RedirectResponse(url="/login")
        try:
            config = core.get_config()
            new_key = {
                "name": name.strip(),
                "key": "sk" + f"-lmab-{uuid.uuid4()}",
                "rpm": max(1, min(rpm, 1000)),
                "created": int(time.time()),
            }
            config["api_keys"].append(new_key)
            core.save_config(config, preserve_api_keys=False)
        except Exception as e:
            core.debug_print(f"❌ Error creating key: {e}")
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/delete-key")
    async def delete_key(session: str = Depends(core.get_current_session), key_id: str = Form(...)):
        if not session:
            return RedirectResponse(url="/login")
        try:
            config = core.get_config()
            config["api_keys"] = [k for k in config["api_keys"] if k["key"] != key_id]
            core.save_config(config, preserve_api_keys=False)
        except Exception as e:
            core.debug_print(f"❌ Error deleting key: {e}")
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/add-auth-token")
    async def add_auth_token(session: str = Depends(core.get_current_session), new_auth_token: str = Form(...)):
        if not session:
            return RedirectResponse(url="/login")
        try:
            config = core.get_config()
            token = new_auth_token.strip()
            if token and token not in config.get("auth_tokens", []):
                if "auth_tokens" not in config:
                    config["auth_tokens"] = []
                config["auth_tokens"].append(token)
                core.save_config(config, preserve_auth_tokens=False)
        except Exception as e:
            core.debug_print(f"❌ Error adding auth token: {e}")
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/delete-auth-token")
    async def delete_auth_token(session: str = Depends(core.get_current_session), token_index: int = Form(...)):
        if not session:
            return RedirectResponse(url="/login")
        try:
            config = core.get_config()
            auth_tokens = config.get("auth_tokens", [])
            if 0 <= token_index < len(auth_tokens):
                auth_tokens.pop(token_index)
                config["auth_tokens"] = auth_tokens
                core.save_config(config, preserve_auth_tokens=False)
        except Exception as e:
            core.debug_print(f"❌ Error deleting auth token: {e}")
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/refresh-tokens")
    async def refresh_tokens(session: str = Depends(core.get_current_session)):
        if not session:
            return RedirectResponse(url="/login")
        try:
            await core.get_initial_data()
        except Exception as e:
            core.debug_print(f"❌ Error refreshing tokens: {e}")
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    # --- Userscript Proxy Support ---

    @router.post("/api/v1/userscript/poll")
    async def userscript_poll(request: Request):
        core._userscript_proxy_check_secret(request)
        core._touch_userscript_poll(time.time())

        try:
            data = await request.json()
        except Exception:
            data = {}

        cfg = core.get_config()
        timeout_seconds = data.get("timeout_seconds")
        if timeout_seconds is None:
            timeout_seconds = cfg.get("userscript_proxy_poll_timeout_seconds", 25)
        try:
            timeout_seconds = int(timeout_seconds)
        except Exception:
            timeout_seconds = 25
        timeout_seconds = max(0, min(timeout_seconds, 60))

        core._PROXY_SERVICE.cleanup_jobs(cfg)

        queue = core._PROXY_SERVICE.queue
        end = time.time() + float(timeout_seconds)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                return Response(status_code=status.HTTP_204_NO_CONTENT)
            try:
                job_id = await asyncio.wait_for(queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                return Response(status_code=status.HTTP_204_NO_CONTENT)

            job = core._USERSCRIPT_PROXY_JOBS.get(str(job_id))
            if not isinstance(job, dict):
                continue
            try:
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
            except Exception:
                pass
            return {"job_id": str(job_id), "payload": job.get("payload") or {}}

    @router.post("/api/v1/userscript/push")
    async def userscript_push(request: Request):
        core._userscript_proxy_check_secret(request)

        try:
            data = await request.json()
        except Exception:
            data = {}

        job_id = str(data.get("job_id") or "").strip()
        if not job_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing job_id")

        job = core._USERSCRIPT_PROXY_JOBS.get(job_id)
        if not isinstance(job, dict):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown job_id")

        status_code = data.get("status")
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

    # --- OpenAI Compatible API Endpoints ---

    @router.get("/api/v1/health")
    async def health_check():
        try:
            models = core.get_models()
            config = core.get_config()

            has_cf_clearance = bool(config.get("cf_clearance"))
            has_models = len(models) > 0
            has_api_keys = len(config.get("api_keys", [])) > 0

            status_str = "healthy" if (has_cf_clearance and has_models) else "degraded"

            return {
                "status": status_str,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": {
                    "cf_clearance": has_cf_clearance,
                    "models_loaded": has_models,
                    "model_count": len(models),
                    "api_keys_configured": has_api_keys,
                },
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e),
            }

    @router.get("/api/v1/models")
    async def list_models(api_key: dict = Depends(core.rate_limit_api_key)):  # noqa: ARG001
        try:
            models = core.get_models()

            valid_models = [
                m
                for m in models
                if (
                    m.get("capabilities", {}).get("outputCapabilities", {}).get("text")
                    or m.get("capabilities", {}).get("outputCapabilities", {}).get("search")
                    or m.get("capabilities", {}).get("outputCapabilities", {}).get("image")
                )
                and m.get("organization")
            ]

            return {
                "object": "list",
                "data": [
                    {
                        "id": model.get("publicName"),
                        "object": "model",
                        "created": int(time.time()),
                        "owned_by": model.get("organization", "lmarena"),
                    }
                    for model in valid_models
                    if model.get("publicName")
                ],
            }
        except Exception as e:
            core.debug_print(f"❌ Error listing models: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to load models: {str(e)}")

    @router.get("/api/v1/_debug/stream")
    async def debug_stream(api_key: dict = Depends(core.rate_limit_api_key)):  # noqa: ARG001
        async def _gen():
            yield ": keep-alive\n\n"
            await asyncio.sleep(0.05)
            yield 'data: {"ok":true}\n\n'
            yield "data: [DONE]\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    @router.post("/api/v1/chat/completions")
    async def api_chat_completions(request: Request, api_key: dict = Depends(core.rate_limit_api_key)):
        return await core.api_chat_completions(request, api_key)

    return router
