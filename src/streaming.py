import asyncio
import json
import time
from contextlib import suppress
from typing import Any, Optional, AsyncIterator, List
from pathlib import Path
from http import HTTPStatus

import httpx
from camoufox.async_api import AsyncCamoufox

from .browser_automation import (
    build_lmarena_context_cookies,
    extract_lmarena_cookie_values,
    maybe_add_lmarena_cookies_to_persistent_context,
    maybe_add_webdriver_stealth_script,
    maybe_capture_and_persist_lmarena_session,
)
from .stream_response import iter_queue_lines, raise_for_status_like_httpx

# Shared constants and helpers for browser-based fetch transports

SSE_KEEPALIVE = ": keep-alive\n\n"
SSE_DONE = "data: [DONE]\n\n"

FETCH_SCRIPT = """async ({url, method, body, extraHeaders, timeoutMs}) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
    try {
        const res = await fetch(url, {
            method,
            headers: { 'content-type': 'text/plain;charset=UTF-8', ...extraHeaders },
            body,
            credentials: 'include',
            signal: controller.signal
        });
        const headers = {};
        try {
            if (res.headers && typeof res.headers.forEach === 'function') {
                res.headers.forEach((value, key) => { headers[key] = value; });
            }
        } catch (e) {}
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
        return { status: """ + str(HTTPStatus.BAD_GATEWAY.value) + """, headers: {}, text: 'FETCH_ERROR:' + String(e) };
    } finally {
        clearTimeout(timer);
    }
}"""


def is_recaptcha_validation_failed(status: int, text: object) -> bool:
    if int(status or 0) != HTTPStatus.FORBIDDEN:
        return False
    if not isinstance(text, str) or not text:
        return False
    try:
        body = json.loads(text)
        return isinstance(body, dict) and body.get("error") == "recaptcha validation failed"
    except Exception:
        return False


def openai_error_payload(message: str, type: str, code: object) -> dict:  # noqa: A002
    return {"error": {"message": str(message), "type": str(type), "code": code}}


async def _run_inpage_fetch_with_retry(
    core,
    *,
    page,
    http_method: str,
    url: str,
    fetch_url: str,
    payload: dict,
    timeout_seconds: int,
    max_recaptcha_attempts: int,
    recaptcha_action: str,
    mint_recaptcha_v3_token,  # noqa: ANN001
    mint_recaptcha_v2_token,  # noqa: ANN001
) -> "BrowserFetchStreamResponse":
    q, done = asyncio.Queue(), asyncio.Event()

    async def _report_chunk(source, line: str):  # noqa: ANN001
        if line and line.strip():
            await q.put(line)

    await page.expose_binding("reportChunk", _report_chunk)

    result: dict = {"status": 0, "headers": {}, "text": ""}
    attempts = max(1, int(max_recaptcha_attempts or 1))
    for attempt in range(attempts):
        while not q.empty():
            q.get_nowait()
        done.clear()

        if not payload.get("recaptchaV2Token") and (attempt > 0 or not payload.get("recaptchaV3Token")):
            token = await mint_recaptcha_v3_token()
            if token:
                payload["recaptchaV3Token"] = token

        tok = payload.get("recaptchaV3Token") or ""
        extra = {"X-Recaptcha-Token": tok, "X-Recaptcha-Action": recaptcha_action} if tok else {}
        fetch_task = asyncio.create_task(
            page.evaluate(
                FETCH_SCRIPT,
                {
                    "url": fetch_url,
                    "method": http_method,
                    "body": json.dumps(payload),
                    "extraHeaders": extra,
                    "timeoutMs": int(timeout_seconds * 1000),
                },
            )
        )

        meta = None
        while not fetch_task.done():
            try:
                item = await asyncio.wait_for(q.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            if isinstance(item, str) and item.startswith('{"__type":"meta"'):
                meta = json.loads(item)
                break
            if item is not None:
                await q.put(item)
            meta = {"status": HTTPStatus.OK, "headers": {}}
            break

        if fetch_task.done() and meta is None:
            try:
                res = fetch_task.result()
                result = (
                    res
                    if isinstance(res, dict) and not res.get("__streaming")
                    else {"status": HTTPStatus.BAD_GATEWAY, "text": "FETCH_DONE_WITHOUT_META"}
                )
            except Exception as e:
                result = {"status": HTTPStatus.BAD_GATEWAY, "text": f"FETCH_EXCEPTION: {e}"}
        elif meta:
            result = meta

        status_code = int(result.get("status") or 0)
        if status_code == HTTPStatus.TOO_MANY_REQUESTS and attempt < attempts - 1:
            hdrs = result.get("headers") or {}
            retry_after = hdrs.get("retry-after") or hdrs.get("Retry-After")
            await asyncio.sleep(core.get_rate_limit_sleep_seconds(str(retry_after) if retry_after is not None else None, attempt))
            continue

        if not is_recaptcha_validation_failed(status_code, result.get("text")):
            if status_code < HTTPStatus.BAD_REQUEST:
                body_text = result.get("text") if isinstance(result, dict) else None
                if isinstance(body_text, str) and body_text:
                    return BrowserFetchStreamResponse(status_code, result.get("headers", {}), body_text, method=http_method, url=url)

                fetch_task.add_done_callback(lambda t: (done.set(), None if t.cancelled() else t.exception()))
                return BrowserFetchStreamResponse(status_code, result.get("headers", {}), method=http_method, url=url, lines_queue=q, done_event=done)
            break

        if attempt < attempts - 1 and not payload.get("recaptchaV2Token"):
            v2_token = await mint_recaptcha_v2_token()
            if v2_token:
                payload["recaptchaV2Token"] = v2_token
                payload.pop("recaptchaV3Token", None)
                await asyncio.sleep(0.5)
                continue

        if attempt < attempts - 1:
            await core.click_turnstile(page)
            await asyncio.sleep(min(2.0 * (2**attempt), 15.0))

    return BrowserFetchStreamResponse(int(result.get("status") or 0), result.get("headers", {}), result.get("text", ""), method=http_method, url=url)


async def sse_wait_for_task_with_keepalive(core, task, *, interval_seconds: float = 1.0) -> AsyncIterator[str]:  # noqa: ANN001
    interval = float(max(0.05, interval_seconds))
    while True:
        done, _ = await core.asyncio.wait({task}, timeout=interval)
        if task in done:
            break
        yield SSE_KEEPALIVE


async def sse_sleep_with_keepalive(core, seconds: float, *, interval_seconds: float = 1.0) -> AsyncIterator[str]:  # noqa: ANN001
    try:
        total = float(seconds)
    except Exception:
        total = 0.0
    if total <= 0:
        return

    interval = float(max(0.05, interval_seconds))
    end_time = core.time.time() + total
    while core.time.time() < end_time:
        remaining = end_time - core.time.time()
        if remaining <= 0:
            break
        yield SSE_KEEPALIVE
        await core.asyncio.sleep(min(interval, remaining))


async def aiter_with_keepalive(core, it, *, timeout_seconds: float = 1.0) -> AsyncIterator[Optional[Any]]:  # noqa: ANN001
    """
    Yield items from an async iterator, yielding `None` periodically while waiting.

    This avoids asyncio.wait_for() because cancelling __anext__ can break some iterators.
    Callers can translate `None` into SSE keep-alives.
    """
    timeout = float(max(0.05, timeout_seconds))
    pending: Optional[asyncio.Task] = core.asyncio.create_task(it.__anext__())
    try:
        while True:
            done, _ = await core.asyncio.wait({pending}, timeout=timeout)
            if pending not in done:
                yield None
                continue
            try:
                item = pending.result()
            except StopAsyncIteration:
                break
            pending = core.asyncio.create_task(it.__anext__())
            yield item
    finally:
        if pending is not None and not pending.done():
            pending.cancel()


def prepare_browser_fetch_params(core, config, url, auth_token):
    cookie_values = extract_lmarena_cookie_values(config)
    desired_cookies = build_lmarena_context_cookies(cookie_values, auth_token=auth_token, include_grecaptcha=True)

    user_agent = core.normalize_user_agent_value(config.get("user_agent"))

    fetch_url = url
    if fetch_url.startswith("https://lmarena.ai"):
        fetch_url = fetch_url[len("https://lmarena.ai") :]
    if not fetch_url.startswith("/"):
        fetch_url = "/" + fetch_url

    return desired_cookies, user_agent, fetch_url


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

    async def aiter_lines(self) -> AsyncIterator[str]:
        if self._lines_queue is not None:
            # Streaming mode
            async for line in iter_queue_lines(
                self._lines_queue,
                done_event=self._done_event,
                poll_timeout_seconds=1.0,
            ):
                yield line
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
        if self.status_code == 0 or self.status_code >= HTTPStatus.BAD_REQUEST:
            raise_for_status_like_httpx(
                status_code=int(self.status_code or 0),
                method=self._method,
                url=self._url,
                message=f"HTTP {self.status_code}",
                content=self._text.encode("utf-8"),
            )


async def fetch_lmarena_stream_via_chrome(
    core,
    http_method: str,
    url: str,
    payload: dict,
    auth_token: str,
    timeout_seconds: int = 120,
    headless: bool = False,
    max_recaptcha_attempts: int = 3,
) -> Optional[BrowserFetchStreamResponse]:
    """
    Fallback transport: perform the stream request via in-browser fetch (Chrome/Edge via Playwright).
    """
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None

    chrome_path = core.find_chrome_executable()
    if not chrome_path:
        return None

    config = core.get_config()
    recaptcha_sitekey, recaptcha_action = core.get_recaptcha_settings(config)

    desired_cookies, user_agent, fetch_url = prepare_browser_fetch_params(core, config, url, auth_token)

    max_recaptcha_attempts = max(1, min(int(max_recaptcha_attempts), 10))
    profile_dir = Path(core.CONFIG_FILE).with_name("chrome_grecaptcha")

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            executable_path=chrome_path,
            headless=bool(headless),
            user_agent=user_agent or None,
            args=["--disable-blink-features=AutomationControlled", "--no-first-run", "--no-default-browser-check"],
        )
        try:
            await maybe_add_webdriver_stealth_script(context)

            if desired_cookies:
                await maybe_add_lmarena_cookies_to_persistent_context(context, desired_cookies)

            page = await context.new_page()
            await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)

            with suppress(Exception):
                for i in range(10):
                    title = await page.title()
                    if "Just a moment" not in title:
                        break
                    core.debug_print(f"  ⏳ Waiting for Cloudflare challenge in Chrome... (attempt {i+1}/10)")
                    await core.click_turnstile(page)
                    await asyncio.sleep(3)
                await page.wait_for_load_state("domcontentloaded", timeout=15000)

            with suppress(Exception):
                await page.mouse.move(100, 100)
                await asyncio.sleep(0.5)
                await page.mouse.wheel(0, 200)
                await asyncio.sleep(3)

            await maybe_capture_and_persist_lmarena_session(
                context,
                page,
                config=config,
                save_config_callback=core.save_config,
                capture_cookies_callback=core._capture_ephemeral_arena_auth_token_from_cookies,
                user_agent_fallback=user_agent,
            )

            async def _mint_recaptcha_v3_token():
                await page.wait_for_function("window.grecaptcha && ((window.grecaptcha.enterprise && typeof window.grecaptcha.enterprise.execute === 'function') || typeof window.grecaptcha.execute === 'function')", timeout=60000)
                return await page.evaluate("({sitekey, action}) => new Promise((resolve, reject) => { const g = (window.grecaptcha?.enterprise && typeof window.grecaptcha.enterprise.execute === 'function') ? window.grecaptcha.enterprise : window.grecaptcha; if (!g || typeof g.execute !== 'function') return reject('NO_GRECAPTCHA'); try { g.execute(sitekey, { action }).then(resolve).catch((err) => reject(String(err))); } catch (e) { reject(String(e)); } })", {"sitekey": recaptcha_sitekey, "action": recaptcha_action})

            async def _mint_recaptcha_v2_token():
                try:
                    await page.wait_for_function("window.grecaptcha && window.grecaptcha.enterprise && typeof window.grecaptcha.enterprise.render === 'function'", timeout=60000)
                except Exception:
                    return None
                return await page.evaluate("({sitekey, timeoutMs}) => new Promise((resolve, reject) => { const g = window.grecaptcha?.enterprise; if (!g || typeof g.render !== 'function') return reject('NO_GRECAPTCHA_V2'); let settled = false; const done = (fn, arg) => { if (settled) return; settled = true; fn(arg); }; try { const el = document.createElement('div'); el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;'; document.body.appendChild(el); const timer = setTimeout(() => done(reject, 'V2_TIMEOUT'), timeoutMs || 60000); const wid = g.render(el, { sitekey, size: 'invisible', callback: (tok) => { clearTimeout(timer); done(resolve, tok); }, 'error-callback': () => { clearTimeout(timer); done(reject, 'V2_ERROR'); }, }); try { if (typeof g.execute === 'function') g.execute(wid); } catch (e) {} } catch (e) { done(reject, String(e)); } })", {"sitekey": core.RECAPTCHA_V2_SITEKEY, "timeoutMs": 60000})

            return await _run_inpage_fetch_with_retry(
                core,
                page=page,
                http_method=http_method,
                url=url,
                fetch_url=fetch_url,
                payload=payload,
                timeout_seconds=timeout_seconds,
                max_recaptcha_attempts=max_recaptcha_attempts,
                recaptcha_action=recaptcha_action,
                mint_recaptcha_v3_token=_mint_recaptcha_v3_token,
                mint_recaptcha_v2_token=_mint_recaptcha_v2_token,
            )
        except Exception as e:
            core.debug_print(f"??? Chrome fetch transport failed: {e}")
            return None
        finally:
            await context.close()


async def fetch_lmarena_stream_via_camoufox(
    core,
    http_method: str,
    url: str,
    payload: dict,
    auth_token: str,
    timeout_seconds: int = 120,
    max_recaptcha_attempts: int = 3,
) -> Optional[BrowserFetchStreamResponse]:
    """
    Fallback transport: fetch via Camoufox (Firefox) in-page fetch.
    """
    core.debug_print("🦊 Attempting Camoufox fetch transport...")
    config = core.get_config()
    recaptcha_sitekey, recaptcha_action = core.get_recaptcha_settings(config)

    desired_cookies, user_agent, fetch_url = prepare_browser_fetch_params(core, config, url, auth_token)

    try:
        headless = bool(config.get("camoufox_fetch_headless", False))
        async with AsyncCamoufox(headless=headless, main_world_eval=True) as browser:
            context = await browser.new_context(user_agent=user_agent or None)
            await maybe_add_webdriver_stealth_script(context)
            if desired_cookies:
                with suppress(Exception): await context.add_cookies(desired_cookies)

            page = await context.new_page()

            core.debug_print(f"  🦊 Navigating to lmarena.ai...")
            with suppress(Exception): await asyncio.wait_for(page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=60000), timeout=70.0)

            for _ in range(5):
                if "Just a moment" not in await page.title(): break
                await core.click_turnstile(page)
                await asyncio.sleep(2)

            await core._maybe_apply_camoufox_window_mode(page, config, mode_key="camoufox_fetch_window_mode", marker="LMArenaBridge Camoufox Fetch", headless=headless)
            
            await maybe_capture_and_persist_lmarena_session(
                context,
                page,
                config=config,
                save_config_callback=core.save_config,
                capture_cookies_callback=core._capture_ephemeral_arena_auth_token_from_cookies,
                user_agent_fallback=user_agent,
            )

            async def _mint_recaptcha_v3_token():
                await page.wait_for_function("() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && ((w.grecaptcha.enterprise && typeof w.grecaptcha.enterprise.execute === 'function') || typeof w.grecaptcha.execute === 'function')); }", timeout=60000)
                await core.safe_page_evaluate(page, "() => { (window.wrappedJSObject || window).__token_result = 'PENDING'; }")
                trigger = f"() => {{ const w = window.wrappedJSObject || window; const sitekey = {json.dumps(recaptcha_sitekey)}; const action = {json.dumps(recaptcha_action)}; try {{ const raw = w.grecaptcha; const g = (raw?.enterprise && typeof raw.enterprise.execute === 'function') ? raw.enterprise : raw; if (!g || typeof g.execute !== 'function') {{ w.__token_result = 'ERROR: NO_GRECAPTCHA'; return; }} const readyFn = (typeof g.ready === 'function') ? g.ready.bind(g) : (raw && typeof raw.ready === 'function') ? raw.ready.bind(raw) : null; const run = () => {{ try {{ Promise.resolve(g.execute(sitekey, {{ action }})).then(token => {{ w.__token_result = token; }}).catch(err => {{ w.__token_result = 'ERROR: ' + String(err); }}); }} catch (e) {{ w.__token_result = 'SYNC_ERROR: ' + String(e); }} }}; try {{ if (readyFn) readyFn(run); else run(); }} catch (e) {{ run(); }} }} catch (e) {{ w.__token_result = 'SYNC_ERROR: ' + String(e); }} }}"
                await core.safe_page_evaluate(page, trigger)
                for _ in range(40):
                    val = await core.safe_page_evaluate(page, "() => (window.wrappedJSObject || window).__token_result")
                    if val != 'PENDING': return None if isinstance(val, str) and ('ERROR' in val or 'SYNC_ERROR' in val) else val
                    await asyncio.sleep(0.5)
                return None

            async def _mint_recaptcha_v2_token():
                try: await page.wait_for_function("() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && w.grecaptcha.enterprise && typeof w.grecaptcha.enterprise.render === 'function'); }", timeout=60000)
                except Exception: return None
                v2_script = f"() => new Promise((resolve, reject) => {{ const w = window.wrappedJSObject || window; const g = w.grecaptcha?.enterprise; if (!g || typeof g.render !== 'function') return reject('NO_GRECAPTCHA_V2'); let settled = false; const done = (fn, arg) => {{ if (settled) return; settled = true; fn(arg); }}; try {{ const el = w.document.createElement('div'); el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;'; w.document.body.appendChild(el); const timer = w.setTimeout(() => done(reject, 'V2_TIMEOUT'), 60000); const wid = g.render(el, {{ sitekey: {json.dumps(core.RECAPTCHA_V2_SITEKEY)}, size: 'invisible', callback: (tok) => {{ w.clearTimeout(timer); done(resolve, tok); }}, 'error-callback': () => {{ w.clearTimeout(timer); done(reject, 'V2_ERROR'); }}, }}); try {{ if (typeof g.execute === 'function') g.execute(wid); }} catch (e) {{}} }} catch (e) {{ done(reject, String(e)); }} }})"
                try: return await core.safe_page_evaluate(page, v2_script)
                except Exception: return None

            return await _run_inpage_fetch_with_retry(
                core,
                page=page,
                http_method=http_method,
                url=url,
                fetch_url=fetch_url,
                payload=payload,
                timeout_seconds=timeout_seconds,
                max_recaptcha_attempts=max_recaptcha_attempts,
                recaptcha_action=recaptcha_action,
                mint_recaptcha_v3_token=_mint_recaptcha_v3_token,
                mint_recaptcha_v2_token=_mint_recaptcha_v2_token,
            )
    except Exception as e:
        core.debug_print(f"??? Camoufox fetch transport failed: {e}")
        return None


def parse_lmarena_line_to_openai_chunks(
    line: str,
    chunk_id: str,
    model_public_name: str,
    state: dict,
) -> List[str]:
    """
    Parse a single upstream line and return OpenAI-compatible SSE chunk strings.

    The parser updates `state` in-place. Expected keys (optional):
    - response_text: str
    - reasoning_text: str
    - citations: list
    - finish_reason: str
    """
    if not isinstance(line, str):
        return []

    normalized = line.strip()
    # Normalize possible SSE framing (e.g. `data: a0:"..."`).
    if normalized.startswith("data:"):
        normalized = normalized[5:].lstrip()
    if not normalized:
        return []

    response_text = str(state.get("response_text") or "")
    reasoning_text = str(state.get("reasoning_text") or "")
    citations = state.get("citations")
    if not isinstance(citations, list):
        citations = []
        state["citations"] = citations

    chunks: list[str] = []

    def _emit_delta(delta: dict, *, finish_reason: Optional[str] = None) -> None:
        chunk_response = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model_public_name,
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish_reason,
                }
            ],
        }
        chunks.append(f"data: {json.dumps(chunk_response)}\n\n")

    # Reasoning: ag:"thinking"
    if normalized.startswith("ag:"):
        chunk_data = normalized[3:]
        try:
            reasoning_chunk = json.loads(chunk_data)
            r_chunk = str(reasoning_chunk or "")
        except Exception:
            r_chunk = ""
        if r_chunk:
            reasoning_text += r_chunk
            _emit_delta({"reasoning_content": r_chunk})

    # Text: a0:"Hello"
    elif normalized.startswith("a0:"):
        chunk_data = normalized[3:]
        try:
            text_chunk = json.loads(chunk_data)
            c_chunk = str(text_chunk or "")
        except Exception:
            c_chunk = ""
        if c_chunk:
            response_text += c_chunk
            _emit_delta({"content": c_chunk})

    # Image generation: a2:[{...}]
    elif normalized.startswith("a2:"):
        image_data = normalized[3:]
        try:
            image_list = json.loads(image_data)
        except Exception:
            image_list = None
        if isinstance(image_list, list) and image_list:
            image_obj = image_list[0] if isinstance(image_list[0], dict) else None
            image_url = ""
            if isinstance(image_obj, dict) and str(image_obj.get("type") or "") == "image":
                image_url = str(image_obj.get("image") or "").strip()
            if image_url:
                c_chunk = f"![Generated Image]({image_url})"
                response_text += c_chunk
                _emit_delta({"content": c_chunk})

    # Citations: ac:{...}
    elif normalized.startswith("ac:"):
        citation_data = normalized[3:]
        try:
            citation_obj = json.loads(citation_data)
        except Exception:
            citation_obj = None
        if isinstance(citation_obj, dict):
            args_delta = citation_obj.get("argsTextDelta")
            if isinstance(args_delta, str) and args_delta:
                try:
                    args_data = json.loads(args_delta)
                except Exception:
                    args_data = None
                if isinstance(args_data, dict) and "source" in args_data:
                    source = args_data.get("source")
                    if isinstance(source, list):
                        citations.extend(source)
                    elif isinstance(source, dict):
                        citations.append(source)

    # Finish / metadata: ad:{...}
    elif normalized.startswith("ad:"):
        metadata_data = normalized[3:]
        try:
            metadata = json.loads(metadata_data)
        except Exception:
            metadata = None
        finish_reason = "stop"
        if isinstance(metadata, dict) and metadata.get("finishReason"):
            finish_reason = str(metadata.get("finishReason") or "stop")
        state["finish_reason"] = finish_reason
        _emit_delta({}, finish_reason=finish_reason)

    # Raw JSON (proxy may already return OpenAI-style deltas)
    elif normalized.startswith("{"):
        try:
            chunk_obj = json.loads(normalized)
        except Exception:
            chunk_obj = None
        if isinstance(chunk_obj, dict) and isinstance(chunk_obj.get("choices"), list) and chunk_obj["choices"]:
            delta = (chunk_obj["choices"][0] or {}).get("delta", {}) if isinstance(chunk_obj["choices"][0], dict) else {}
            if isinstance(delta, dict):
                if "reasoning_content" in delta:
                    r_chunk = str(delta.get("reasoning_content") or "")
                    if r_chunk:
                        reasoning_text += r_chunk
                        _emit_delta({"reasoning_content": r_chunk})
                if "content" in delta:
                    c_chunk = str(delta.get("content") or "")
                    if c_chunk:
                        response_text += c_chunk
                        _emit_delta({"content": c_chunk})

    state["response_text"] = response_text
    state["reasoning_text"] = reasoning_text
    return chunks
