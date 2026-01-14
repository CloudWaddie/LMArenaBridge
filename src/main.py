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
from http import HTTPStatus
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta

import uvicorn
from camoufox.async_api import AsyncCamoufox
from fastapi import FastAPI, HTTPException, Depends, Request
from starlette.responses import StreamingResponse
from fastapi.security import APIKeyHeader

import httpx

if __name__ == "__main__" and __package__ is None:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "src"

from .browser_automation import (
    RECAPTCHA_SITEKEY,
    RECAPTCHA_ACTION,
    RECAPTCHA_V2_SITEKEY,
    TURNSTILE_SITEKEY,
    TurnstileClickLimiter,
    STRICT_CHROME_FETCH_MODELS,
    extract_recaptcha_params_from_text,
    get_recaptcha_settings,
    _is_windows,
    _normalize_camoufox_window_mode,
    _windows_apply_window_mode_by_title_substring,
    apply_camoufox_window_mode as _maybe_apply_camoufox_window_mode,
    click_turnstile,
    find_chrome_executable,
    is_execution_context_destroyed_error,
    safe_page_evaluate,
    normalize_user_agent_value,
    upsert_browser_session as _upsert_browser_session_into_config,
    get_recaptcha_v3_token_with_chrome as _get_recaptcha_v3_token_with_chrome,
)

from . import browser_automation as _browser_automation

from .proxy import ProxyService, UserscriptProxyStreamResponse

# ============================================================
# CONFIGURATION
# ============================================================
# Set to True for detailed logging, False for minimal logging
DEBUG = True
try:
    _browser_automation.DEBUG = DEBUG
except Exception:
    pass

# Port to run the server on
PORT = 8000

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
    try:
        message = HTTPStatus(status_code).phrase
    except ValueError:
        message = f"Unknown Status {status_code}"
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

async def get_recaptcha_v3_token_with_chrome(config: dict) -> Optional[str]:
    # Wrapper around the extracted function to inject save_config side-effect
    return await _get_recaptcha_v3_token_with_chrome(
        config,
        save_config_callback=save_config,
        config_file=CONFIG_FILE,
    )


from .streaming import (
    BrowserFetchStreamResponse,
    SSE_DONE,
    SSE_KEEPALIVE,
    aiter_with_keepalive,
    fetch_lmarena_stream_via_chrome as _fetch_via_chrome,
    fetch_lmarena_stream_via_camoufox as _fetch_via_camoufox,
    openai_error_payload,
    parse_lmarena_line_to_openai_chunks,
    sse_sleep_with_keepalive,
    sse_wait_for_task_with_keepalive,
)

async def fetch_lmarena_stream_via_chrome(*args, **kwargs):
    return await _fetch_via_chrome(sys.modules[__name__], *args, **kwargs)

async def fetch_lmarena_stream_via_camoufox(*args, **kwargs):
    return await _fetch_via_camoufox(sys.modules[__name__], *args, **kwargs)


_PROXY_SERVICE = ProxyService()
_USERSCRIPT_PROXY_JOBS: dict[str, dict] = _PROXY_SERVICE.jobs

def _touch_userscript_poll(now: Optional[float] = None) -> None:
    """
    Update userscript-proxy "last seen" timestamps.

    The bridge supports both an external userscript poller and an internal Camoufox-backed poller.
    Keep both timestamps in sync so strict-model routing can reliably detect proxy availability.
    """
    global last_userscript_poll
    _PROXY_SERVICE.touch_poll(now)
    # Legacy timestamp used by status messages/back-compat.
    last_userscript_poll = float(_PROXY_SERVICE.last_poll_at or 0.0)


def _userscript_proxy_is_active(config: Optional[dict] = None) -> bool:
    cfg = config or get_config()
    return _PROXY_SERVICE.is_active(cfg, now=time.time())


def _userscript_proxy_check_secret(request: Request) -> None:
    cfg = get_config()
    secret = str(cfg.get("userscript_proxy_secret") or "").strip()
    if secret and request.headers.get("X-LMBridge-Secret") != secret:
        raise HTTPException(status_code=401, detail="Invalid userscript proxy secret")


async def fetch_lmarena_stream_via_userscript_proxy(
    http_method: str,
    url: str,
    payload: dict,
    timeout_seconds: int = 120,
    auth_token: str = "",
) -> Optional[UserscriptProxyStreamResponse]:
    config = get_config()
    _PROXY_SERVICE.cleanup_jobs(config)
    sitekey, action = get_recaptcha_settings(config)
    proxy_cfg = {
        "userscript_proxy_job_ttl_seconds": config.get("userscript_proxy_job_ttl_seconds", 90),
        "recaptcha_sitekey": sitekey,
        "recaptcha_action": action,
    }
    return await _PROXY_SERVICE.enqueue_stream_job(
        url=str(url),
        http_method=str(http_method or "POST"),
        payload=payload,
        auth_token=str(auth_token or "").strip(),
        timeout_seconds=int(timeout_seconds or 120),
        config=proxy_cfg,
    )


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

    # Proxy-only: no legacy queue fallback.
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
                    if "Just a moment" in title or "Cloudflare" in title:
                        debug_print("  🔒 Cloudflare challenge active. Attempting to click...")
                        clicked = await click_turnstile(page)
                        if clicked:
                            debug_print("  ✅ Clicked Turnstile.")
                            # Give it time to verify
                            await asyncio.sleep(3)
                    else:
                        # If title is normal, we might still have a widget on the page but it's less likely.
                        # We'll do one quick attempt and break if not found.
                        await click_turnstile(page)
                        break
                    await asyncio.sleep(2)
                
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

_DEFAULT_API_KEY_CREATED = 1704236400  # Jan 3 2024 (stable default to avoid config churn)


def _normalize_api_keys_value(raw_value: object) -> list[dict]:
    """
    Normalize config `api_keys` into the canonical list-of-dicts form.

    Accepts legacy shapes:
    - "api_keys": "<key>"
    - "api_keys": ["<key>", ...]
    """
    entries: list[object]
    if isinstance(raw_value, list):
        entries = list(raw_value)
    elif isinstance(raw_value, str):
        entries = [raw_value]
    elif isinstance(raw_value, dict):
        entries = [raw_value]
    else:
        entries = []

    normalized: list[dict] = []
    for entry in entries:
        if isinstance(entry, str):
            key = entry.strip()
            if not key:
                continue
            normalized.append(
                {
                    "name": "Imported Key",
                    "key": key,
                    "created": _DEFAULT_API_KEY_CREATED,
                    "rpm": 60,
                }
            )
            continue

        if isinstance(entry, dict):
            key_val = entry.get("key")
            if key_val is None and "api_key" in entry:
                key_val = entry.get("api_key")
            key = str(key_val or "").strip()
            if not key:
                continue

            name = str(entry.get("name") or "Unnamed Key").strip() or "Unnamed Key"

            created = entry.get("created", _DEFAULT_API_KEY_CREATED)
            try:
                created = int(created)
            except Exception:
                created = _DEFAULT_API_KEY_CREATED

            rpm = entry.get("rpm", 60)
            try:
                rpm = int(rpm)
            except Exception:
                rpm = 60
            rpm = max(1, min(rpm, 1000))

            normalized.append({"name": name, "key": key, "rpm": rpm, "created": created})
            continue

    return normalized


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
        config["api_keys"] = _normalize_api_keys_value(config.get("api_keys"))

        # Back-compat: accept a top-level `api_key` (singular) and import it into `api_keys`.
        if not config.get("api_keys"):
            config["api_keys"] = _normalize_api_keys_value(config.get("api_key"))
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

def save_config(config, *, preserve_auth_tokens: bool = True, preserve_api_keys: bool = True):
    try:
        # Avoid clobbering user-provided auth tokens when multiple tasks write config.json concurrently.
        # Background refreshes/cookie upserts shouldn't overwrite auth tokens that may have been added via the dashboard.
        if preserve_auth_tokens or preserve_api_keys:
            try:
                with open(CONFIG_FILE, "r") as f:
                    on_disk = json.load(f)
            except Exception:
                on_disk = None

            if isinstance(on_disk, dict):
                if preserve_auth_tokens:
                    if "auth_tokens" in on_disk and isinstance(on_disk.get("auth_tokens"), list):
                        config["auth_tokens"] = list(on_disk.get("auth_tokens") or [])
                    if "auth_token" in on_disk:
                        config["auth_token"] = str(on_disk.get("auth_token") or "")
                if preserve_api_keys:
                    # Back-compat: preserve a singular `api_key` too (older configs), and prefer `api_keys` when present.
                    preserved = None
                    if "api_keys" in on_disk:
                        preserved = _normalize_api_keys_value(on_disk.get("api_keys"))
                    if not preserved and "api_key" in on_disk:
                        preserved = _normalize_api_keys_value(on_disk.get("api_key"))
                    if preserved:
                        config["api_keys"] = preserved

        # Persist in-memory stats to the config dict before saving
        config["usage_stats"] = dict(model_usage_stats)
        tmp_path = f"{CONFIG_FILE}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
        os.replace(tmp_path, CONFIG_FILE)
    except Exception as e:
        debug_print(f"❌ Error saving config: {e}")


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
    
    # Pragmatic fallback: if Authorization is missing/empty, use the first available key
    if not api_key_str:
        if api_keys:
            api_key_str = api_keys[0]["key"]
            # debug_print(f"ℹ️  No API key provided, using first available key: {api_key_str[:8]}...")
        else:
            raise HTTPException(
                status_code=401, 
                detail="Authentication required. No API keys configured and none provided in Authorization header."
            )
    
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
        generated_default_key = False
        if not config.get("api_keys"):
            config["api_keys"] = [
                {
                    "name": "Default Key",
                    "key": "sk" + f"-lmab-{uuid.uuid4()}",
                    "rpm": 60,
                    "created": int(time.time()),
                }
            ]
            generated_default_key = True
        save_config(config, preserve_api_keys=not generated_default_key)
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
        _touch_userscript_poll(time.time())
        
        asyncio.create_task(camoufox_proxy_worker())
        
    except Exception as e:
        debug_print(f"❌ Error during startup: {e}")
        # Continue anyway - server should still start

# --- Userscript Proxy Support ---

# Timestamp of last userscript poll (legacy; kept for status messages/back-compat)
last_userscript_poll: float = 0

async def push_proxy_chunk(jid, d) -> None:
    _touch_userscript_poll()

    job_id = str(jid or "").strip()
    job = _USERSCRIPT_PROXY_JOBS.get(job_id)
    if not isinstance(job, dict):
        return

    if not isinstance(d, dict):
        return

    status = d.get("status")
    if isinstance(status, int) and not job.get("_proxy_status_logged"):
        job["_proxy_status_logged"] = True
        debug_print(f"🦊 Camoufox proxy job {job_id[:8]} upstream status: {int(status)}")

    error = d.get("error")
    if error:
        debug_print(f"⚠️ Camoufox proxy job {job_id[:8]} error: {str(error)[:200]}")

    debug_obj = d.get("debug")
    if debug_obj and os.environ.get("LM_BRIDGE_PROXY_DEBUG"):
        try:
            dbg_text = json.dumps(debug_obj, ensure_ascii=False)
        except Exception:
            dbg_text = str(debug_obj)
        debug_print(f"🦊 Camoufox proxy debug {job_id[:8]}: {dbg_text[:300]}")

    await _PROXY_SERVICE.push_proxy_chunk(job_id=job_id, payload=d)

    if bool(d.get("done")):
        debug_print(f"🦊 Camoufox proxy job {job_id[:8]} done")


from .proxy_worker import camoufox_proxy_worker as _camoufox_proxy_worker

async def camoufox_proxy_worker():
    return await _camoufox_proxy_worker(sys.modules[__name__])

from .chat_completions import api_chat_completions as _api_chat_completions

async def api_chat_completions(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    return await _api_chat_completions(sys.modules[__name__], request, api_key)

from .api_server import build_router as _build_api_router

app.include_router(_build_api_router(sys.modules[__name__]))

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
