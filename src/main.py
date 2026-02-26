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

# Import from modularized modules
from . import constants
from . import config as _config_module
from . import state as _state_module
from .config import get_models, save_models
from .browser_utils import (
    _is_windows,
    _normalize_camoufox_window_mode,
    _windows_apply_window_mode_by_title_substring,
    _maybe_apply_camoufox_window_mode,
    click_turnstile,
    is_execution_context_destroyed_error,
    safe_page_evaluate,
    _consume_background_task_exception,
    _cancel_background_task,
)
from .recaptcha import (
    extract_recaptcha_params_from_text,
    get_recaptcha_settings,
    _mint_recaptcha_v3_token_in_page,
    _camoufox_proxy_signup_anonymous_user,
    _set_provisional_user_id_in_browser,
    _maybe_inject_arena_auth_cookie_from_localstorage,
    find_chrome_executable,
    get_recaptcha_v3_token_with_chrome,
    get_recaptcha_v3_token,
    refresh_recaptcha_token,
    get_cached_recaptcha_token,
)
from .auth import (
    _combine_split_arena_auth_cookies,
    _capture_ephemeral_arena_auth_token_from_cookies,
    _upsert_browser_session_into_config,
    normalize_user_agent_value,
    get_request_headers_with_token,
    _decode_arena_auth_session_token,
    maybe_build_arena_auth_cookie_from_signup_response_body,
    _decode_jwt_payload,
    extract_supabase_anon_key_from_text,
    _derive_supabase_auth_base_url_from_arena_auth_token,
    get_arena_auth_token_expiry_epoch,
    is_arena_auth_token_expired,
    is_probably_valid_arena_auth_token,
    refresh_arena_auth_token_via_lmarena_http,
    refresh_arena_auth_token_via_supabase,
    maybe_refresh_expired_auth_tokens_via_lmarena_http,
    maybe_refresh_expired_auth_tokens,
    get_next_auth_token,
    remove_auth_token,
    ARENA_AUTH_REFRESH_LOCK,
)

from .transport import (
    BrowserFetchStreamResponse,
    UserscriptProxyStreamResponse,
    _touch_userscript_poll,
    _get_userscript_proxy_queue,
    _userscript_proxy_is_active,
    _userscript_proxy_check_secret,
    _cleanup_userscript_proxy_jobs,
    _mark_userscript_proxy_inactive,
    _finalize_userscript_proxy_job,
    _detect_arena_origin,
    _arena_origin_candidates,
    _arena_auth_cookie_specs,
    _provisional_user_id_cookie_specs,
    _get_arena_context_cookies,
    _normalize_userscript_proxy_url,
    fetch_lmarena_stream_via_userscript_proxy,
    fetch_lmarena_stream_via_chrome,
    fetch_lmarena_stream_via_camoufox,
    fetch_via_proxy_queue,
    push_proxy_chunk,
    camoufox_proxy_worker,
)

# Aliases for backward compatibility
DEBUG = constants.DEBUG
PORT = constants.PORT
HTTPStatus = constants.HTTPStatus
STATUS_MESSAGES = constants.STATUS_MESSAGES
RECAPTCHA_SITEKEY = constants.RECAPTCHA_SITEKEY
RECAPTCHA_ACTION = constants.RECAPTCHA_ACTION
RECAPTCHA_V2_SITEKEY = constants.RECAPTCHA_V2_SITEKEY
TURNSTILE_SITEKEY = constants.TURNSTILE_SITEKEY
STRICT_CHROME_FETCH_MODELS = constants.STRICT_CHROME_FETCH_MODELS
LMARENA_ORIGIN = constants.LMARENA_ORIGIN
ARENA_ORIGIN = constants.ARENA_ORIGIN
ARENA_HOST_TO_ORIGIN = constants.ARENA_HOST_TO_ORIGIN
DEFAULT_REQUEST_TIMEOUT = constants.DEFAULT_REQUEST_TIMEOUT
GRECAPTCHA_TIMEOUT_MS = constants.GRECAPTCHA_TIMEOUT_MS
GRECAPTCHA_POLL_MS = constants.GRECAPTCHA_POLL_MS
TOKEN_EXPIRY_SKEW_SECONDS = constants.TOKEN_EXPIRY_SKEW_SECONDS
RECAPTCHA_TOKEN_EXPIRY_SECONDS = constants.RECAPTCHA_TOKEN_EXPIRY_SECONDS
RECAPTCHA_V3_TOKEN_LIFETIME_SECONDS = constants.RECAPTCHA_V3_TOKEN_LIFETIME_SECONDS
PERIODIC_REFRESH_INTERVAL_SECONDS = constants.PERIODIC_REFRESH_INTERVAL_SECONDS
DEFAULT_RATE_LIMIT_RPM = constants.DEFAULT_RATE_LIMIT_RPM
RATE_LIMIT_WINDOW_SECONDS = constants.RATE_LIMIT_WINDOW_SECONDS
DEFAULT_USERSCRIPT_PROXY_POLL_TIMEOUT_SECONDS = constants.DEFAULT_USERSCRIPT_PROXY_POLL_TIMEOUT_SECONDS
DEFAULT_USERSCRIPT_PROXY_JOB_TTL_SECONDS = constants.DEFAULT_USERSCRIPT_PROXY_JOB_TTL_SECONDS
USERSCRIPT_PROXY_ACTIVE_WINDOW_BUFFER_SECONDS = constants.USERSCRIPT_PROXY_ACTIVE_WINDOW_BUFFER_SECONDS
USERSCRIPT_PROXY_JOB_TTL_MAX_SECONDS = constants.USERSCRIPT_PROXY_JOB_TTL_MAX_SECONDS
DEFAULT_CAMOUFOX_PROXY_WINDOW_MODE = constants.DEFAULT_CAMOUFOX_PROXY_WINDOW_MODE
DEFAULT_CAMOUFOX_FETCH_WINDOW_MODE = constants.DEFAULT_CAMOUFOX_FETCH_WINDOW_MODE
DEFAULT_CHROME_FETCH_WINDOW_MODE = constants.DEFAULT_CHROME_FETCH_WINDOW_MODE
VALID_WINDOW_MODES = constants.VALID_WINDOW_MODES
CHROME_PATH_CANDIDATES = constants.CHROME_PATH_CANDIDATES
EDGE_PATH_CANDIDATES = constants.EDGE_PATH_CANDIDATES
DEFAULT_USER_AGENT = constants.DEFAULT_USER_AGENT
MAX_IMAGE_SIZE_BYTES = constants.MAX_IMAGE_SIZE_BYTES
SUPPORTED_IMAGE_MIME_TYPES = constants.SUPPORTED_IMAGE_MIME_TYPES
CF_CLEARANCE_COOKIE = constants.CF_CLEARANCE_COOKIE
CF_BM_COOKIE = constants.CF_BM_COOKIE
CF_UVID_COOKIE = constants.CF_UVID_COOKIE
PROVISIONAL_USER_ID_COOKIE = constants.PROVISIONAL_USER_ID_COOKIE
ARENA_AUTH_COOKIE = constants.ARENA_AUTH_COOKIE
GRECAPTCHA_COOKIE = constants.GRECAPTCHA_COOKIE
ARENA_COOKIE_DOMAINS = constants.ARENA_COOKIE_DOMAINS
ARENA_DIRECT_MODE_URL = constants.ARENA_DIRECT_MODE_URL
NEXTJS_API_SIGNUP = constants.NEXTJS_API_SIGNUP
CONTENT_TYPE_TEXT_PLAIN_UTF8 = constants.CONTENT_TYPE_TEXT_PLAIN_UTF8
CONTENT_TYPE_APPLICATION_JSON = constants.CONTENT_TYPE_APPLICATION_JSON
TURNSTILE_SELECTORS = constants.TURNSTILE_SELECTORS
TURNSTILE_INNER_SELECTORS = constants.TURNSTILE_INNER_SELECTORS
ARENA_ORIGIN_HEADER = constants.ARENA_ORIGIN_HEADER
ARENA_REFERER_HEADER = constants.ARENA_REFERER_HEADER
SUPABASE_JWT_PATTERN = constants.SUPABASE_JWT_PATTERN
CLOUDFLARE_CHALLENGE_TITLE = constants.CLOUDFLARE_CHALLENGE_TITLE

# Backoff functions
def get_rate_limit_sleep_seconds(retry_after: Optional[str], attempt: int) -> int:
    return constants.get_rate_limit_backoff_seconds(retry_after, attempt)

def get_general_backoff_seconds(attempt: int) -> int:
    return constants.get_general_backoff_seconds(attempt)


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


def get_status_emoji(status_code: int) -> str:
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


def log_http_status(status_code: int, context: str = "") -> None:
    emoji = get_status_emoji(status_code)
    message = STATUS_MESSAGES.get(status_code, f"Unknown Status {status_code}")
    if context:
        debug_print(f"{emoji} HTTP {status_code}: {message} ({context})")
    else:
        debug_print(f"{emoji} HTTP {status_code}: {message}")



# Updated constants from gpt4free/g4f/Provider/needs_auth/LMArena.py
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"
# reCAPTCHA Enterprise v2 sitekey used when v3 scoring fails and LMArena prompts a checkbox challenge.
RECAPTCHA_V2_SITEKEY = "6Ld7ePYrAAAAAB34ovoFoDau1fqCJ6IyOjFEQaMn"
# Cloudflare Turnstile sitekey used by LMArena to mint anonymous-user signup tokens.
# (Used for POST /nextjs-api/sign-up before `arena-auth-prod-v1` exists.)
TURNSTILE_SITEKEY = "0x4AAAAAAA65vWDmG-O_lPtT"
STREAM_CREATE_EVALUATION_PATH = "/nextjs-api/stream/create-evaluation"

# LMArena occasionally changes the reCAPTCHA sitekey/action. We try to discover them from captured JS chunks on startup
# and persist them into config.json; these helpers read and apply those values with safe fallbacks.

# _is_windows, _normalize_camoufox_window_mode imported from browser_utils


USERSCRIPT_PROXY_LAST_POLL_AT: float = 0.0
_USERSCRIPT_PROXY_QUEUE: Optional[asyncio.Queue] = None
_USERSCRIPT_PROXY_JOBS: dict[str, dict] = {}


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
CONFIG_FILE = constants.CONFIG_FILE
MODELS_FILE = constants.MODELS_FILE
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
        _config_module._apply_config_defaults(config)
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
            url = f"https://lmarena.ai{STREAM_CREATE_EVALUATION_PATH}"
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
                nonlocal session_id, user_msg_id, model_msg_id, model_b_msg_id
                
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
                                    # New-session create-evaluation retries must use fresh IDs. Reusing IDs after an
                                    # upstream no-delta/error response can trigger 400 duplicate/invalid request errors.
                                    if (
                                        (not session)
                                        and isinstance(payload, dict)
                                        and http_method.upper() == "POST"
                                        and STREAM_CREATE_EVALUATION_PATH in url
                                    ):
                                        session_id = str(uuid7())
                                        user_msg_id = str(uuid7())
                                        model_msg_id = str(uuid7())
                                        model_b_msg_id = str(uuid7())
                                        payload["id"] = session_id
                                        payload["userMessageId"] = user_msg_id
                                        payload["modelAMessageId"] = model_msg_id
                                        payload["modelBMessageId"] = model_b_msg_id
                                        debug_print("🔁 Retrying create-evaluation with fresh session/message IDs.")
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
