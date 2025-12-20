import asyncio
import json
import re
import uuid
import time
import secrets
import base64
import mimetypes
from collections import defaultdict
from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta

import uvicorn
from camoufox.async_api import AsyncCamoufox
from fastapi import FastAPI, HTTPException, Depends, status, Form, Request, Response
from starlette.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import APIKeyHeader

import httpx

# ============================================================
# CONFIGURATION
# ============================================================
# Set to True for detailed logging, False for minimal logging
DEBUG = True

# Port to run the server on
PORT = 8000

# HTTP Status Codes
class HTTPStatus:
    # 1xx Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    EARLY_HINTS = 103
    
    # 2xx Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    
    # 3xx Redirection
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    MOVED_TEMPORARILY = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308
    
    # 4xx Client Errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    REQUEST_TOO_LONG = 413
    REQUEST_URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    IM_A_TEAPOT = 418
    INSUFFICIENT_SPACE_ON_RESOURCE = 419
    METHOD_FAILURE = 420
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    UNAVAILABLE_FOR_LEGAL_REASONS = 451
    
    # 5xx Server Errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    INSUFFICIENT_STORAGE = 507
    NETWORK_AUTHENTICATION_REQUIRED = 511

# Status code descriptions for logging
STATUS_MESSAGES = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK - Success",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request - Invalid request syntax",
    401: "Unauthorized - Invalid or expired token",
    402: "Payment Required",
    403: "Forbidden - Access denied",
    404: "Not Found - Resource doesn't exist",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone - Resource permanently deleted",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Too Long - Payload too large",
    414: "Request URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a Teapot",
    419: "Insufficient Space on Resource",
    420: "Method Failure",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests - Rate limit exceeded",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    507: "Insufficient Storage",
    511: "Network Authentication Required"
}

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
    message = STATUS_MESSAGES.get(status_code, f"Unknown Status {status_code}")
    if context:
        debug_print(f"{emoji} HTTP {status_code}: {message} ({context})")
    else:
        debug_print(f"{emoji} HTTP {status_code}: {message}")
# ============================================================

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is True"""
    if DEBUG:
        print(*args, **kwargs)

# --- New reCAPTCHA Functions ---

# Updated constants from gpt4free/g4f/Provider/needs_auth/LMArena.py
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"

async def click_turnstile(page):
    """
    Attempts to locate and click the Cloudflare Turnstile widget.
    Based on gpt4free logic.
    """
    debug_print("  🖱️  Attempting to click Cloudflare Turnstile...")
    try:
        # Common selectors used by LMArena's Turnstile implementation
        selectors = [
            '#cf-turnstile', 
            'iframe[src*="challenges.cloudflare.com"]',
            '[style*="display: grid"] iframe' # The grid style often wraps the checkbox
        ]
        
        for selector in selectors:
            element = await page.query_selector(selector)
            if element:
                # Get bounding box to click specific coordinates if needed
                box = await element.bounding_box()
                if box:
                    x = box['x'] + (box['width'] / 2)
                    y = box['y'] + (box['height'] / 2)
                    debug_print(f"  🎯 Found widget at {x},{y}. Clicking...")
                    await page.mouse.click(x, y)
                    await asyncio.sleep(2)
                    return True
        return False
    except Exception as e:
        debug_print(f"  ⚠️ Error clicking turnstile: {e}")
        return False

async def get_recaptcha_v3_token() -> Optional[str]:
    """
    Retrieves reCAPTCHA v3 token using a 'Side-Channel' approach.
    We write the token to a global window variable and poll for it, 
    bypassing Promise serialization issues in the Main World bridge.
    """
    debug_print("🔐 Starting reCAPTCHA v3 token retrieval (Side-Channel Mode)...")
    
    config = get_config()
    cf_clearance = config.get("cf_clearance", "")
    
    try:
        async with AsyncCamoufox(headless=True, main_world_eval=True) as browser:
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
                    if "Just a moment" in title:
                        debug_print("  🔒 Cloudflare challenge active. Attempting to click...")
                        clicked = await click_turnstile(page)
                        if clicked:
                            debug_print("  ✅ Clicked Turnstile.")
                            # Give it time to verify
                            await asyncio.sleep(3)
                    else:
                        # If title is normal, we might still have a widget on the page
                        await click_turnstile(page)
                        break
                    await asyncio.sleep(1)
                
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
            lib_ready = await page.evaluate("mw:() => !!(window.grecaptcha && window.grecaptcha.enterprise)")
            if not lib_ready:
                debug_print("  ⚠️ Library not found immediately. Waiting...")
                await asyncio.sleep(3)
                lib_ready = await page.evaluate("mw:() => !!(window.grecaptcha && window.grecaptcha.enterprise)")
                if not lib_ready:
                    debug_print("❌ reCAPTCHA library never loaded.")
                    return None

            # 3. SETUP: Initialize our global result variable
            # We use a unique name to avoid conflicts
            await page.evaluate("mw:window.__token_result = 'PENDING'")

            # 4. TRIGGER: Execute reCAPTCHA and write to the variable
            # We do NOT await the result here. We just fire the process.
            debug_print("  🚀 Triggering reCAPTCHA execution...")
            trigger_script = f"""mw:() => {{
                try {{
                    window.grecaptcha.enterprise.execute('{RECAPTCHA_SITEKEY}', {{ action: '{RECAPTCHA_ACTION}' }})
                    .then(token => {{
                        window.__token_result = token;
                    }})
                    .catch(err => {{
                        window.__token_result = 'ERROR: ' + err.toString();
                    }});
                }} catch (e) {{
                    window.__token_result = 'SYNC_ERROR: ' + e.toString();
                }}
            }}"""
            
            await page.evaluate(trigger_script)

            # 5. POLL: Watch the variable for changes
            debug_print("  👀 Polling for result...")
            token = None
            
            for i in range(20): # Wait up to 20 seconds
                # Read the global variable
                result = await page.evaluate("mw:window.__token_result")
                
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
                global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
                RECAPTCHA_TOKEN = token
                RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
                return token
            else:
                debug_print("❌ Timed out waiting for token variable to update.")
                return None

    except Exception as e:
        debug_print(f"❌ Unexpected error: {e}")
        return None

def _is_recaptcha_validation_failed(body_text: str) -> bool:
    """Best-effort detection of LMArena's reCAPTCHA failure response."""
    lowered = (body_text or "").lower()
    return "recaptcha" in lowered and "validation failed" in lowered


async def refresh_recaptcha_token(force: bool = False):
    """Checks if the global reCAPTCHA token is expired and refreshes it if necessary.

    Args:
        force: If True, always fetch a fresh token (useful when upstream rejects a token).
    """
    global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
    
    current_time = datetime.now(timezone.utc)
    # Check if token is expired (set a refresh margin of 10 seconds)
    if force or RECAPTCHA_TOKEN is None or current_time > RECAPTCHA_EXPIRY - timedelta(seconds=10):
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

app = FastAPI()

# --- Constants & Global State ---
CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
API_KEY_HEADER = APIKeyHeader(name="Authorization")

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
# Track which token is assigned to each conversation (conversation_id -> token)
conversation_tokens: Dict[str, str] = {}
# Track failed tokens per request to avoid retrying with same token
request_failed_tokens: Dict[str, set] = {}

# --- New Global State for reCAPTCHA ---
RECAPTCHA_TOKEN: Optional[str] = None
# Initialize expiry far in the past to force a refresh on startup
RECAPTCHA_EXPIRY: datetime = datetime.now(timezone.utc) - timedelta(days=365)
# --------------------------------------

# --- Helper Functions ---

def get_config():
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

def save_config(config):
    try:
        # Persist in-memory stats to the config dict before saving
        config["usage_stats"] = dict(model_usage_stats)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        debug_print(f"❌ Error saving config: {e}")

def get_models():
    try:
        with open(MODELS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_models(models):
    try:
        with open(MODELS_FILE, "w") as f:
            json.dump(models, f, indent=2)
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
            raise HTTPException(status_code=500, detail="Arena auth token not set in dashboard.")
    
    return get_request_headers_with_token(token)

def get_request_headers_with_token(token: str):
    """Get request headers with a specific auth token"""
    config = get_config()
    cf_clearance = config.get("cf_clearance", "").strip()
    return {
        "Content-Type": "text/plain;charset=UTF-8",
        "Cookie": f"cf_clearance={cf_clearance}; arena-auth-prod-v1={token}",
    }

def get_next_auth_token(exclude_tokens: set = None):
    """Get next auth token using round-robin selection
    
    Args:
        exclude_tokens: Set of tokens to exclude from selection (e.g., already tried tokens)
    """
    global current_token_index
    config = get_config()
    
    # Get all available tokens
    auth_tokens = config.get("auth_tokens", [])
    if not auth_tokens:
        raise HTTPException(status_code=500, detail="No auth tokens configured")
    
    # Filter out excluded tokens
    if exclude_tokens:
        available_tokens = [t for t in auth_tokens if t not in exclude_tokens]
        if not available_tokens:
            raise HTTPException(status_code=500, detail="No more auth tokens available to try")
    else:
        available_tokens = auth_tokens
    
    # Round-robin selection from available tokens
    token = available_tokens[current_token_index % len(available_tokens)]
    current_token_index = (current_token_index + 1) % len(auth_tokens)
    return token

def remove_auth_token(token: str):
    """Remove an expired/invalid auth token from the list"""
    try:
        config = get_config()
        auth_tokens = config.get("auth_tokens", [])
        if token in auth_tokens:
            auth_tokens.remove(token)
            config["auth_tokens"] = auth_tokens
            save_config(config)
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
    if not key.startswith("Bearer "):
        raise HTTPException(
            status_code=401, 
            detail="Invalid Authorization header. Expected 'Bearer YOUR_API_KEY'"
        )
    
    # Remove "Bearer " prefix and strip whitespace
    api_key_str = key[7:].strip()
    config = get_config()
    
    key_data = next((k for k in config["api_keys"] if k["key"] == api_key_str), None)
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
            try:
                await page.wait_for_function(
                    "() => document.title.indexOf('Just a moment...') === -1", 
                    timeout=45000
                )
                debug_print("✅ Cloudflare challenge passed.")
            except Exception as e:
                debug_print(f"❌ Cloudflare challenge took too long or failed: {e}")
                return

            # Give it time to capture all JS responses
            await asyncio.sleep(5)

            # Extract cf_clearance
            cookies = await page.context.cookies()
            cf_clearance_cookie = next((c for c in cookies if c["name"] == "cf_clearance"), None)
            
            config = get_config()
            if cf_clearance_cookie:
                config["cf_clearance"] = cf_clearance_cookie["value"]
                save_config(config)
                debug_print(f"✅ Saved cf_clearance token: {cf_clearance_cookie['value'][:20]}...")
            else:
                debug_print("⚠️ Could not find cf_clearance cookie.")

            # Extract models
            debug_print("Extracting models from page...")
            try:
                body = await page.content()
                match = re.search(r'{\\"initialModels\\":(\[.*?\]),\\"initialModel[A-Z]Id', body, re.DOTALL)
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

@app.on_event("startup")
async def startup_event():
    try:
        # Ensure config and models files exist
        save_config(get_config())
        save_models(get_models())
        # Load usage stats from config
        load_usage_stats()
        
        # 1. First, get initial data (cookies, models, etc.)
        # We await this so we have the cookie BEFORE trying reCAPTCHA
        await get_initial_data() 
        
        # 2. Now start the initial reCAPTCHA fetch (using the cookie we just got)
        # Block startup until we have a token or fail, so we don't serve 403s
        await refresh_recaptcha_token()
        
        # 3. Start background tasks
        asyncio.create_task(periodic_refresh_task())
        
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
        created_date = time.strftime('%Y-%m-%d %H:%M', time.localtime(key.get('created', 0)))
        keys_html += f"""
            <tr>
                <td><strong>{key['name']}</strong></td>
                <td><code class="api-key-code">{key['key']}</code></td>
                <td><span class="badge">{key['rpm']} RPM</span></td>
                <td><small>{created_date}</small></td>
                <td>
                    <form action='/delete-key' method='post' style='margin:0;' onsubmit='return confirm("Delete this API key?");'>
                        <input type='hidden' name='key_id' value='{key['key']}'>
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
    save_config(config)
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
            save_config(config)
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
            save_config(config)
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
        
        # Determine modality based on model capabilities
        # Priority: image > search > chat
        if model_capabilities.get('outputCapabilities', {}).get('image'):
            modality = "image"
        elif model_capabilities.get('outputCapabilities', {}).get('search'):
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
            system_prompt = "\n\n".join([m.get("content", "") for m in system_messages])
            debug_print(f"📋 System prompt found: {system_prompt[:100]}..." if len(system_prompt) > 100 else f"📋 System prompt: {system_prompt}")
        
        # Process last message content (may include images)
        try:
            last_message_content = messages[-1].get("content", "")
            prompt, experimental_attachments = await process_message_content(last_message_content, model_capabilities)
            
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
        recaptcha_token = await refresh_recaptcha_token()
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
        
        headers = get_request_headers()
        debug_print(f"📋 Headers prepared (auth token length: {len(headers.get('Cookie', '').split('arena-auth-prod-v1=')[-1].split(';')[0])} chars)")
        
        # Check if conversation exists for this API key
        session = chat_sessions[api_key_str].get(conversation_id)
        
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
            
            debug_print(f"🔑 Generated session_id: {session_id}")
            debug_print(f"👤 Generated user_msg_id: {user_msg_id}")
            debug_print(f"🤖 Generated model_msg_id: {model_msg_id}")
            
            payload = {
                "id": session_id,
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "userMessage": {
                    "content": prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = "https://lmarena.ai/nextjs-api/stream/create-evaluation"
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
            
            payload = {
                "id": session["conversation_id"],
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
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
        
        # Get initial auth token using round-robin (excluding any failed ones)
        current_token = get_next_auth_token(exclude_tokens=failed_tokens)
        headers = get_request_headers_with_token(current_token)
        debug_print(f"🔑 Using token (round-robin): {current_token[:20]}...")
        
        # Retry logic wrapper
        async def make_request_with_retry(url, payload, http_method, max_retries=3):
            """Make request with automatic retry on 429/401 errors"""
            nonlocal current_token, headers, failed_tokens
            
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
                            # Add current token to failed set
                            failed_tokens.add(current_token)
                            debug_print(f"📝 Failed tokens so far: {len(failed_tokens)}")
                            
                            if attempt < max_retries - 1:
                                try:
                                    # Try with next token (excluding failed ones)
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    headers = get_request_headers_with_token(current_token)
                                    debug_print(f"🔄 Retrying with next token: {current_token[:20]}...")
                                    await asyncio.sleep(1)  # Brief delay
                                    continue
                                except HTTPException as e:
                                    debug_print(f"❌ No more tokens available: {e.detail}")
                                    break
                        
                        elif response.status_code == HTTPStatus.UNAUTHORIZED:
                            debug_print(f"🔒 Attempt {attempt + 1}/{max_retries} - Auth failed with token {current_token[:20]}...")
                            # Add current token to failed set
                            failed_tokens.add(current_token)
                            # Remove the expired token from config
                            remove_auth_token(current_token)
                            debug_print(f"📝 Failed tokens so far: {len(failed_tokens)}")
                            
                            if attempt < max_retries - 1:
                                try:
                                    # Try with next available token (excluding failed ones)
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    headers = get_request_headers_with_token(current_token)
                                    debug_print(f"🔄 Retrying with next token: {current_token[:20]}...")
                                    await asyncio.sleep(1)  # Brief delay
                                    continue
                                except HTTPException as e:
                                    debug_print(f"❌ No more tokens available: {e.detail}")
                                    break
                        
                        elif response.status_code in [HTTPStatus.BAD_REQUEST, HTTPStatus.FORBIDDEN]:
                            # LMArena sometimes returns: {"error":"recaptcha validation failed"}
                            if _is_recaptcha_validation_failed(response.text):
                                debug_print("🔄 Upstream rejected reCAPTCHA token. Refreshing and retrying...")
                                new_token = await refresh_recaptcha_token(force=True)
                                if not new_token:
                                    response.raise_for_status()
                                payload["recaptchaV3Token"] = new_token
                                await asyncio.sleep(1)  # Brief delay
                                continue

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
                nonlocal current_token, headers
                chunk_id = f"chatcmpl-{uuid.uuid4()}"
                
                # Retry logic for streaming
                max_retries = 3
                for attempt in range(max_retries):
                    # Reset response data for each attempt
                    response_text = ""
                    reasoning_text = ""
                    citations = []
                    try:
                        async with httpx.AsyncClient() as client:
                            debug_print(f"📡 Sending {http_method} request for streaming (attempt {attempt + 1}/{max_retries})...")
                            
                            if http_method == "PUT":
                                stream_context = client.stream('PUT', url, json=payload, headers=headers, timeout=120)
                            else:
                                stream_context = client.stream('POST', url, json=payload, headers=headers, timeout=120)
                            
                            async with stream_context as response:
                                # Log status with human-readable message
                                log_http_status(response.status_code, "LMArena API Stream")
                                
                                # Check for retry-able errors before processing stream
                                if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                                    debug_print(f"⏱️  Stream attempt {attempt + 1}/{max_retries}")
                                    if attempt < max_retries - 1:
                                        current_token = get_next_auth_token()
                                        headers = get_request_headers_with_token(current_token)
                                        debug_print(f"🔄 Retrying stream with next token: {current_token[:20]}...")
                                        await asyncio.sleep(1)
                                        continue
                                
                                elif response.status_code == HTTPStatus.UNAUTHORIZED:
                                    debug_print(f"🔒 Stream token expired")
                                    remove_auth_token(current_token)
                                    if attempt < max_retries - 1:
                                        try:
                                            current_token = get_next_auth_token()
                                            headers = get_request_headers_with_token(current_token)
                                            debug_print(f"🔄 Retrying stream with next token: {current_token[:20]}...")
                                            await asyncio.sleep(1)
                                            continue
                                        except HTTPException:
                                            debug_print(f"❌ No more tokens available")
                                            break
                                
                                elif response.status_code in [HTTPStatus.BAD_REQUEST, HTTPStatus.FORBIDDEN]:
                                    # For non-200 responses, LMArena may return JSON instead of a stream.
                                    body_bytes = await response.aread()
                                    body_text = body_bytes.decode("utf-8", errors="replace")
                                    if _is_recaptcha_validation_failed(body_text) and attempt < max_retries - 1:
                                        debug_print("🔄 Upstream rejected reCAPTCHA token (stream). Refreshing and retrying...")
                                        new_token = await refresh_recaptcha_token(force=True)
                                        if new_token:
                                            payload["recaptchaV3Token"] = new_token
                                            await asyncio.sleep(1)
                                            continue

                                log_http_status(response.status_code, "Stream Connection")
                                response.raise_for_status()
                                
                                async for line in response.aiter_lines():
                                    line = line.strip()
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
                                
                    except httpx.HTTPStatusError as e:
                        # Handle retry-able errors
                        if e.response.status_code in [429, 401] and attempt < max_retries - 1:
                            continue  # Retry loop will handle it
                        # Provide user-friendly error messages
                        if e.response.status_code == 429:
                            error_msg = "Rate limit exceeded on LMArena. Please try again in a few moments."
                            error_type = "rate_limit_error"
                        elif e.response.status_code == 401:
                            error_msg = "Unauthorized: Your LMArena auth token has expired or is invalid. Please get a new auth token from the dashboard."
                            error_type = "authentication_error"
                        else:
                            error_msg = f"LMArena API error: {e.response.status_code}"
                            error_type = "api_error"
                        
                        print(f"❌ {error_msg}")
                        error_chunk = {
                            "error": {
                                "message": error_msg,
                                "type": error_type,
                                "code": e.response.status_code
                            }
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        return
                    except Exception as e:
                        print(f"❌ Stream error: {str(e)}")
                        error_chunk = {
                            "error": {
                                "message": str(e),
                                "type": "internal_error"
                            }
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        return
            
            return StreamingResponse(generate_stream(), media_type="text/event-stream")
        
        # Handle non-streaming mode with retry
        try:
            response = await make_request_with_retry(url, payload, http_method)
            
            log_http_status(response.status_code, "LMArena API Response")
            debug_print(f"📏 Response length: {len(response.text)} characters")
            debug_print(f"📋 Response headers: {dict(response.headers)}")
            
            debug_print(f"🔍 Processing response...")
            debug_print(f"📄 First 500 chars of response:\n{response.text[:500]}")
            
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
            for line in response.text.splitlines():
                line_count += 1
                line = line.strip()
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
                debug_print(f"📄 Full raw response:\n{response.text}")
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
                error_detail = "Forbidden: Access to this resource is denied."
                error_type = "forbidden_error"
            elif e.response.status_code == HTTPStatus.NOT_FOUND:
                error_detail = "Not Found: The requested resource doesn't exist."
                error_type = "not_found_error"
            elif e.response.status_code == HTTPStatus.BAD_REQUEST:
                # Use LMArena's error message if available
                if lmarena_error:
                    error_detail = f"Bad Request: {lmarena_error}"
                else:
                    error_detail = "Bad Request: Invalid request parameters."
                error_type = "bad_request_error"
            elif e.response.status_code >= 500:
                error_detail = f"Server Error: LMArena API returned {e.response.status_code}"
                error_type = "server_error"
            else:
                # Use LMArena's error message if available
                if lmarena_error:
                    error_detail = f"LMArena API error: {lmarena_error}"
                else:
                    error_detail = f"LMArena API error: {e.response.status_code}"
                    try:
                        error_body = e.response.json()
                        error_detail += f" - {error_body}"
                    except:
                        error_detail += f" - {e.response.text[:200]}"
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
    print("=" * 60)
    print("🚀 LMArena Bridge Server Starting...")
    print("=" * 60)
    print(f"📍 Dashboard: http://localhost:{PORT}/dashboard")
    print(f"🔐 Login: http://localhost:{PORT}/login")
    print(f"📚 API Base URL: http://localhost:{PORT}/api/v1")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=PORT)
