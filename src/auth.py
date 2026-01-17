import json
import base64
import re
import time
import httpx
import uuid
from typing import Optional, List, Set
from fastapi import HTTPException, Request, Depends
from fastapi.security import APIKeyHeader

try:
    from . import globals
    from . import config
    from .utils import debug_print
except ImportError:
    import globals
    import config
    from utils import debug_print

# Updated constants from gpt4free/g4f/Provider/needs_auth/LMArena.py
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"
# reCAPTCHA Enterprise v2 sitekey used when v3 scoring fails and LMArena prompts a checkbox challenge.
RECAPTCHA_V2_SITEKEY = "6Ld7ePYrAAAAAB34ovoFoDau1fqCJ6IyOjFEQaMn"
# Cloudflare Turnstile sitekey used by LMArena to mint anonymous-user signup tokens.
# (Used for POST /nextjs-api/sign-up before `arena-auth-prod-v1` exists.)
TURNSTILE_SITEKEY = "0x4AAAAAAA65vWDmG-O_lPtT"

API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)

_SUPABASE_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")

def extract_recaptcha_params_from_text(text: str) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(text, str) or not text:
        return None, None

    discovered_sitekey: Optional[str] = None
    discovered_action: Optional[str] = None

    # 1) Prefer direct matches from execute(sitekey,{action:"..."}) when present.
    if "execute" in text and "action" in text:
        patterns = [
            r'grecaptcha\.enterprise\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'grecaptcha\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
            # Fallback for minified code that aliases grecaptcha to another identifier.
            r'\.execute\(\s*["\'](?P<sitekey>6[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
        ]
        for pattern in patterns:
            try:
                match = re.search(pattern, text)
            except re.error:
                continue
            if not match:
                continue
            sitekey = str(match.group("sitekey") or "").strip()
            action = str(match.group("action") or "").strip()
            if sitekey and action:
                return sitekey, action

    # 2) Discover sitekey from the enterprise.js/api.js render URL (common in HTML/JS chunks).
    # Example: https://www.google.com/recaptcha/enterprise.js?render=SITEKEY
    sitekey_patterns = [
        r'recaptcha/(?:enterprise|api)\.js\?render=(?P<sitekey>[0-9A-Za-z_-]{8,200})',
        r'(?:enterprise|api)\.js\?render=(?P<sitekey>[0-9A-Za-z_-]{8,200})',
    ]
    for pattern in sitekey_patterns:
        try:
            match = re.search(pattern, text)
        except re.error:
            continue
        if not match:
            continue
        sitekey = str(match.group("sitekey") or "").strip()
        if sitekey:
            discovered_sitekey = sitekey
            break

    # 3) Discover action from headers/constants in client-side code.
    if "recaptcha" in text.lower() or "X-Recaptcha-Action" in text or "x-recaptcha-action" in text:
        action_patterns = [
            r'X-Recaptcha-Action["\']\s*[:=]\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'X-Recaptcha-Action["\']\s*,\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'x-recaptcha-action["\']\s*[:=]\s*["\'](?P<action>[^"\']{1,80})["\']',
        ]
        for pattern in action_patterns:
            try:
                match = re.search(pattern, text)
            except re.error:
                continue
            if not match:
                continue
            action = str(match.group("action") or "").strip()
            if action:
                discovered_action = action
                break

    return discovered_sitekey, discovered_action


def get_recaptcha_settings(cfg: Optional[dict] = None) -> tuple[str, str]:
    cfg = cfg or config.get_config()
    sitekey = str((cfg or {}).get("recaptcha_sitekey") or "").strip()
    action = str((cfg or {}).get("recaptcha_action") or "").strip()
    if not sitekey:
        sitekey = RECAPTCHA_SITEKEY
    if not action:
        action = RECAPTCHA_ACTION
    return sitekey, action

def normalize_user_agent_value(user_agent: object) -> str:
    ua = str(user_agent or "").strip()
    if not ua:
        return ""
    if ua.lower() in ("user-agent", "user agent"):
        return ""
    return ua

def get_request_headers_with_token(token: str, recaptcha_v3_token: Optional[str] = None):
    """Get request headers with a specific auth token and optional reCAPTCHA v3 token"""
    cfg = config.get_config()
    cf_clearance = str(cfg.get("cf_clearance") or "").strip()
    cf_bm = str(cfg.get("cf_bm") or "").strip()
    cfuvid = str(cfg.get("cfuvid") or "").strip()
    provisional_user_id = str(cfg.get("provisional_user_id") or "").strip()

    cookie_store = cfg.get("browser_cookies")
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

    user_agent = normalize_user_agent_value(cfg.get("user_agent"))
    if user_agent:
        headers["User-Agent"] = user_agent

    if recaptcha_v3_token:
        headers["X-Recaptcha-Token"] = recaptcha_v3_token
        _, recaptcha_action = get_recaptcha_settings(cfg)
        headers["X-Recaptcha-Action"] = recaptcha_action
    return headers

def get_request_headers():
    """Get request headers with the first available auth token (for compatibility)"""
    cfg = config.get_config()

    # Try to get token from auth_tokens first, then fallback to single token
    auth_tokens = cfg.get("auth_tokens", [])
    if auth_tokens:
        token = auth_tokens[0]  # Just use first token for non-API requests
    else:
        token = cfg.get("auth_token", "").strip()
        if not token:
            cookie_store = cfg.get("browser_cookies")
            if isinstance(cookie_store, dict) and bool(cfg.get("persist_arena_auth_cookie")):
                token = str(cookie_store.get("arena-auth-prod-v1") or "").strip()
                if token:
                    cfg["auth_tokens"] = [token]
                    config.save_config(cfg, preserve_auth_tokens=False)
        if not token:
            raise HTTPException(status_code=500, detail="Arena auth token not set in dashboard.")

    return get_request_headers_with_token(token)

def _decode_arena_auth_session_token(token: str) -> Optional[dict]:
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

def extract_supabase_anon_key_from_text(text: str) -> Optional[str]:
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
    token = str(token or "").strip()
    if not token:
        return False
    if token.startswith("base64-"):
        session = _decode_arena_auth_session_token(token)
        if not isinstance(session, dict):
            return False
        if not session.get("access_token") or not session.get("refresh_token"):
            return False
        return True

    # If not base64, assume it's a JWT access token directly
    payload = _decode_jwt_payload(token)
    if isinstance(payload, dict):
        return True
    return False

def get_next_auth_token(exclude_tokens: Optional[Set[str]] = None, allow_ephemeral_fallback: bool = True) -> str:
    """
    Get the next available auth token in round-robin fashion.
    """
    cfg = config.get_config()

    # Check both auth_tokens list and single auth_token
    auth_tokens = cfg.get("auth_tokens", [])
    if not auth_tokens and cfg.get("auth_token"):
        auth_tokens = [cfg.get("auth_token")]

    # Filter out excluded tokens
    if exclude_tokens:
        available_tokens = [t for t in auth_tokens if t not in exclude_tokens]
    else:
        available_tokens = auth_tokens

    # If no tokens configured/available, check if we have a captured browser cookie token.
    # This allows the bridge to work zero-config if the browser automation captured a token recently.
    if not available_tokens:
        if allow_ephemeral_fallback and globals.EPHEMERAL_ARENA_AUTH_TOKEN:
            cand = str(globals.EPHEMERAL_ARENA_AUTH_TOKEN).strip()
            if cand and cand not in (exclude_tokens or set()):
                # Only use it if it looks valid
                if is_probably_valid_arena_auth_token(cand):
                    return cand

        # Raise 401/500 if we truly have nothing.
        if not auth_tokens:
            raise HTTPException(status_code=500, detail="Arena auth token not set in dashboard.")
        else:
            raise HTTPException(status_code=401, detail="All available auth tokens have failed or are rate-limited.")

    # Simple round-robin
    token = available_tokens[globals.current_token_index % len(available_tokens)]
    globals.current_token_index = (globals.current_token_index + 1) % len(available_tokens)

    return token

def get_available_auth_tokens_count() -> int:
    cfg = config.get_config()
    tokens = cfg.get("auth_tokens", [])
    if not tokens and cfg.get("auth_token"):
        return 1
    return len(tokens)


async def _refresh_token_via_http(refresh_url: str, payload: dict, headers: dict) -> Optional[dict]:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(refresh_url, json=payload, headers=headers, timeout=20.0)
            if resp.status_code == 200:
                try:
                    return resp.json()
                except Exception:
                    return None
            return None
    except Exception:
        return None

async def refresh_arena_auth_token_via_lmarena_http(token: str, cfg: dict) -> Optional[str]:
    """
    Attempt to refresh a base64-encoded LMArena session token via LMArena's backend (which proxies to Supabase).
    """
    session = _decode_arena_auth_session_token(token)
    if not isinstance(session, dict):
        return None

    refresh_token = str(session.get("refresh_token") or "").strip()
    if not refresh_token:
        return None

    # Try LMArena's own refresh endpoint if available (reverse-engineered path)
    # Usually: POST /api/auth/v1/token?grant_type=refresh_token
    # Or Supabase direct. LMArena often exposes the Supabase Anon Key in the client bundle.

    # Without the anon key, we can't easily hit Supabase directly unless we scrape it.
    # `refresh_arena_auth_token_via_supabase` handles the direct Supabase path.
    # This function is a placeholder if LMArena adds a server-side proxy endpoint.
    return None


async def refresh_arena_auth_token_via_supabase(token: str) -> Optional[str]:
    """
    Attempt to refresh the token directly against the Supabase project used by LMArena.
    Requires the public anon key (scraped from JS).
    """
    if not globals.SUPABASE_ANON_KEY:
        return None

    session = _decode_arena_auth_session_token(token)
    if not isinstance(session, dict):
        return None

    refresh_token = str(session.get("refresh_token") or "").strip()
    if not refresh_token:
        return None

    # Derive project URL from the issuer or a known constant.
    # LMArena (currently) uses a specific Supabase project.
    base_url = _derive_supabase_auth_base_url_from_arena_auth_token(token)
    if not base_url:
        # Fallback to known LMArena Supabase URL if derivation fails (optional/risky if they change it).
        # For now, rely on derivation from the JWT 'iss' claim.
        return None

    target_url = base_url.rstrip("/") + "/token?grant_type=refresh_token"
    headers = {
        "apikey": globals.SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }
    payload = {"refresh_token": refresh_token}

    res = await _refresh_token_via_http(target_url, payload, headers)
    if not res:
        return None

    # The response is a new session object.
    # We need to wrap it back into "base64-<json>".
    new_token = maybe_build_arena_auth_cookie_from_signup_response_body(json.dumps(res))
    return new_token


async def maybe_refresh_expired_auth_tokens(exclude_tokens: Optional[Set[str]] = None) -> Optional[str]:
    """
    Scan configured tokens. If any are expired (base64 sessions), try to refresh them.
    Returns the first successfully refreshed token string, or None.
    """
    cfg = config.get_config()
    tokens = cfg.get("auth_tokens", [])
    if not isinstance(tokens, list):
        tokens = []

    # Identify candidates
    refreshed_any = False
    first_refreshed: Optional[str] = None

    new_list = []
    for t in tokens:
        t = str(t or "").strip()
        if not t:
            continue

        # If it's excluded (failed recently), we can still try to refresh it if it's expired!
        # But if it failed because it was revoked, refresh will fail too.

        if is_arena_auth_token_expired(t, skew_seconds=60):
            debug_print(f"🔄 Token {t[:15]}... appears expired. Attempting refresh...")
            new_val = await refresh_arena_auth_token_via_lmarena_http(t, cfg)
            if not new_val:
                new_val = await refresh_arena_auth_token_via_supabase(t)

            if new_val:
                debug_print(f"✅ Token refreshed successfully!")
                new_list.append(new_val)
                refreshed_any = True
                if not first_refreshed:
                    first_refreshed = new_val
            else:
                debug_print("❌ Token refresh failed.")
                # Keep the old one? Or prune?
                # If prune_invalid_tokens is on, we might drop it.
                if cfg.get("prune_invalid_tokens"):
                    debug_print("🗑️ Pruning expired/invalid token.")
                else:
                    new_list.append(t)
        else:
            new_list.append(t)

    if refreshed_any:
        cfg["auth_tokens"] = new_list
        config.save_config(cfg)

    return first_refreshed

# --- Dashboard Authentication ---

async def get_current_session(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in globals.dashboard_sessions:
        return globals.dashboard_sessions[session_id]
    return None

# --- API Key Authentication & Rate Limiting ---

async def rate_limit_api_key(key: str = Depends(API_KEY_HEADER)):
    cfg = config.get_config()
    api_keys = cfg.get("api_keys", [])

    api_key_str = None
    if key and key.startswith("Bearer "):
        api_key_str = key[7:].strip()

    # Pragmatic fallback: if Authorization is missing/empty, use the first available key
    if not api_key_str:
        if api_keys:
            api_key_str = api_keys[0]["key"]
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
    if api_key_str in globals.api_key_usage:
        globals.api_key_usage[api_key_str] = [t for t in globals.api_key_usage[api_key_str] if current_time - t < 60]

    if len(globals.api_key_usage[api_key_str]) >= rate_limit:
        # Calculate seconds until oldest request expires (60 seconds window)
        oldest_timestamp = min(globals.api_key_usage[api_key_str]) if globals.api_key_usage[api_key_str] else current_time
        retry_after = int(60 - (current_time - oldest_timestamp))
        retry_after = max(1, retry_after)  # At least 1 second

        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )

    globals.api_key_usage[api_key_str].append(current_time)

    return key_data

def _capture_ephemeral_arena_auth_token_from_cookies(cookies: list[dict]) -> None:
    """
    Capture the current `arena-auth-prod-v1` cookie value into an in-memory global.

    This keeps the bridge usable even if the user hasn't pasted tokens into config.json,
    while still honoring `persist_arena_auth_cookie` for persistence.
    """
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
            globals.EPHEMERAL_ARENA_AUTH_TOKEN = best
        elif fallback:
            globals.EPHEMERAL_ARENA_AUTH_TOKEN = fallback
    except Exception:
        return None
