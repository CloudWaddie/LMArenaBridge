"""
Auth token management for LMArenaBridge.

Handles:
- Token decode/encode (base64 session, JWT)
- Token expiry detection
- Token refresh (via LMArena HTTP and Supabase)
- Round-robin token selection (get_next_auth_token)
- Token removal
- Browser session cookie helpers
- Supabase anon key extraction

Globals _m().EPHEMERAL_ARENA_AUTH_TOKEN, _m().SUPABASE_ANON_KEY, _m().current_token_index are owned
by main.py and accessed here via late imports (from . import main as _main) so that
test patches on main.X continue to work.
"""

import asyncio
import base64
import json
import re
import time
from typing import Optional

import httpx
from fastapi import HTTPException


def _m():
    """Late import of main module so tests can patch main.X and it is reflected here."""
    from . import main
    return main

def _combine_split_arena_auth_cookies(cookies: list[dict]) -> Optional[str]:
    """
    Combine split arena-auth-prod-v1.0 and .1 cookies into a single value.
    Google OAuth sometimes creates split cookies due to size limits.
    """
    parts = {}
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        if name == "arena-auth-prod-v1.0":
            parts[0] = str(cookie.get("value") or "")
        elif name == "arena-auth-prod-v1.1":
            parts[1] = str(cookie.get("value") or "")
    if 0 in parts and 1 in parts:
        combined = (parts[0] + parts[1]).strip()
        return combined if combined else None
    elif 0 in parts:
        value = parts[0].strip()
        return value if value else None
    return None


def _capture_ephemeral_arena_auth_token_from_cookies(cookies: list[dict]) -> None:
    """
    Capture the current `arena-auth-prod-v1` cookie value into an in-memory global.

    This keeps the bridge usable even if the user hasn't pasted tokens into config.json,
    while still honoring `persist_arena_auth_cookie` for persistence.
    """
    try:
        best: Optional[str] = None
        fallback: Optional[str] = None

        # First try to combine split cookies (.0 and .1)
        combined = _combine_split_arena_auth_cookies(cookies)
        if combined:
            try:
                if not is_arena_auth_token_expired(combined, skew_seconds=0):
                    _m().EPHEMERAL_ARENA_AUTH_TOKEN = combined
                    return
                fallback = combined  # It's expired, but a candidate for fallback.
            except Exception:
                # If expiry check fails, treat it as a valid token and return.
                _m().EPHEMERAL_ARENA_AUTH_TOKEN = combined
                return


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
            _m().EPHEMERAL_ARENA_AUTH_TOKEN = best
        elif fallback:
            _m().EPHEMERAL_ARENA_AUTH_TOKEN = fallback
    except Exception:
        return None


def _upsert_browser_session_into_config(config: dict, cookies: list[dict], user_agent: str | None = None) -> bool:
    """
    Persist useful browser session identity (cookies + UA) into config.json.
    This helps keep Cloudflare + LMArena auth aligned with reCAPTCHA/browser fetch flows.
    """
    changed = False

    cookie_store = config.get("browser_cookies")
    if not isinstance(cookie_store, dict):
        cookie_store = {}
        config["browser_cookies"] = cookie_store
        changed = True

    for cookie in cookies or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        name = str(name)
        if name == "arena-auth-prod-v1" and not bool(config.get("persist_arena_auth_cookie")):
            continue
        value = str(value)
        if cookie_store.get(name) != value:
            cookie_store[name] = value
            changed = True

    # Combine split cookies (.0 and .1) and save as arena-auth-prod-v1
    if bool(config.get("persist_arena_auth_cookie")):
        combined = _combine_split_arena_auth_cookies(cookies)
        if combined and cookie_store.get("arena-auth-prod-v1") != combined:
            cookie_store["arena-auth-prod-v1"] = combined
            changed = True

    # Promote frequently-used cookies to top-level config keys.
    cf_clearance = str(cookie_store.get("cf_clearance") or "").strip()
    cf_bm = str(cookie_store.get("__cf_bm") or "").strip()
    cfuvid = str(cookie_store.get("_cfuvid") or "").strip()
    provisional_user_id = str(cookie_store.get("provisional_user_id") or "").strip()

    if cf_clearance and config.get("cf_clearance") != cf_clearance:
        config["cf_clearance"] = cf_clearance
        changed = True
    if cf_bm and config.get("cf_bm") != cf_bm:
        config["cf_bm"] = cf_bm
        changed = True
    if cfuvid and config.get("cfuvid") != cfuvid:
        config["cfuvid"] = cfuvid
        changed = True
    if provisional_user_id and config.get("provisional_user_id") != provisional_user_id:
        config["provisional_user_id"] = provisional_user_id
        changed = True

    ua = str(user_agent or "").strip()
    if ua and str(config.get("user_agent") or "").strip() != ua:
        config["user_agent"] = ua
        changed = True

    return changed


def normalize_user_agent_value(user_agent: object) -> str:
    ua = str(user_agent or "").strip()
    if not ua:
        return ""
    if ua.lower() in ("user-agent", "user agent"):
        return ""
    return ua


def get_request_headers_with_token(token: str, recaptcha_v3_token: Optional[str] = None):
    """Get request headers with a specific auth token and optional reCAPTCHA v3 token"""
    config = _m().get_config()
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
        _, recaptcha_action = _m().get_recaptcha_settings(config)
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

    cfg = config or _m().get_config()
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

    Requires the Supabase anon key (public client key). We keep it in-memory (_m().SUPABASE_ANON_KEY) by default.
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

    key = str(anon_key or _m().SUPABASE_ANON_KEY or "").strip()
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

    cfg = _m().get_config()
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
        cfg = _m().get_config()
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
            _m().EPHEMERAL_ARENA_AUTH_TOKEN = new_token
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

    cfg = _m().get_config()
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
        cfg = _m().get_config()
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

            _m().EPHEMERAL_ARENA_AUTH_TOKEN = new_token
            return new_token

    return None


def get_next_auth_token(exclude_tokens: set = None, *, allow_ephemeral_fallback: bool = True):
    """Get next auth token using round-robin selection
     
    Args:
        exclude_tokens: Set of tokens to exclude from selection (e.g., already tried tokens)
        allow_ephemeral_fallback: If True, may fall back to an in-memory `_m().EPHEMERAL_ARENA_AUTH_TOKEN` when all
            configured tokens are excluded.
    """
    config = _m().get_config()
    
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
    if not auth_tokens and _m().EPHEMERAL_ARENA_AUTH_TOKEN and not is_arena_auth_token_expired(_m().EPHEMERAL_ARENA_AUTH_TOKEN):
        # Use an in-memory token captured from the browser session as a fallback (do not override configured tokens).
        auth_tokens = [_m().EPHEMERAL_ARENA_AUTH_TOKEN]
    if not auth_tokens:
        cookie_store = config.get("browser_cookies")
        if isinstance(cookie_store, dict) and bool(config.get("persist_arena_auth_cookie")):
            token = str(cookie_store.get("arena-auth-prod-v1") or "").strip()
            if token and not is_arena_auth_token_expired(token):
                config["auth_tokens"] = [token]
                _m().save_config(config, preserve_auth_tokens=False)
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
                    candidate = str(_m().EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
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
    token = available_tokens[_m().current_token_index % len(available_tokens)]
    _m().current_token_index = (_m().current_token_index + 1) % len(auth_tokens)
    # If we selected a token we can conclusively determine is expired, prefer a valid in-memory token
    # captured from the browser session (Camoufox/Chrome) rather than hammering upstream with 401s.
    try:
        if token and is_arena_auth_token_expired(token, skew_seconds=0):
            candidate = str(_m().EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
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
        config = _m().get_config()
        prune_enabled = config.get("prune_invalid_tokens", False)
        
        if not prune_enabled and not force:
            _m().debug_print(f"🔒 Token failed but pruning is disabled. Keep in config: {token[:20]}...")
            return

        auth_tokens = config.get("auth_tokens", [])
        if token in auth_tokens:
            auth_tokens.remove(token)
            config["auth_tokens"] = auth_tokens
            _m().save_config(config, preserve_auth_tokens=False)
            _m().debug_print(f"🗑️  Removed expired token from list: {token[:20]}...")
    except Exception as e:
        _m().debug_print(f"⚠️  Error removing auth token: {e}")