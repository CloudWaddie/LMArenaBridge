import json
import os

try:
    from . import globals
    from .utils import debug_print
except ImportError:
    import globals
    from utils import debug_print

def get_config():
    # If tests or callers swap CONFIG_FILE at runtime, reset the token round-robin index so token selection
    # is deterministic per config file.
    if globals._LAST_CONFIG_FILE != globals.CONFIG_FILE:
        globals._LAST_CONFIG_FILE = globals.CONFIG_FILE
        globals.current_token_index = 0
    try:
        with open(globals.CONFIG_FILE, "r") as f:
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

        # Normalize api_keys to prevent KeyErrors in dashboard and rate limiting
        if isinstance(config.get("api_keys"), list):
            normalized_keys = []
            for i, key_entry in enumerate(config["api_keys"]):
                if isinstance(key_entry, dict):
                    # Ensure 'key' exists as it's critical
                    if "key" not in key_entry:
                        continue # Skip invalid entries missing the actual key

                    if "name" not in key_entry:
                        key_entry["name"] = "Unnamed Key"
                    if "created" not in key_entry:
                        # Use a default old timestamp (Jan 3 2024)
                        key_entry["created"] = 1704236400
                    if "rpm" not in key_entry:
                        key_entry["rpm"] = 60
                    normalized_keys.append(key_entry)
            config["api_keys"] = normalized_keys
    except Exception as e:
        debug_print(f"⚠️  Error setting config defaults: {e}")

    return config

def load_usage_stats():
    """Load usage stats from config into memory"""
    try:
        config = get_config()
        # Update the global model_usage_stats in place
        globals.model_usage_stats.clear()
        globals.model_usage_stats.update(config.get("usage_stats", {}))
    except Exception as e:
        debug_print(f"⚠️  Error loading usage stats: {e}, using empty stats")
        globals.model_usage_stats.clear()

def save_config(config, *, preserve_auth_tokens: bool = True):
    try:
        # Avoid clobbering user-provided auth tokens when multiple tasks write config.json concurrently.
        # Background refreshes/cookie upserts shouldn't overwrite auth tokens that may have been added via the dashboard.
        if preserve_auth_tokens:
            try:
                with open(globals.CONFIG_FILE, "r") as f:
                    on_disk = json.load(f)
            except Exception:
                on_disk = None

            if isinstance(on_disk, dict):
                if "auth_tokens" in on_disk and isinstance(on_disk.get("auth_tokens"), list):
                    config["auth_tokens"] = list(on_disk.get("auth_tokens") or [])
                if "auth_token" in on_disk:
                    config["auth_token"] = str(on_disk.get("auth_token") or "")

        # Persist in-memory stats to the config dict before saving
        config["usage_stats"] = dict(globals.model_usage_stats)
        tmp_path = f"{globals.CONFIG_FILE}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
        os.replace(tmp_path, globals.CONFIG_FILE)
    except Exception as e:
        debug_print(f"❌ Error saving config: {e}")

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
