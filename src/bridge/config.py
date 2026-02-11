import json
import os
import time
from collections import defaultdict
from typing import Optional

from fastapi.security import APIKeyHeader

from .runtime import debug_print

CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)

# Token cycling: current index for round-robin selection
current_token_index = 0
# Track config file path changes to reset per-config state in tests/dev.
_LAST_CONFIG_FILE: Optional[str] = None


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

        # Environment overrides (preferred for secrets)
        env_password = str(os.environ.get("ADMIN_PASSWORD") or os.environ.get("ADMIN_PASS") or "").strip()
        if env_password:
            config["password"] = env_password

        env_auth_token = str(os.environ.get("ARENA_AUTH_TOKEN") or "").strip()
        if env_auth_token:
            config["auth_token"] = env_auth_token

        env_auth_tokens = str(os.environ.get("AUTH_TOKENS") or "").strip()
        if env_auth_tokens:
            tokens = [t.strip() for t in env_auth_tokens.split(",") if t.strip()]
            if tokens:
                config["auth_tokens"] = tokens

        # Normalize api_keys to prevent KeyErrors in dashboard and rate limiting
        if isinstance(config.get("api_keys"), list):
            normalized_keys = []
            for i, key_entry in enumerate(config["api_keys"]):
                if isinstance(key_entry, dict):
                    # Ensure 'key' exists as it's critical
                    if "key" not in key_entry:
                        continue  # Skip invalid entries missing the actual key

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


def load_usage_stats(model_usage_stats):
    """Load usage stats from config into memory"""
    try:
        config = get_config()
        model_usage_stats.clear()
        model_usage_stats.update(defaultdict(int, config.get("usage_stats", {})))
    except Exception as e:
        debug_print(f"⚠️  Error loading usage stats: {e}, using empty stats")
        model_usage_stats.clear()


def save_config(config, *, preserve_auth_tokens: bool = True):
    try:
        # Avoid clobbering user-provided auth tokens when multiple tasks write config.json concurrently.
        # Background refreshes/cookie upserts shouldn't overwrite auth tokens that may have been added via the dashboard.
        if preserve_auth_tokens:
            try:
                latest = get_config()
            except Exception:
                latest = None
            if isinstance(latest, dict):
                if "auth_token" in latest and "auth_token" not in config:
                    config["auth_token"] = latest.get("auth_token", "")
                if "auth_tokens" in latest and "auth_tokens" not in config:
                    config["auth_tokens"] = latest.get("auth_tokens", [])
                if "api_keys" in latest and "api_keys" not in config:
                    config["api_keys"] = latest.get("api_keys", [])
                if "password" in latest and "password" not in config:
                    config["password"] = latest.get("password", "")
                if "cf_clearance" in latest and "cf_clearance" not in config:
                    config["cf_clearance"] = latest.get("cf_clearance", "")
                if "usage_stats" in latest and "usage_stats" not in config:
                    config["usage_stats"] = latest.get("usage_stats", {})
                if "persist_arena_auth_cookie" in latest and "persist_arena_auth_cookie" not in config:
                    config["persist_arena_auth_cookie"] = latest.get("persist_arena_auth_cookie", False)
                if "prune_invalid_tokens" in latest and "prune_invalid_tokens" not in config:
                    config["prune_invalid_tokens"] = latest.get("prune_invalid_tokens", False)

        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        debug_print(f"⚠️  Error saving config: {e}")
