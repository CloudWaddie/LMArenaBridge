"""
Configuration management for LMArenaBridge.
Handles loading, saving, and managing configuration.
"""

import json
import os
from typing import Optional, Dict, Any
from collections import defaultdict

from . import constants


# Global state
_current_config_file: str = constants.CONFIG_FILE
_current_token_index: int = 0


def get_config_file() -> str:
    """Get the current config file path."""
    return _current_config_file


def set_config_file(path: str) -> None:
    """Set the config file path (useful for tests)."""
    global _current_config_file, _current_token_index
    if _current_config_file != path:
        _current_config_file = path
        _current_token_index = 0


def get_config() -> dict:
    """
    Load configuration from file with defaults.
    Returns a dictionary with all configuration values.
    """
    global _current_token_index
    
    # Reset token index if config file changed
    if _current_token_index != 0:
        global_state = _get_global_state()
        if global_state.get("_last_config_file") != _current_config_file:
            _current_token_index = 0
    
    try:
        with open(_current_config_file, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {}
    except Exception:
        config = {}

    # Ensure default keys exist
    _apply_config_defaults(config)
    
    return config


def _apply_config_defaults(config: dict) -> None:
    """Apply default values to config dictionary."""
    config.setdefault("password", "admin")
    config.setdefault("auth_token", "")
    config.setdefault("auth_tokens", [])
    config.setdefault("cf_clearance", "")
    config.setdefault("api_keys", [])
    config.setdefault("usage_stats", {})
    config.setdefault("prune_invalid_tokens", False)
    config.setdefault("persist_arena_auth_cookie", False)
    config.setdefault("camoufox_proxy_window_mode", constants.DEFAULT_CAMOUFOX_PROXY_WINDOW_MODE)
    config.setdefault("camoufox_fetch_window_mode", constants.DEFAULT_CAMOUFOX_FETCH_WINDOW_MODE)
    config.setdefault("chrome_fetch_window_mode", constants.DEFAULT_CHROME_FETCH_WINDOW_MODE)
    
    # Normalize api_keys
    if isinstance(config.get("api_keys"), list):
        normalized_keys = []
        for key_entry in config["api_keys"]:
            if isinstance(key_entry, dict):
                if "key" not in key_entry:
                    continue
                if "name" not in key_entry:
                    key_entry["name"] = "Unnamed Key"
                if "created" not in key_entry:
                    key_entry["created"] = 1704236400  # Default timestamp
                if "rpm" not in key_entry:
                    key_entry["rpm"] = constants.DEFAULT_RATE_LIMIT_RPM
                normalized_keys.append(key_entry)
        config["api_keys"] = normalized_keys


def save_config(config: dict, *, preserve_auth_tokens: bool = True) -> None:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary to save
        preserve_auth_tokens: If True, don't overwrite auth tokens from disk
    """
    try:
        if preserve_auth_tokens:
            try:
                with open(_current_config_file, "r") as f:
                    on_disk = json.load(f)
            except Exception:
                on_disk = None

            if isinstance(on_disk, dict):
                if "auth_tokens" in on_disk and isinstance(on_disk.get("auth_tokens"), list):
                    config["auth_tokens"] = list(on_disk.get("auth_tokens") or [])
                if "auth_token" in on_disk:
                    config["auth_token"] = str(on_disk.get("auth_token") or "")

        # usage_stats will be set by the caller
        
        tmp_path = f"{_current_config_file}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
        os.replace(tmp_path, _current_config_file)
    except Exception as e:
        print(f"Error saving config: {e}")


# Global state storage (for cross-module state)
_global_state: Dict[str, Any] = {}


def _get_global_state() -> Dict[str, Any]:
    """Get the global state dictionary."""
    return _global_state


def set_global_state(key: str, value: Any) -> None:
    """Set a global state value."""
    _global_state[key] = value


def get_global_state(key: str, default: Any = None) -> Any:
    """Get a global state value."""
    return _global_state.get(key, default)


# === Model management ===

def get_models() -> list:
    """Load models from file."""
    try:
        with open(constants.MODELS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_models(models: list) -> None:
    """Save models to file."""
    try:
        tmp_path = f"{constants.MODELS_FILE}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(models, f, indent=2)
        os.replace(tmp_path, constants.MODELS_FILE)
    except Exception as e:
        print(f"Error saving models: {e}")


# === Default config for startup ===

def get_default_config() -> dict:
    """Get default configuration values."""
    return {
        "password": "admin",
        "auth_token": "",
        "auth_tokens": [],
        "cf_clearance": "",
        "api_keys": [
            {
                "name": "Default Key",
                "key": "",  # Will be generated
                "rpm": constants.DEFAULT_RATE_LIMIT_RPM,
                "created": 0,
            }
        ],
        "usage_stats": {},
        "prune_invalid_tokens": False,
        "persist_arena_auth_cookie": False,
        "camoufox_proxy_window_mode": constants.DEFAULT_CAMOUFOX_PROXY_WINDOW_MODE,
        "camoufox_fetch_window_mode": constants.DEFAULT_CAMOUFOX_FETCH_WINDOW_MODE,
        "chrome_fetch_window_mode": constants.DEFAULT_CHROME_FETCH_WINDOW_MODE,
    }
