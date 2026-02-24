"""
Global state management for LMArenaBridge.
Holds in-memory state that needs to be shared across modules.
"""

from collections import defaultdict
from typing import Dict, Any, Optional
import time


# In-memory stores
chat_sessions: Dict[str, Dict[str, dict]] = defaultdict(dict)
dashboard_sessions: Dict[str, str] = {}
api_key_usage: Dict[str, list] = defaultdict(list)
model_usage_stats: defaultdict = defaultdict(int)

# Token cycling
current_token_index: int = 0

# Config file tracking
_last_config_file: Optional[str] = None

# Conversation tracking
conversation_tokens: Dict[str, str] = {}
request_failed_tokens: Dict[str, set] = {}

# Ephemeral tokens
EPHEMERAL_ARENA_AUTH_TOKEN: Optional[str] = None
SUPABASE_ANON_KEY: Optional[str] = None

# reCAPTCHA
RECAPTCHA_TOKEN: Optional[str] = None
RECAPTCHA_EXPIRY: Any = None  # Will be set on init


def get_model_usage_stats() -> defaultdict:
    return model_usage_stats


def set_model_usage_stats(stats: defaultdict) -> None:
    global model_usage_stats
    model_usage_stats = stats


def get_current_token_index() -> int:
    return current_token_index


def set_current_token_index(index: int) -> None:
    global current_token_index
    current_token_index = index


def increment_token_index(length: int) -> int:
    global current_token_index
    if length > 0:
        current_token_index = (current_token_index + 1) % length
    return current_token_index
