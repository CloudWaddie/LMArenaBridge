"""
Global state management for LMArenaBridge.
Holds in-memory state that needs to be shared across modules.
"""

from collections import defaultdict
from typing import Dict, Any, Optional


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
# Initialize expiry far in the past to force a refresh on startup
RECAPTCHA_EXPIRY: Any = None  # Will be set on init

# Image cache: { md5_hash: { key: str, url: str, expiry: float } }
IMAGES_CACHE: Dict[str, dict] = {}

# Discovered actions: { action_name: action_id }
DISCOVERED_ACTIONS: Dict[str, str] = {}
