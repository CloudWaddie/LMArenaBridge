from collections import defaultdict
from typing import Dict, Optional, List
from datetime import datetime, timezone, timedelta
import asyncio

# --- Constants & Global State ---
CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"

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

# Userscript proxy state
USERSCRIPT_PROXY_LAST_POLL_AT: float = 0.0
last_userscript_poll: float = 0.0 # Legacy timestamp used by older code paths/tests.

_USERSCRIPT_PROXY_QUEUE: Optional[asyncio.Queue] = None
_USERSCRIPT_PROXY_JOBS: dict[str, dict] = {}
