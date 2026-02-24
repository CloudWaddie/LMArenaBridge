"""
Constants for LMArenaBridge.
All hardcoded values should be defined here.
"""

# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

# Set to True for detailed logging, False for minimal logging
DEBUG = True

# Port to run the server on
PORT = 8000

# Default config and models file paths
CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"

# ============================================================
# HTTP STATUS CODES
# ============================================================

class HTTPStatus:
    """HTTP Status Codes"""
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

# ============================================================
# RECAPTCHA CONSTANTS
# ============================================================

# Default reCAPTCHA sitekey and action from gpt4free/g4f/Provider/needs_auth/LMArena.py
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"

# reCAPTCHA Enterprise v2 sitekey used when v3 scoring fails and LMArena prompts a checkbox challenge
RECAPTCHA_V2_SITEKEY = "6Ld7ePYrAAAAAB34ovoFoDau1fqCJ6IyOjFEQaMn"

# Cloudflare Turnstile sitekey used by LMArena to mint anonymous-user signup tokens
TURNSTILE_SITEKEY = "0x4AAAAAAA65vWDmG-O_lPtT"

# ============================================================
# ARENA ORIGINS
# ============================================================

LMARENA_ORIGIN = "https://lmarena.ai"
ARENA_ORIGIN = "https://arena.ai"

ARENA_HOST_TO_ORIGIN = {
    "lmarena.ai": LMARENA_ORIGIN,
    "www.lmarena.ai": LMARENA_ORIGIN,
    "arena.ai": ARENA_ORIGIN,
    "www.arena.ai": ARENA_ORIGIN,
}

# ============================================================
# BROWSER FETCH MODELS
# ============================================================

# Models that should always use the in-browser (Chrome fetch) transport for streaming
STRICT_CHROME_FETCH_MODELS = {
    "gemini-3-pro-grounding",
    "gemini-exp-1206",
}

# ============================================================
# TIMEOUTS AND LIMITS
# ============================================================

# Default timeout for requests (seconds)
DEFAULT_REQUEST_TIMEOUT = 120

# reCAPTCHA timeout settings (milliseconds)
GRECAPTCHA_TIMEOUT_MS = 60000
GRECAPTCHA_POLL_MS = 250

# Token expiry margins (seconds)
TOKEN_EXPIRY_SKEW_SECONDS = 30
RECAPTCHA_TOKEN_EXPIRY_SECONDS = 110
RECAPTCHA_V3_TOKEN_LIFETIME_SECONDS = 120

# Background refresh interval (seconds)
PERIODIC_REFRESH_INTERVAL_SECONDS = 1800  # 30 minutes

# Rate limiting
RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMIT_RPM = 60

# ============================================================
# USERSCRIPT PROXY SETTINGS
# ============================================================

DEFAULT_USERSCRIPT_PROXY_POLL_TIMEOUT_SECONDS = 25
DEFAULT_USERSCRIPT_PROXY_JOB_TTL_SECONDS = 90
USERSCRIPT_PROXY_ACTIVE_WINDOW_BUFFER_SECONDS = 10
USERSCRIPT_PROXY_JOB_TTL_MAX_SECONDS = 600

# ============================================================
# BACKOFF SETTINGS
# ============================================================

# Exponential backoff for rate limit responses (429)
def get_rate_limit_backoff_seconds(retry_after: str | None, attempt: int) -> int:
    """Compute backoff seconds for upstream 429 responses."""
    if retry_after:
        try:
            value = int(float(retry_after.strip()))
        except Exception:
            value = 0
        if value > 0:
            return min(value, 3600)
    
    attempt = max(0, int(attempt))
    return min(5 * (2 ** attempt), 300)


def get_general_backoff_seconds(attempt: int) -> int:
    """Compute general exponential backoff seconds."""
    attempt = max(0, int(attempt))
    return min(2 * (2 ** attempt), 30)

# ============================================================
# BROWSER SETTINGS
# ============================================================

# Default browser window modes
DEFAULT_CAMOUFOX_PROXY_WINDOW_MODE = "hide"
DEFAULT_CAMOUFOX_FETCH_WINDOW_MODE = "hide"
DEFAULT_CHROME_FETCH_WINDOW_MODE = "hide"

# Window mode valid values
VALID_WINDOW_MODES = {"hide", "hidden", "minimize", "minimized", "offscreen", "off-screen", "moveoffscreen", "move-offscreen", "visible"}

# Chrome/Edge executable paths (Windows)
CHROME_PATH_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]
EDGE_PATH_CANDIDATES = [
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]

# Browser user agent
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ============================================================
# IMAGE UPLOAD SETTINGS
# ============================================================

MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

# Supported MIME types for image upload
SUPPORTED_IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
}

# ============================================================
# CLOUDFLARE COOKIE NAMES
# ============================================================

CF_CLEARANCE_COOKIE = "cf_clearance"
CF_BM_COOKIE = "__cf_bm"
CF_UVID_COOKIE = "_cfuvid"
PROVISIONAL_USER_ID_COOKIE = "provisional_user_id"
ARENA_AUTH_COOKIE = "arena-auth-prod-v1"
GRECAPTCHA_COOKIE = "_GRECAPTCHA"

# Cookie domains
ARENA_COOKIE_DOMAINS = (".lmarena.ai", ".arena.ai")

# ============================================================
# API ENDPOINTS
# ============================================================

ARENA_DIRECT_MODE_URL = "https://lmarena.ai/?mode=direct"
NEXTJS_API_SIGNUP = "/nextjs-api/sign-up"

# ============================================================
# CONTENT TYPES
# ============================================================

CONTENT_TYPE_TEXT_PLAIN_UTF8 = "text/plain;charset=UTF-8"
CONTENT_TYPE_APPLICATION_JSON = "application/json"

# ============================================================
# TURNSTILE SELECTORS
# ============================================================

TURNSTILE_SELECTORS = [
    '#lm-bridge-turnstile',
    '#lm-bridge-turnstile iframe',
    '#cf-turnstile', 
    'iframe[src*="challenges.cloudflare.com"]',
    '[style*="display: grid"] iframe'
]

TURNSTILE_INNER_SELECTORS = [
    "input[type='checkbox']",
    "div[role='checkbox']",
    "label",
]

# ============================================================
# HTTP HEADERS
# ============================================================

ARENA_ORIGIN_HEADER = "https://lmarena.ai"
ARENA_REFERER_HEADER = "https://lmarena.ai/?mode=direct"

# ============================================================
# SUPABASE
# ============================================================

# Regex pattern for finding Supabase JWT
SUPABASE_JWT_PATTERN = r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"

# ============================================================
# TURNSTILE / CLOUDFLARE
# ============================================================

CLOUDFLARE_CHALLENGE_TITLE = "Just a moment"
