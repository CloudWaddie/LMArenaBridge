import os
import time

# Set to True for detailed logging, False for minimal logging
DEBUG = str(os.environ.get("DEBUG", "false")).strip().lower() in {"1", "true", "yes", "y"}

# Port to run the server on
PORT = int(os.environ.get("PORT", "8000"))

# --- Runtime ---
START_TIME = time.monotonic()

# Circuit breaker for upstream LMArena
UPSTREAM_FAILURES = 0
UPSTREAM_CIRCUIT_OPEN_UNTIL = 0.0
UPSTREAM_CIRCUIT_THRESHOLD = int(os.environ.get("UPSTREAM_CIRCUIT_THRESHOLD", "5"))
UPSTREAM_CIRCUIT_COOLDOWN = int(os.environ.get("UPSTREAM_CIRCUIT_COOLDOWN", "60"))


def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is True"""
    if DEBUG:
        print(*args, **kwargs)


def is_upstream_circuit_open() -> bool:
    return time.monotonic() < UPSTREAM_CIRCUIT_OPEN_UNTIL


def record_upstream_success() -> None:
    global UPSTREAM_FAILURES, UPSTREAM_CIRCUIT_OPEN_UNTIL
    UPSTREAM_FAILURES = 0
    UPSTREAM_CIRCUIT_OPEN_UNTIL = 0.0


def record_upstream_failure() -> None:
    global UPSTREAM_FAILURES, UPSTREAM_CIRCUIT_OPEN_UNTIL
    UPSTREAM_FAILURES += 1
    if UPSTREAM_FAILURES >= UPSTREAM_CIRCUIT_THRESHOLD:
        UPSTREAM_CIRCUIT_OPEN_UNTIL = time.monotonic() + max(1, UPSTREAM_CIRCUIT_COOLDOWN)
