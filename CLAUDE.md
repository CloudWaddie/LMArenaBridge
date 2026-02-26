# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the server
python src/main.py

# Run all tests
python -m pytest tests/

# Run a single test file
python -m pytest tests/test_stream_403_recaptcha_retries.py -v

# Run a single test by name
python -m pytest tests/test_stream_403_recaptcha_retries.py::TestStream403RecaptchaRetries::test_stream_403_recaptcha_validation_failed_retries_with_fresh_token -v

# Syntax check
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read()); print('OK')"
```

Python version: **3.12** (see `.python-version`).

## Architecture

This is an OpenAI-compatible API bridge to LM Arena (`lmarena.ai`). It exposes `POST /api/v1/chat/completions` and proxies requests through LMArena's internal API using browser automation to handle Cloudflare/reCAPTCHA challenges.

### Module structure (`src/`)

- **`main.py`** (~4700 lines) — FastAPI app, all route handlers, request/streaming logic, startup lifespan. Re-exports all symbols from submodules for backward compat.
- **`constants.py`** — All hardcoded values: HTTP status codes, sitekeys, timeouts, URLs, cookie names, selectors, path candidates.
- **`config.py`** — Config file I/O (`get_config`, `save_config`, `get_models`, `save_models`, `_apply_config_defaults`). Note: `main.py` has its own `get_config` that respects `main.CONFIG_FILE` (tests monkey-patch this), and its own `save_config` that flushes `model_usage_stats`.
- **`state.py`** — In-memory shared state (chat sessions, token cycling, reCAPTCHA token, ephemeral auth token, etc.).
- **`browser_utils.py`** — Windows/Playwright browser utilities: `_is_windows`, `_maybe_apply_camoufox_window_mode`, `click_turnstile`, `safe_page_evaluate`, `_cancel_background_task`, etc.
- **`auth.py`** — Auth token management: decode/encode, expiry checks, round-robin selection, Supabase/LMArena refresh, ephemeral cookie capture.
- **`recaptcha.py`** — reCAPTCHA v3/v2 token minting via Chrome (Playwright) and Camoufox. Includes `get_recaptcha_v3_token`, `get_cached_recaptcha_token`, `refresh_recaptcha_token`.
- **`transport.py`** — Transport layer: `BrowserFetchStreamResponse`, `UserscriptProxyStreamResponse`, all three fetch strategies (`fetch_lmarena_stream_via_chrome`, `fetch_lmarena_stream_via_camoufox`, `fetch_lmarena_stream_via_userscript_proxy`), Camoufox proxy worker, `push_proxy_chunk`.

### Cross-module pattern (`_m()` late import)

All submodules access `main.py` globals and functions via a lazy import helper:

```python
def _m():
    from . import main
    return main
```

This ensures that `patch.object(test.main, "X", mock)` in tests correctly intercepts calls from submodules (e.g. `_m().get_config()` resolves to the patched version). Key globals that must stay in `main.py`: `CONFIG_FILE`, `chat_sessions`, `current_token_index`, `EPHEMERAL_ARENA_AUTH_TOKEN`, `RECAPTCHA_TOKEN`, `RECAPTCHA_EXPIRY`, `_USERSCRIPT_PROXY_JOBS`, `_USERSCRIPT_PROXY_QUEUE`, `USERSCRIPT_PROXY_LAST_POLL_AT`, `last_userscript_poll`.

### Transport layer

The chat completions endpoint selects a transport based on model and config:

1. **Direct httpx** — Standard async HTTP via `httpx.AsyncClient`. Used for most models.
2. **Chrome fetch** (`fetch_lmarena_stream_via_chrome`) — Launches a real Chrome/Edge browser via Playwright to execute `fetch()` in-page. Used for `STRICT_CHROME_FETCH_MODELS` and as primary when reCAPTCHA v3 is needed.
3. **Camoufox fetch** (`fetch_lmarena_stream_via_camoufox`) — Firefox-based (Camoufox) browser transport. Fallback when Chrome is blocked or failing repeatedly. Uses `main_world_eval=True` for reCAPTCHA JS injection.
4. **Userscript proxy** (`fetch_lmarena_stream_via_userscript_proxy`) — Long-poll mechanism where a browser userscript does the actual fetch. Used when no auth token is configured.

Transport selection adapts: after 2+ consecutive Chrome reCAPTCHA failures, switches to Camoufox; after 2+ Camoufox failures, switches back to Chrome.

### Auth token lifecycle

- Tokens are `arena-auth-prod-v1` JWT cookies from LMArena.
- `get_next_auth_token()` does round-robin over `config["auth_tokens"]`, filtering expired tokens.
- `EPHEMERAL_ARENA_AUTH_TOKEN` holds a token captured from browser sessions (not persisted unless `persist_arena_auth_cookie: true`).
- Expired tokens can be refreshed via `refresh_arena_auth_token_via_lmarena_http()` or `refresh_arena_auth_token_via_supabase()`.
- `maybe_refresh_expired_auth_tokens()` is called proactively before requests fail.

### Startup flow (`lifespan` / `get_initial_data`)

On startup, `get_initial_data()` launches a Camoufox browser to:
1. Scrape the LMArena page to discover reCAPTCHA sitekey/action and Supabase anon key.
2. Fetch the models list and available arena action IDs.
3. Optionally mint an initial reCAPTCHA v3 token.

`periodic_refresh_task()` repeats this every 30 minutes. During testing, startup is skipped via `PYTEST_CURRENT_TEST` env var.

### Userscript proxy

A two-sided long-poll system:
- `POST /api/v1/userscript/poll` — Browser userscript polls for fetch jobs
- `POST /api/v1/userscript/push` — Userscript pushes response chunks back
- `camoufox_proxy_worker()` — A singleton background Camoufox browser that handles anonymous signup (Turnstile challenge) and preflight token refresh

### Dashboard

`GET /dashboard` serves a full HTML admin UI (Chart.js) for managing auth tokens, API keys, usage stats, and triggering token refreshes. Session auth is via a password in `config.json`.

### Key global state in `main.py`

- `chat_sessions` — Per-API-key conversation history
- `current_token_index` — Round-robin pointer for auth tokens
- `EPHEMERAL_ARENA_AUTH_TOKEN` / `SUPABASE_ANON_KEY` / `RECAPTCHA_TOKEN` / `RECAPTCHA_EXPIRY` — Discovered at runtime
- `_USERSCRIPT_PROXY_JOBS` / `_USERSCRIPT_PROXY_QUEUE` — Pending proxy jobs

### Testing

Tests use `unittest.IsolatedAsyncioTestCase` via `BaseBridgeTest` in `tests/_stream_test_utils.py`. Each test:
- Writes a temp `config.json` and patches `main.CONFIG_FILE` to point to it
- Clears `main.chat_sessions` and `main.api_key_usage` between tests
- Uses `FakeStreamResponse` / `FakeStreamContext` to mock `httpx.AsyncClient.stream`
- Uses `unittest.mock.patch` on `src.main.*` functions

Browser-dependent tests (camoufox, chrome) are separate files and may be skipped in CI.

### Config file (`config.json`)

Key fields: `auth_tokens` (list), `auth_token` (legacy single), `api_keys` (list of `{name, key, rpm, created}`), `password`, `cf_clearance`, `persist_arena_auth_cookie`, `camoufox_proxy_window_mode`, `camoufox_fetch_window_mode`, `chrome_fetch_window_mode`.

### Active refactor branch

`refactor/modularize` — Modularization is complete. Extracted modules: `constants.py`, `config.py`, `state.py`, `browser_utils.py`, `auth.py`, `recaptcha.py`, `transport.py`. `main.py` re-exports all symbols via `from .X import ...` for backward compat. `get_config` remains local in `main.py` because tests patch `main.CONFIG_FILE` directly.
