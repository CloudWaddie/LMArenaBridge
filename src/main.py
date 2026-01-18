import sys
import uvicorn
import asyncio
import os
import uuid
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.responses import HTMLResponse, RedirectResponse

try:
    from . import globals
    from . import config
    from . import models
    from . import browser
    from .utils import debug_print
    from .routes import dashboard, chat, proxy
except ImportError:
    import globals
    import config
    import models
    import browser
    from utils import debug_print
    from routes import dashboard, chat, proxy

PORT = 8000

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Prevent unit tests (TestClient/ASGITransport) from clobbering the user's real config.json
    # and running slow browser/network startup routines.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        yield
        return

    try:
        debug_print("🚀 LMArena Bridge Server Starting...")

        # Ensure config and models files exist
        cfg = config.get_config()
        if not cfg.get("api_keys"):
            cfg["api_keys"] = [
                {
                    "name": "Default Key",
                    "key": f"sk-lmab-{uuid.uuid4()}",
                    "rpm": 60,
                    "created": int(time.time()),
                }
            ]
        config.save_config(cfg)
        models.save_models(models.get_models())
        # Load usage stats from config
        config.load_usage_stats()
        
        # 1. First, get initial data (cookies, models, etc.)
        await browser.get_initial_data()

        # Best-effort: refresh expired auth tokens on startup
        try:
            from . import auth
        except ImportError:
            import auth

        try:
            refreshed = await auth.maybe_refresh_expired_auth_tokens()
        except Exception:
            refreshed = None
        if refreshed:
            debug_print("🔄 Refreshed arena-auth-prod-v1 session (startup).")
        
        # 2. Start background tasks
        asyncio.create_task(browser.periodic_refresh_task())
        
        # Mark userscript proxy as active at startup
        now = time.time()
        globals.last_userscript_poll = now
        globals.USERSCRIPT_PROXY_LAST_POLL_AT = now
        
        asyncio.create_task(browser.camoufox_proxy_worker())
        
    except Exception as e:
        debug_print(f"❌ Error during startup: {e}")
        # Continue anyway - server should still start
    
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(dashboard.router)
app.include_router(chat.router)
app.include_router(proxy.router)

if __name__ == "__main__":
    # Avoid crashes on Windows consoles with non-UTF8 code pages (e.g., GBK) when printing emojis.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 60)
    print("🚀 LMArena Bridge Server Starting...")
    print("=" * 60)
    print(f"📍 Dashboard: http://localhost:{PORT}/dashboard")
    print(f"🔐 Login: http://localhost:{PORT}/login")
    print(f"📚 API Base URL: http://localhost:{PORT}/api/v1")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=PORT)
