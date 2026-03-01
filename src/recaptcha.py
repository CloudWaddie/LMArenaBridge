"""
reCAPTCHA and browser challenge handling for LMArenaBridge.

Handles:
- reCAPTCHA v3 token minting via Chrome (Playwright) and Camoufox
- reCAPTCHA v3 token caching and refresh
- Camoufox anonymous user signup (Turnstile)
- Finding Chrome/Edge executable
- Provisional user ID injection into browser context
- LMArena auth cookie recovery from localStorage

Cross-module globals (_m().RECAPTCHA_TOKEN, _m().RECAPTCHA_EXPIRY, _m().SUPABASE_ANON_KEY) are
accessed via _m() late-import of main so test patches remain effective.
"""

import asyncio
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


def _m():
    """Late import of main module so tests can patch main.X and it is reflected here."""
    from . import main
    return main


def extract_recaptcha_params_from_text(text: str) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(text, str) or not text:
        return None, None

    discovered_sitekey: Optional[str] = None
    discovered_action: Optional[str] = None

    # 1) Prefer direct matches from execute(sitekey,{action:"..."}) when present.
    if "execute" in text and "action" in text:
        patterns = [
            r'grecaptcha\.enterprise\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'grecaptcha\.execute\(\s*["\'](?P<sitekey>[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
            # Fallback for minified code that aliases grecaptcha to another identifier.
            r'\.execute\(\s*["\'](?P<sitekey>6[0-9A-Za-z_-]{8,200})["\']\s*,\s*\{\s*(?:action|["\']action["\'])\s*:\s*["\'](?P<action>[^"\']{1,80})["\']',
        ]
        for pattern in patterns:
            try:
                match = re.search(pattern, text)
            except re.error:
                continue
            if not match:
                continue
            sitekey = str(match.group("sitekey") or "").strip()
            action = str(match.group("action") or "").strip()
            if sitekey and action:
                return sitekey, action

    # 2) Discover sitekey from the enterprise.js/api.js render URL (common in HTML/JS chunks).
    # Example: https://www.google.com/recaptcha/enterprise.js?render=SITEKEY
    sitekey_patterns = [
        r'recaptcha/(?:enterprise|api)\.js\?render=(?P<sitekey>[0-9A-Za-z_-]{8,200})',
        r'(?:enterprise|api)\.js\?render=(?P<sitekey>[0-9A-Za-z_-]{8,200})',
    ]
    for pattern in sitekey_patterns:
        try:
            match = re.search(pattern, text)
        except re.error:
            continue
        if not match:
            continue
        sitekey = str(match.group("sitekey") or "").strip()
        if sitekey:
            discovered_sitekey = sitekey
            break

    # 3) Discover action from headers/constants in client-side code.
    if "recaptcha" in text.lower() or "X-Recaptcha-Action" in text or "x-recaptcha-action" in text:
        action_patterns = [
            r'X-Recaptcha-Action["\']\s*[:=]\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'X-Recaptcha-Action["\']\s*,\s*["\'](?P<action>[^"\']{1,80})["\']',
            r'x-recaptcha-action["\']\s*[:=]\s*["\'](?P<action>[^"\']{1,80})["\']',
        ]
        for pattern in action_patterns:
            try:
                match = re.search(pattern, text)
            except re.error:
                continue
            if not match:
                continue
            action = str(match.group("action") or "").strip()
            if action:
                discovered_action = action
                break

    return discovered_sitekey, discovered_action


def get_recaptcha_settings(config: Optional[dict] = None) -> tuple[str, str]:
    cfg = config or _m().get_config()
    sitekey = str((cfg or {}).get("recaptcha_sitekey") or "").strip()
    action = str((cfg or {}).get("recaptcha_action") or "").strip()
    if not sitekey:
        sitekey = _m().RECAPTCHA_SITEKEY
    if not action:
        action = _m().RECAPTCHA_ACTION
    return sitekey, action


async def _mint_recaptcha_v3_token_in_page(
    page,
    *,
    sitekey: str,
    action: str,
    grecaptcha_timeout_ms: int = 60000,
    grecaptcha_poll_ms: int = 250,
    outer_timeout_seconds: float = 70.0,
) -> str:
    """
    Best-effort reCAPTCHA v3 token minting inside an existing page.

    LMArena currently requires a `recaptchaToken` (action: "sign_up") for anonymous signup.
    """
    sitekey = str(sitekey or "").strip()
    action = str(action or "").strip()
    if not sitekey:
        return ""
    if not action:
        action = "sign_up"

    mint_js = """async ({ sitekey, action, timeoutMs, pollMs }) => {
      // LM_BRIDGE_MINT_RECAPTCHA_V3
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const w = (window.wrappedJSObject || window);
      const key = String(sitekey || '');
      const act = String(action || 'sign_up');
      const limit = Math.max(1000, Math.min(Number(timeoutMs || 60000), 180000));
      const poll = Math.max(50, Math.min(Number(pollMs || 250), 2000));
      const start = Date.now();

      const pickG = () => {
        const ent = w?.grecaptcha?.enterprise;
        if (ent && typeof ent.execute === 'function' && typeof ent.ready === 'function') return ent;
        const g = w?.grecaptcha;
        if (g && typeof g.execute === 'function' && typeof g.ready === 'function') return g;
        return null;
      };

      const inject = () => {
        try {
          if (w.__LM_BRIDGE_RECAPTCHA_INJECTED) return;
          w.__LM_BRIDGE_RECAPTCHA_INJECTED = true;
          const h = w.document?.head;
          if (!h) return;
          const urls = [
            'https://www.google.com/recaptcha/enterprise.js?render=' + encodeURIComponent(key),
            'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(key),
          ];
          for (const u of urls) {
            const s = w.document.createElement('script');
            s.src = u;
            s.async = true;
            s.defer = true;
            h.appendChild(s);
          }
        } catch (e) { console.error('LM Bridge: reCAPTCHA v3 script injection failed', e); }
      };

      let injected = false;
      while ((Date.now() - start) < limit) {
        const g = pickG();
        if (g) {
          try {
            // g.ready can hang; guard with a short timeout.
            await Promise.race([
              new Promise((resolve) => { try { g.ready(resolve); } catch (e) { console.error('LM Bridge: reCAPTCHA v3 ready callback failed', e); resolve(true); } }),
              sleep(5000),
            ]);
          } catch (e) { console.error('LM Bridge: reCAPTCHA v3 ready wait failed', e); }
          try {
            // Firefox Xray wrappers: build params in the page compartment.
            const params = new w.Object();
            params.action = act;
            const tok = await g.execute(key, params);
            return String(tok || '');
          } catch (e) {
            console.error('LM Bridge: reCAPTCHA v3 execute failed', e);
            return '';
          }
        }
        if (!injected) { injected = true; inject(); }
        await sleep(poll);
      }
      return '';
    }"""

    try:
        tok = await asyncio.wait_for(
            page.evaluate(
                mint_js,
                {
                    "sitekey": sitekey,
                    "action": action,
                    "timeoutMs": int(grecaptcha_timeout_ms),
                    "pollMs": int(grecaptcha_poll_ms),
                },
            ),
            timeout=float(outer_timeout_seconds),
        )
    except asyncio.TimeoutError:
        _m().debug_print("reCAPTCHA v3 mint timed out in page.")
        tok = ""
    except Exception as e:
        _m().debug_print(f"Unexpected error minting reCAPTCHA v3 token in page: {type(e).__name__}: {e}")
        tok = ""
    return str(tok or "").strip()


async def _camoufox_proxy_signup_anonymous_user(
    page,
    *,
    turnstile_token: str,
    provisional_user_id: str,
    recaptcha_sitekey: str,
    recaptcha_action: str = "sign_up",
) -> Optional[dict]:
    """
    Perform LMArena anonymous signup using the same flow as the site JS:
    POST /nextjs-api/sign-up with {turnstileToken, recaptchaToken, provisionalUserId}.
    """
    turnstile_token = str(turnstile_token or "").strip()
    provisional_user_id = str(provisional_user_id or "").strip()
    recaptcha_sitekey = str(recaptcha_sitekey or "").strip()
    recaptcha_action = str(recaptcha_action or "").strip() or "sign_up"

    if not turnstile_token or not provisional_user_id:
        return None

    recaptcha_token = await _mint_recaptcha_v3_token_in_page(
        page,
        sitekey=recaptcha_sitekey,
        action=recaptcha_action,
    )
    if not recaptcha_token:
        _m().debug_print("⚠️ Camoufox proxy: reCAPTCHA mint failed for anonymous signup.")
        return None

    sign_up_js = """async ({ turnstileToken, recaptchaToken, provisionalUserId }) => {
      // LM_BRIDGE_ANON_SIGNUP
      const w = (window.wrappedJSObject || window);
      const opts = new w.Object();
      opts.method = 'POST';
      opts.credentials = 'include';
      // Match site behavior: let the browser set Content-Type for string bodies (text/plain;charset=UTF-8).
      opts.body = JSON.stringify({
        turnstileToken: String(turnstileToken || ''),
        recaptchaToken: String(recaptchaToken || ''),
        provisionalUserId: String(provisionalUserId || ''),
      });
      const res = await w.fetch('/nextjs-api/sign-up', opts);
      let text = '';
      try { text = await res.text(); } catch (e) { text = ''; }
      return { status: Number(res.status || 0), ok: !!res.ok, body: String(text || '') };
    }"""

    try:
        resp = await asyncio.wait_for(
            page.evaluate(
                sign_up_js,
                {
                    "turnstileToken": turnstile_token,
                    "recaptchaToken": recaptcha_token,
                    "provisionalUserId": provisional_user_id,
                },
            ),
            timeout=20.0,
        )
    except Exception as e:
        _m().debug_print(f"Unexpected error during anonymous signup evaluate: {type(e).__name__}: {e}")
        resp = None
    return resp if isinstance(resp, dict) else None


async def _set_provisional_user_id_in_browser(page, context, *, provisional_user_id: str) -> None:
    """
    Best-effort: keep the provisional user id consistent across cookies and storage.

    LMArena uses `provisional_user_id` to mint/restore anonymous sessions. If multiple storages disagree (e.g. a stale
    localStorage value vs a rotated cookie), /nextjs-api/sign-up can fail with confusing errors like "User already exists".
    """
    provisional_user_id = str(provisional_user_id or "").strip()
    if not provisional_user_id:
        return

    try:
        if context is not None:
            # Keep cookie variants in sync:
            # - Some sessions store `provisional_user_id` as a domain cookie on `.lmarena.ai`
            # - Others store it as a host-only cookie on `lmarena.ai` (via `url`)
            # If the two disagree, upstream can reject /nextjs-api/sign-up with confusing errors.
            await context.add_cookies(_m()._provisional_user_id_cookie_specs(provisional_user_id))
    except Exception as e:
        _m().debug_print(f"Failed to set provisional_user_id cookies in browser context: {type(e).__name__}: {e}")

    try:
        await page.evaluate(
            """(pid) => {
              const w = (window.wrappedJSObject || window);
              try { w.localStorage.setItem('provisional_user_id', String(pid || '')); } catch (e) {}
              return true;
            }""",
            provisional_user_id,
        )
    except Exception as e:
        _m().debug_print(f"Failed to set provisional_user_id in localStorage: {type(e).__name__}: {e}")


async def _maybe_inject_arena_auth_cookie_from_localstorage(page, context) -> Optional[str]:
    """
    Best-effort: recover a missing `arena-auth-prod-v1` cookie from browser storage.

    Some auth flows keep the Supabase session JSON in localStorage. If the cookie is missing but the session is still
    present, we can encode it into the `base64-<json>` cookie format and inject it.
    """
    if page is None or context is None:
        return None

    try:
        store = await page.evaluate(
            """() => {
              const w = (window.wrappedJSObject || window);
              try {
                const ls = w.localStorage;
                if (!ls) return {};
                const out = {};
                for (let i = 0; i < ls.length; i++) {
                  const k = ls.key(i);
                  if (!k) continue;
                  const key = String(k);
                  if (!(key.includes('auth') || key.includes('sb-') || key.includes('supabase') || key.includes('session'))) continue;
                  out[key] = String(ls.getItem(key) || '');
                }
                return out;
              } catch (e) {
                return {};
              }
            }"""
    )
    except Exception:
        return None

    if not isinstance(store, dict):
        return None

    for _, raw in list(store.items()):
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            cookie = _m().maybe_build_arena_auth_cookie_from_signup_response_body(text)
        except Exception:
            cookie = None
        if not cookie:
            continue
        try:
            if _m().is_arena_auth_token_expired(cookie, skew_seconds=0):
                continue
        except Exception:
            pass

        try:
            try:
                page_url = str(getattr(page, "url", "") or "")
            except Exception:
                page_url = ""
            await context.add_cookies(_m()._arena_auth_cookie_specs(cookie, page_url=page_url))
            _m()._capture_ephemeral_arena_auth_token_from_cookies([{"name": "arena-auth-prod-v1", "value": cookie}])
            _m().debug_print("🦊 Camoufox proxy: injected arena-auth cookie from localStorage session.")
            return cookie
        except Exception:
            continue

    return None


def find_chrome_executable() -> Optional[str]:
    configured = str(os.environ.get("CHROME_PATH") or "").strip()
    if configured and Path(configured).exists():
        return configured

    candidates = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        / "Google"
        / "Chrome"
        / "Application"
        / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
        / "Google"
        / "Chrome"
        / "Application"
        / "chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Google"
        / "Chrome"
        / "Application"
        / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    for name in ("google-chrome", "chrome", "chromium", "chromium-browser", "msedge"):
        resolved = shutil.which(name)
        if resolved:
            return resolved

    return None


async def get_recaptcha_v3_token_with_chrome(config: dict) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return None

    chrome_path = find_chrome_executable()
    if not chrome_path:
        return None

    profile_dir = Path(_m().CONFIG_FILE).with_name("chrome_grecaptcha")

    cf_clearance = str(config.get("cf_clearance") or "").strip()
    cf_bm = str(config.get("cf_bm") or "").strip()
    cfuvid = str(config.get("cfuvid") or "").strip()
    provisional_user_id = str(config.get("provisional_user_id") or "").strip()
    user_agent = _m().normalize_user_agent_value(config.get("user_agent"))
    recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(config)

    cookies = []
    if cf_clearance:
        cookies.append({"name": "cf_clearance", "value": cf_clearance, "domain": ".lmarena.ai", "path": "/"})
    if cf_bm:
        cookies.append({"name": "__cf_bm", "value": cf_bm, "domain": ".lmarena.ai", "path": "/"})
    if cfuvid:
        cookies.append({"name": "_cfuvid", "value": cfuvid, "domain": ".lmarena.ai", "path": "/"})
    if provisional_user_id:
        cookies.append(
            {"name": "provisional_user_id", "value": provisional_user_id, "domain": ".lmarena.ai", "path": "/"}
        )

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            executable_path=chrome_path,
            headless=False,  # Headful for better reCAPTCHA score/warmup
            user_agent=user_agent or None,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )
        try:
            # Small stealth tweak: reduces bot-detection surface for reCAPTCHA v3 scoring.
            try:
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
            except Exception:
                pass

            if cookies:
                try:
                    existing_names: set[str] = set()
                    try:
                        existing = await _m()._get_arena_context_cookies(context)
                        for c in existing or []:
                            name = c.get("name")
                            if name:
                                existing_names.add(str(name))
                    except Exception:
                        existing_names = set()

                    cookies_to_add: list[dict] = []
                    for c in cookies:
                        name = str(c.get("name") or "")
                        if not name:
                            continue
                        # Always ensure the auth cookie matches the selected upstream token.
                        if name == "arena-auth-prod-v1":
                            cookies_to_add.append(c)
                            continue

                        # Do NOT overwrite/inject Cloudflare or reCAPTCHA cookies in the persistent profile.
                        # The profile manages these itself; injecting stale ones from config causes 403s.
                        if name in ("cf_clearance", "__cf_bm", "_GRECAPTCHA"):
                            continue

                        # Avoid overwriting existing Cloudflare/session cookies in the persistent profile.
                        if name in existing_names:
                            continue
                        cookies_to_add.append(c)

                    if cookies_to_add:
                        await context.add_cookies(cookies_to_add)
                except Exception:
                    pass

            page = await context.new_page()
            await _m()._maybe_apply_camoufox_window_mode(
                page,
                config,
                mode_key="chrome_fetch_window_mode",
                marker="LMArenaBridge Chrome Fetch",
                headless=False,
            )
            await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)

            # Best-effort: if we land on a Cloudflare challenge page, try clicking Turnstile.
            try:
                for _ in range(5):
                    title = await page.title()
                    if "Just a moment" not in title:
                        break
                    await _m().click_turnstile(page)
                    await asyncio.sleep(2)
            except Exception:
                pass

            # Light warm-up (often improves reCAPTCHA v3 score vs firing immediately).
            try:
                await page.mouse.move(100, 100)
                await page.mouse.wheel(0, 200)
                await asyncio.sleep(1)
                await page.mouse.move(200, 300)
                await page.mouse.wheel(0, 300)
                await asyncio.sleep(3) # Increased "Human" pause
            except Exception:
                pass

            # Persist updated cookies/UA from this real browser context (often refreshes arena-auth-prod-v1).
            try:
                fresh_cookies = await _m()._get_arena_context_cookies(context, page_url=str(getattr(page, "url", "") or ""))
                try:
                    ua_now = await page.evaluate("() => navigator.userAgent")
                except Exception:
                    ua_now = user_agent
                if _m()._upsert_browser_session_into_config(config, fresh_cookies, user_agent=ua_now):
                    _m().save_config(config)
            except Exception:
                pass

            await page.wait_for_function(
                "window.grecaptcha && ("
                "(window.grecaptcha.enterprise && typeof window.grecaptcha.enterprise.execute === 'function') || "
                "typeof window.grecaptcha.execute === 'function'"
                ")",
                timeout=60000,
            )

            token = await page.evaluate(
                """({sitekey, action}) => new Promise((resolve, reject) => {
                  const g = (window.grecaptcha?.enterprise && typeof window.grecaptcha.enterprise.execute === 'function')
                    ? window.grecaptcha.enterprise
                    : window.grecaptcha;
                  if (!g || typeof g.execute !== 'function') return reject('NO_GRECAPTCHA');
                  try {
                    g.execute(sitekey, { action }).then(resolve).catch((err) => reject(String(err)));
                  } catch (e) { reject(String(e)); }
                })""",
                {"sitekey": recaptcha_sitekey, "action": recaptcha_action},
            )
            if isinstance(token, str) and token:
                return token
            return None
        except Exception as e:
            _m().debug_print(f"⚠️ Chrome reCAPTCHA retrieval failed: {e}")
            return None
        finally:
            await context.close()


async def get_recaptcha_v3_token() -> Optional[str]:
    """
    Retrieves reCAPTCHA v3 token using a 'Side-Channel' approach.
    We write the token to a global window variable and poll for it, 
    bypassing Promise serialization issues in the Main World bridge.
    """
    _m().debug_print("🔐 Starting reCAPTCHA v3 token retrieval (Side-Channel Mode)...")
    
    config = _m().get_config()
    cf_clearance = config.get("cf_clearance", "")
    recaptcha_sitekey, recaptcha_action = get_recaptcha_settings(config)
    
    try:
        chrome_token = await _m().get_recaptcha_v3_token_with_chrome(config)
        if chrome_token:
            _m().RECAPTCHA_TOKEN = chrome_token
            _m().RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
            return chrome_token

        # Use isolated world (main_world_eval=False) to avoid execution context destruction issues.
        # We will access the main world objects via window.wrappedJSObject.
        async with _m().AsyncCamoufox(headless=True, main_world_eval=False) as browser:
            context = await browser.new_context()
            if cf_clearance:
                await context.add_cookies([{
                    "name": "cf_clearance",
                    "value": cf_clearance,
                    "domain": ".lmarena.ai",
                    "path": "/"
                }])

            page = await context.new_page()
            
            _m().debug_print("  🌐 Navigating to lmarena.ai...")
            await page.goto("https://lmarena.ai/", wait_until="domcontentloaded")

            # --- NEW: Cloudflare/Turnstile Pass-Through ---
            _m().debug_print("  🛡️  Checking for Cloudflare Turnstile...")
            
            # Allow time for the widget to render if it's going to
            try:
                # Check for challenge title or widget presence
                # click_turnstile() includes a 2-second wait after successful click
                max_attempts = _m().constants.TURNSTILE_MAX_ATTEMPTS  # 15 attempts with 2s click_turnstile wait = 30s max
                for attempt in range(max_attempts):
                    title = await page.title()
                    if _m().CLOUDFLARE_CHALLENGE_TITLE not in title:
                        # Title changed - Turnstile likely completed
                        _m().debug_print(f"  ✅ Turnstile challenge resolved (title: {title[:30]}...)")
                        break
                    _m().debug_print(f"  🔒 Cloudflare challenge active (attempt {attempt + 1}/{max_attempts})...")
                    clicked = await _m().click_turnstile(page)
                    if clicked:
                        _m().debug_print("  🖱️  Clicked Turnstile.")
                    # Note: click_turnstile() already includes 2-second wait after successful click
                
                # Wait for the page to actually settle into the main app
                await page.wait_for_load_state("domcontentloaded")
            except Exception as e:
                _m().debug_print(f"  ⚠️ Error handling Turnstile: {e}")
            # ----------------------------------------------

            # 1. Wake up the page (Humanize)
            _m().debug_print("  🖱️  Waking up page...")
            await page.mouse.move(100, 100)
            await page.mouse.wheel(0, 200)
            await asyncio.sleep(2) # Vital "Human" pause

            # 2. Check for Library
            _m().debug_print("  ⏳ Checking for library...")
            # Use wrappedJSObject to check for grecaptcha in the main world
            lib_ready = await _m().safe_page_evaluate(
                page,
                "() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && w.grecaptcha.enterprise); }",
            )
            if not lib_ready:
                _m().debug_print("  ⚠️ Library not found immediately. Waiting...")
                await asyncio.sleep(3)
                lib_ready = await _m().safe_page_evaluate(
                    page,
                    "() => { const w = window.wrappedJSObject || window; return !!(w.grecaptcha && w.grecaptcha.enterprise); }",
                )
                if not lib_ready:
                    _m().debug_print("❌ reCAPTCHA library never loaded.")
                    return None

            # 3. SETUP: Initialize our global result variable
            # We use a unique name to avoid conflicts
            await _m().safe_page_evaluate(page, "() => { (window.wrappedJSObject || window).__token_result = 'PENDING'; }")

            # 4. TRIGGER: Execute reCAPTCHA and write to the variable
            # We do NOT await the result here. We just fire the process.
            _m().debug_print("  🚀 Triggering reCAPTCHA execution...")
            trigger_script = f"""() => {{
                const w = window.wrappedJSObject || window;
                try {{
                    w.grecaptcha.enterprise.execute('{recaptcha_sitekey}', {{ action: '{recaptcha_action}' }})
                    .then(token => {{
                        w.__token_result = token;
                    }})
                    .catch(err => {{
                        w.__token_result = 'ERROR: ' + err.toString();
                    }});
                }} catch (e) {{
                    w.__token_result = 'SYNC_ERROR: ' + e.toString();
                }}
            }}"""
            
            await _m().safe_page_evaluate(page, trigger_script)

            # 5. POLL: Watch the variable for changes
            _m().debug_print("  👀 Polling for result...")
            token = None
            
            for i in range(20): # Wait up to 20 seconds
                # Read the global variable
                result = await _m().safe_page_evaluate(page, "() => (window.wrappedJSObject || window).__token_result", retries=2)
                
                if result != 'PENDING':
                    if result and result.startswith('ERROR'):
                        _m().debug_print(f"❌ JS Execution Error: {result}")
                        return None
                    elif result and result.startswith('SYNC_ERROR'):
                        _m().debug_print(f"❌ JS Sync Error: {result}")
                        return None
                    else:
                        token = result
                        _m().debug_print(f"✅ Token captured! ({len(token)} chars)")
                        break
                
                if i % 2 == 0:
                    _m().debug_print(f"    ... waiting ({i}s)")
                await asyncio.sleep(1)

            if token:
                _m().RECAPTCHA_TOKEN = token
                _m().RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
                return token
            else:
                _m().debug_print("❌ Timed out waiting for token variable to update.")
                return None

    except Exception as e:
        _m().debug_print(f"❌ Unexpected error: {e}")
        return None


async def refresh_recaptcha_token(force_new: bool = False):
    """Checks if the global reCAPTCHA token is expired and refreshes it if necessary."""
    
    current_time = datetime.now(timezone.utc)
    if force_new:
        _m().RECAPTCHA_TOKEN = None
        _m().RECAPTCHA_EXPIRY = current_time - timedelta(days=365)
    # Unit tests should never launch real browser automation. Tests that need a token patch
    # `refresh_recaptcha_token` / `get_recaptcha_v3_token` explicitly.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return get_cached_recaptcha_token() or None
    # Check if token is expired (set a refresh margin of 10 seconds)
    if _m().RECAPTCHA_TOKEN is None or current_time > _m().RECAPTCHA_EXPIRY - timedelta(seconds=10):
        _m().debug_print("🔄 Recaptcha token expired or missing. Refreshing...")
        new_token = await get_recaptcha_v3_token()
        if new_token:
            _m().RECAPTCHA_TOKEN = new_token
            # reCAPTCHA v3 tokens typically last 120 seconds (2 minutes)
            _m().RECAPTCHA_EXPIRY = current_time + timedelta(seconds=120)
            _m().debug_print(f"✅ Recaptcha token refreshed, expires at {_m().RECAPTCHA_EXPIRY.isoformat()}")
            return new_token
        else:
            _m().debug_print("❌ Failed to refresh recaptcha token.")
            # Set a short retry delay if refresh fails
            _m().RECAPTCHA_EXPIRY = current_time + timedelta(seconds=10)
            return None
    
    return _m().RECAPTCHA_TOKEN


def get_cached_recaptcha_token() -> str:
    """Return the current reCAPTCHA v3 token if it's still valid, without refreshing."""
    token = _m().RECAPTCHA_TOKEN
    if not token:
        return ""
    current_time = datetime.now(timezone.utc)
    if current_time > _m().RECAPTCHA_EXPIRY - timedelta(seconds=10):
        return ""
    return str(token)