from __future__ import annotations

async def camoufox_proxy_worker(core):
    """
    Internal Userscript-Proxy client backed by Camoufox.
    Maintains a SINGLE persistent browser instance to avoid crash loops and resource exhaustion.
    """

    # Bind globals from the owning module (src.main) so test patch points remain stable.
    AsyncCamoufox = core.AsyncCamoufox
    Path = core.Path
    _capture_ephemeral_arena_auth_token_from_cookies = core._capture_ephemeral_arena_auth_token_from_cookies
    _touch_userscript_poll = core._touch_userscript_poll
    asyncio = core.asyncio
    click_turnstile = core.click_turnstile
    debug_print = core.debug_print
    get_config = core.get_config
    is_arena_auth_token_expired = core.is_arena_auth_token_expired
    os = core.os
    push_proxy_chunk = core.push_proxy_chunk
    refresh_arena_auth_token_via_lmarena_http = core.refresh_arena_auth_token_via_lmarena_http
    refresh_arena_auth_token_via_supabase = core.refresh_arena_auth_token_via_supabase
    time = core.time
    uuid = core.uuid

    # Mark the proxy as alive immediately
    _touch_userscript_poll()
    debug_print("🦊 Camoufox proxy worker started (Singleton Mode).")

    async def _poll_heartbeat() -> None:
        while True:
            try:
                _touch_userscript_poll()
            except Exception:
                pass
            await asyncio.sleep(2.0)

    heartbeat_task = asyncio.create_task(_poll_heartbeat())

    browser_cm = None
    browser = None
    context = None
    page = None

    proxy_recaptcha_sitekey = core.RECAPTCHA_SITEKEY
    proxy_recaptcha_action = core.RECAPTCHA_ACTION
    last_signup_attempt_at: float = 0.0
    
    queue = core._PROXY_SERVICE.queue

    while True:
        try:
            _touch_userscript_poll()
            
            # --- 1. HEALTH CHECK & LAUNCH ---
            needs_launch = False
            if browser is None or context is None or page is None:
                needs_launch = True
            else:
                try:
                    if page.is_closed():
                        debug_print("⚠️ Camoufox proxy page closed. Relaunching...")
                        needs_launch = True
                    elif not context.pages:
                        debug_print("⚠️ Camoufox proxy context has no pages. Relaunching...")
                        needs_launch = True
                except Exception:
                    needs_launch = True

            if needs_launch:
                # Cleanup existing if any
                if browser_cm:
                    try:
                        await browser_cm.__aexit__(None, None, None)
                    except Exception:
                        pass
                browser_cm = None
                browser = None
                context = None
                page = None

                cfg = get_config()
                recaptcha_sitekey, recaptcha_action = core.get_recaptcha_settings(cfg)
                proxy_recaptcha_sitekey = recaptcha_sitekey
                proxy_recaptcha_action = recaptcha_action
                user_agent = core.normalize_user_agent_value(cfg.get("user_agent"))
                
                headless_value = cfg.get("camoufox_proxy_headless", None)
                headless = bool(headless_value) if headless_value is not None else False
                launch_timeout = float(cfg.get("camoufox_proxy_launch_timeout_seconds", 90))
                launch_timeout = max(20.0, min(launch_timeout, 300.0))

                debug_print(f"🦊 Camoufox proxy: launching browser (headless={headless})...")

                profile_dir = None
                try:
                    profile_dir_value = cfg.get("camoufox_proxy_user_data_dir")
                    if profile_dir_value:
                        profile_dir = Path(str(profile_dir_value)).expanduser()
                except Exception:
                    pass
                if profile_dir is None:
                    try:
                        profile_dir = Path(core.CONFIG_FILE).with_name("grecaptcha")
                    except Exception:
                        pass

                persistent_pref = cfg.get("camoufox_proxy_persistent_context", None)
                want_persistent = bool(persistent_pref) if persistent_pref is not None else False
                
                persistent_context_enabled = False
                if want_persistent and isinstance(profile_dir, Path) and profile_dir.exists():
                    persistent_context_enabled = True
                    browser_cm = AsyncCamoufox(
                        headless=headless,
                        main_world_eval=True,
                        persistent_context=True,
                        user_data_dir=str(profile_dir),
                    )
                else:
                    browser_cm = AsyncCamoufox(headless=headless, main_world_eval=True)

                try:
                    browser = await asyncio.wait_for(browser_cm.__aenter__(), timeout=launch_timeout)
                except Exception as e:
                    debug_print(f"⚠️ Camoufox launch failed ({type(e).__name__}): {e}")
                    if persistent_context_enabled:
                        debug_print("⚠️ Retrying without persistence...")
                        try:
                            await browser_cm.__aexit__(None, None, None)
                        except Exception:
                            pass
                        persistent_context_enabled = False
                        browser_cm = AsyncCamoufox(headless=headless, main_world_eval=True)
                        browser = await asyncio.wait_for(browser_cm.__aenter__(), timeout=launch_timeout)
                    else:
                        raise

                if persistent_context_enabled:
                    context = browser
                else:
                    context = await browser.new_context(user_agent=user_agent or None)
                
                try:
                    await core._browser_automation.maybe_add_webdriver_stealth_script(context)
                except Exception:
                    pass

                # Inject only a minimal set of cookies (do not overwrite browser-managed state).
                cookie_values = core.extract_lmarena_cookie_values(cfg)
                desired_cookies = core.build_lmarena_context_cookies(cookie_values, include_grecaptcha=False)

                if desired_cookies:
                    try:
                        try:
                            existing = await context.cookies("https://lmarena.ai")
                        except Exception:
                            existing = []
                        existing_names = {str(c.get("name") or "") for c in (existing or []) if c.get("name")}
                        cookies_to_add = [
                            c for c in desired_cookies if str(c.get("name") or "") not in existing_names
                        ]
                        if cookies_to_add:
                            await context.add_cookies(cookies_to_add)
                    except Exception:
                        pass
                
                # Best-effort: seed the browser context with a usable `arena-auth-prod-v1` session cookie.
                # Prefer a non-expired base64 session from config, and avoid clobbering a fresh browser-managed cookie.
                try:
                    existing_auth = ""
                    try:
                        existing = await context.cookies("https://lmarena.ai")
                    except Exception:
                        existing = []
                    for c in existing or []:
                        try:
                            if str(c.get("name") or "") == "arena-auth-prod-v1":
                                existing_auth = str(c.get("value") or "").strip()
                                break
                        except Exception:
                            continue
                    has_fresh_existing = False
                    if existing_auth:
                        try:
                            has_fresh_existing = not is_arena_auth_token_expired(existing_auth, skew_seconds=0)
                        except Exception:
                            has_fresh_existing = True
                    
                    if not has_fresh_existing:
                        candidate = ""
                        try:
                            if core.EPHEMERAL_ARENA_AUTH_TOKEN and not is_arena_auth_token_expired(
                                core.EPHEMERAL_ARENA_AUTH_TOKEN, skew_seconds=0
                            ):
                                candidate = str(core.EPHEMERAL_ARENA_AUTH_TOKEN).strip()
                        except Exception:
                            candidate = ""
                        
                        if not candidate:
                            cfg_tokens = cfg.get("auth_tokens", [])
                            if not isinstance(cfg_tokens, list):
                                cfg_tokens = []
                            # Prefer a clearly non-expired session.
                            for t in cfg_tokens:
                                t = str(t or "").strip()
                                if not t:
                                    continue
                                try:
                                    if core.is_probably_valid_arena_auth_token(t) and not is_arena_auth_token_expired(
                                        t, skew_seconds=0
                                    ):
                                        candidate = t
                                        break
                                except Exception:
                                    continue
                            # Fallback: seed with any base64 session (even if expired; in-page refresh may work).
                            if not candidate:
                                for t in cfg_tokens:
                                    t = str(t or "").strip()
                                    if t.startswith("base64-"):
                                        candidate = t
                                        break

                        if candidate:
                            await context.add_cookies(
                                [
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": candidate,
                                        "domain": "lmarena.ai",
                                        "path": "/",
                                    },
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": candidate,
                                        "domain": ".lmarena.ai",
                                        "path": "/",
                                    },
                                ]
                            )
                except Exception:
                    pass

                page = await context.new_page()

                try:
                    debug_print("🦊 Camoufox proxy: navigating to https://lmarena.ai/?mode=direct ...")
                    await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=120000)
                    debug_print("🦊 Camoufox proxy: navigation complete.")
                except Exception as e:
                    debug_print(f"⚠️ Navigation warning: {e}")

                # Attach console listener
                def _on_console(message) -> None:
                    try:
                        attr = getattr(message, "text", None)
                        text = attr() if callable(attr) else attr
                    except Exception:
                        return
                    if not isinstance(text, str):
                        return
                    if not text.startswith("LM_BRIDGE_PROXY|"):
                        return
                    try:
                        _, jid, payload_json = text.split("|", 2)
                    except ValueError:
                        return
                    try:
                        payload = core.json.loads(payload_json)
                    except Exception:
                        payload = {"error": "proxy console payload decode error", "done": True}
                    try:
                        asyncio.create_task(push_proxy_chunk(str(jid), payload))
                    except Exception:
                        return
                
                try:
                    page.on("console", _on_console)
                except Exception:
                    pass
                
                # Check for "Just a moment" (Cloudflare) and click if needed
                try:
                    for _ in range(5):
                        title = await page.title()
                        if "Just a moment" not in title:
                            break
                        debug_print("🦊 Cloudflare challenge detected.")
                        await click_turnstile(page)
                        await asyncio.sleep(2)
                except Exception:
                    pass

                # MINIMAL FIX: apply window mode AFTER potential initial Turnstile solve.
                await core._maybe_apply_camoufox_window_mode(
                    page,
                    cfg,
                    mode_key="camoufox_proxy_window_mode",
                    marker="LMArenaBridge Camoufox Proxy",
                    headless=headless,
                )

                # Pre-warm
                try:
                    await page.mouse.move(100, 100)
                except Exception:
                    pass

            async def _get_auth_cookie_value() -> str:
                nonlocal context
                if context is None:
                    return ""
                try:
                    cookies = await context.cookies("https://lmarena.ai")
                except Exception:
                    return ""
                try:
                    _capture_ephemeral_arena_auth_token_from_cookies(cookies or [])
                except Exception:
                    pass
                candidates: list[str] = []
                for c in cookies or []:
                    try:
                        if str(c.get("name") or "") != "arena-auth-prod-v1":
                            continue
                        value = str(c.get("value") or "").strip()
                        if value:
                            candidates.append(value)
                    except Exception:
                        continue
                for value in candidates:
                    try:
                        if not is_arena_auth_token_expired(value, skew_seconds=0):
                            return value
                    except Exception:
                        return value
                if candidates:
                    return candidates[0]
                return ""

            async def _attempt_anonymous_signup(*, min_interval_seconds: float = 20.0) -> None:
                nonlocal last_signup_attempt_at, page, context
                if page is None or context is None:
                    return
                now = time.time()
                if (now - float(last_signup_attempt_at or 0.0)) < float(min_interval_seconds):
                    return
                last_signup_attempt_at = now

                # Turnstile clicking is expensive/noisy; keep it throttled and budgeted per signup attempt.
                turnstile_limiter = core.TurnstileClickLimiter(max_clicks=12, cooldown_seconds=5.0)

                async def _maybe_click_turnstile(*, allow_without_challenge: bool = False) -> None:
                    nonlocal page, turnstile_limiter
                    if page is None:
                        return

                    if not allow_without_challenge:
                        title = ""
                        try:
                            title = await asyncio.wait_for(page.title(), timeout=2.0)
                        except Exception:
                            title = ""
                        if ("Just a moment" not in title) and ("Cloudflare" not in title):
                            return

                    try:
                        now_mono = time.monotonic()
                    except Exception:
                        now_mono = 0.0
                    if not turnstile_limiter.try_acquire(float(now_mono)):
                        return
                    try:
                        await click_turnstile(page)
                    except Exception:
                        pass

                # First, give LMArena a chance to create an anonymous user itself (it already ships a
                # Turnstile-backed sign-up flow in the app). We just wait/poll for the auth cookie.
                try:
                    for _ in range(8):
                        cur = await _get_auth_cookie_value()
                        if cur and not is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        await _maybe_click_turnstile()
                        await asyncio.sleep(1.5)
                except Exception:
                    pass

                try:
                    cfg_now = get_config()
                except Exception:
                    cfg_now = {}
                cookie_store = cfg_now.get("browser_cookies") if isinstance(cfg_now, dict) else None
                provisional_user_id = ""
                if isinstance(cfg_now, dict):
                    provisional_user_id = str(cfg_now.get("provisional_user_id") or "").strip()
                if (not provisional_user_id) and isinstance(cookie_store, dict):
                    provisional_user_id = str(cookie_store.get("provisional_user_id") or "").strip()
                if not provisional_user_id:
                    provisional_user_id = str(uuid.uuid4())

                # Try to force a fresh anonymous signup by rotating the provisional ID and clearing any stale auth.
                try:
                    fresh_provisional = str(uuid.uuid4())
                    await context.add_cookies(
                        [{"name": "provisional_user_id", "value": fresh_provisional, "domain": ".lmarena.ai", "path": "/"}]
                    )
                    provisional_user_id = fresh_provisional
                except Exception:
                    pass
                try:
                    await context.add_cookies(
                        [
                            {
                                "name": "arena-auth-prod-v1",
                                "value": "",
                                "domain": "lmarena.ai",
                                "path": "/",
                                "expires": 1,
                            },
                            {
                                "name": "arena-auth-prod-v1",
                                "value": "",
                                "domain": ".lmarena.ai",
                                "path": "/",
                                "expires": 1,
                            },
                        ]
                    )
                except Exception:
                    pass
                try:
                    await page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=45000)
                except Exception:
                    pass
                try:
                    for _ in range(6):
                        cur = await _get_auth_cookie_value()
                        if cur and not is_arena_auth_token_expired(cur, skew_seconds=0):
                            return
                        await _maybe_click_turnstile()
                        await asyncio.sleep(1.5)
                except Exception:
                    pass

                # Turnstile token minting:
                # Avoid long-running `page.evaluate` promises (they can hang if the page reloads). Render once, then poll
                # `turnstile.getResponse(widgetId)` from Python and click the widget if it becomes interactive.
                render_turnstile_js = """async ({ sitekey }) => {
                  const w = (window.wrappedJSObject || window);
                  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
                  const key = String(sitekey || '');
                  const out = { ok: false, widgetId: null, stage: 'start', error: '' };
                  if (!key) { out.stage = 'no_sitekey'; return out; }

                  try {
                    const prev = w.__LM_BRIDGE_TURNSTILE_WIDGET_ID;
                    if (prev != null && w.turnstile && typeof w.turnstile.remove === 'function') {
                      try { w.turnstile.remove(prev); } catch (e) {}
                    }
                  } catch (e) {}
                  try {
                    const old = w.document.getElementById('lm-bridge-turnstile');
                    if (old) old.remove();
                  } catch (e) {}

                  async function ensureLoaded() {
                    if (w.turnstile && typeof w.turnstile.render === 'function') return true;
                    try {
                      const h = w.document?.head;
                      if (!h) return false;
                      if (!w.__LM_BRIDGE_TURNSTILE_INJECTED) {
                        w.__LM_BRIDGE_TURNSTILE_INJECTED = true;
                        out.stage = 'inject_script';
                        await Promise.race([
                          new Promise((resolve) => {
                            const s = w.document.createElement('script');
                            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
                            s.async = true;
                            s.defer = true;
                            s.onload = () => resolve(true);
                            s.onerror = () => resolve(false);
                            h.appendChild(s);
                          }),
                          sleep(12000).then(() => false),
                        ]);
                      }
                    } catch (e) { out.error = String(e); }
                    const start = Date.now();
                    while ((Date.now() - start) < 15000) {
                      if (w.turnstile && typeof w.turnstile.render === 'function') return true;
                      await sleep(250);
                    }
                    return false;
                  }

                  const ok = await ensureLoaded();
                  if (!ok || !(w.turnstile && typeof w.turnstile.render === 'function')) { out.stage = 'not_loaded'; return out; }

                  out.stage = 'render';
                  try {
                    const el = w.document.createElement('div');
                    el.id = 'lm-bridge-turnstile';
                    el.style.cssText = 'position:fixed;left:20px;top:20px;z-index:2147483647;';
                    (w.document.body || w.document.documentElement).appendChild(el);
                    const params = new w.Object();
                    params.sitekey = key;
                    // Match LMArena's own anonymous sign-up widget settings.
                    // `size: normal` + `appearance: interaction-only` tends to be accepted more reliably than
                    // forcing an invisible execute flow.
                    params.size = 'normal';
                    params.appearance = 'interaction-only';
                    params.callback = (tok) => { try { w.__LM_BRIDGE_TURNSTILE_TOKEN = String(tok || ''); } catch (e) {} };
                    params['error-callback'] = () => { try { w.__LM_BRIDGE_TURNSTILE_TOKEN = ''; } catch (e) {} };
                    params['expired-callback'] = () => { try { w.__LM_BRIDGE_TURNSTILE_TOKEN = ''; } catch (e) {} };
                    const widgetId = w.turnstile.render(el, params);
                    w.__LM_BRIDGE_TURNSTILE_WIDGET_ID = widgetId;
                    out.ok = true;
                    out.widgetId = widgetId;
                    return out;
                  } catch (e) {
                    out.error = String(e);
                    out.stage = 'render_error';
                    return out;
                  }
                }"""

                poll_turnstile_js = """({ widgetId }) => {
                  const w = (window.wrappedJSObject || window);
                  try {
                    const tok = w.__LM_BRIDGE_TURNSTILE_TOKEN;
                    if (tok && String(tok).trim()) return String(tok);
                    if (!w.turnstile || typeof w.turnstile.getResponse !== 'function') return '';
                    return String(w.turnstile.getResponse(widgetId) || '');
                  } catch (e) {
                    return '';
                  }
                }"""

                cleanup_turnstile_js = """({ widgetId }) => {
                  const w = (window.wrappedJSObject || window);
                  try { if (w.turnstile && typeof w.turnstile.remove === 'function') w.turnstile.remove(widgetId); } catch (e) {}
                  try {
                    const el = w.document.getElementById('lm-bridge-turnstile');
                    if (el) el.remove();
                  } catch (e) {}
                  try { delete w.__LM_BRIDGE_TURNSTILE_WIDGET_ID; } catch (e) {}
                  try { delete w.__LM_BRIDGE_TURNSTILE_TOKEN; } catch (e) {}
                  return true;
                }"""

                token_value = ""
                widget_id = None
                stage = ""
                err = ""
                try:
                    mint_info = await asyncio.wait_for(
                        page.evaluate(render_turnstile_js, {"sitekey": core.TURNSTILE_SITEKEY}),
                        timeout=30.0,
                    )
                except Exception as e:
                    mint_info = {"ok": False, "stage": "evaluate_error", "error": str(e)}
                if isinstance(mint_info, dict):
                    try:
                        widget_id = mint_info.get("widgetId")
                    except Exception:
                        widget_id = None
                    try:
                        stage = str(mint_info.get("stage") or "")
                    except Exception:
                        stage = ""
                    try:
                        err = str(mint_info.get("error") or "")
                    except Exception:
                        err = ""
                if widget_id is None:
                    debug_print(f"⚠️ Camoufox proxy: Turnstile render failed (stage={stage} err={err[:120]})")
                    return

                started = time.monotonic()
                try:
                    while (time.monotonic() - started) < 90.0:
                        try:
                            cur = await asyncio.wait_for(
                                page.evaluate(poll_turnstile_js, {"widgetId": widget_id}),
                                timeout=5.0,
                            )
                        except Exception:
                            cur = ""
                        token_value = str(cur or "").strip()
                        if token_value:
                            break
                        await _maybe_click_turnstile(allow_without_challenge=True)
                        await asyncio.sleep(2.0)
                finally:
                    try:
                        await page.evaluate(cleanup_turnstile_js, {"widgetId": widget_id})
                    except Exception:
                        pass

                if not token_value:
                    debug_print("⚠️ Camoufox proxy: Turnstile mint failed (timeout).")
                    return

                recaptcha_token = ""
                mint_recaptcha_js = """async ({ sitekey, action, timeoutMs }) => {
                  const w = (window.wrappedJSObject || window);
                  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
                  const pickG = () => {
                    const ent = w?.grecaptcha?.enterprise;
                    if (ent && typeof ent.execute === 'function' && typeof ent.ready === 'function') return ent;
                    const g = w?.grecaptcha;
                    if (g && typeof g.execute === 'function' && typeof g.ready === 'function') return g;
                    return null;
                  };
                  const key = String(sitekey || '');
                  if (!key) return '';
                  const act = String(action || 'sign_up');
                  const start = Date.now();
                  let injected = false;
                  while ((Date.now() - start) < Number(timeoutMs || 60000)) {
                    const g = pickG();
                    if (g) {
                      try {
                        await Promise.race([
                          new Promise((resolve) => { try { g.ready(resolve); } catch (e) { resolve(); } }),
                          sleep(5000).then(() => {}),
                        ]);
                      } catch (e) {}
                      try {
                        const params = new w.Object();
                        params.action = act;
                        const tok = await Promise.race([
                          Promise.resolve().then(() => g.execute(key, params)),
                          sleep(15000).then(() => ''),
                        ]);
                        return (typeof tok === 'string') ? tok : '';
                      } catch (e) {
                        return '';
                      }
                    }
                    if (!injected) {
                      injected = true;
                      try {
                        const h = w.document?.head;
                        if (h) {
                          const s1 = w.document.createElement('script');
                          s1.src = 'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(key);
                          s1.async = true;
                          s1.defer = true;
                          h.appendChild(s1);
                          const s2 = w.document.createElement('script');
                          s2.src = 'https://www.google.com/recaptcha/enterprise.js?render=' + encodeURIComponent(key);
                          s2.async = true;
                          s2.defer = true;
                          h.appendChild(s2);
                        }
                      } catch (e) {}
                    }
                    await sleep(250);
                  }
                  return '';
                }"""

                try:
                    recaptcha_token = await asyncio.wait_for(
                        page.evaluate(
                            mint_recaptcha_js,
                            {"sitekey": proxy_recaptcha_sitekey, "action": "sign_up", "timeoutMs": 60000},
                        ),
                        timeout=30.0,
                    )
                except Exception:
                    recaptcha_token = ""
                recaptcha_token = str(recaptcha_token or "").strip()
                if not recaptcha_token:
                    debug_print("⚠️ Camoufox proxy: could not mint reCAPTCHA token for sign-up.")
                    return

                sign_up_js = """async ({ turnstileToken, recaptchaToken, provisionalUserId }) => {
                  const w = (window.wrappedJSObject || window);
                  const opts = new w.Object();
                  opts.method = 'POST';
                  opts.credentials = 'include';
                  opts.headers = new w.Object();
                  opts.headers['Content-Type'] = 'application/json';
                  opts.body = JSON.stringify({ turnstileToken: String(turnstileToken || ''), recaptchaToken: String(recaptchaToken || ''), provisionalUserId: String(provisionalUserId || '') });
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
                                "turnstileToken": token_value,
                                "recaptchaToken": recaptcha_token,
                                "provisionalUserId": provisional_user_id,
                            },
                        ),
                        timeout=20.0,
                    )
                except Exception:
                    resp = None

                status = 0
                try:
                    status = int((resp or {}).get("status") or 0) if isinstance(resp, dict) else 0
                except Exception:
                    status = 0
                debug_print(f"🦊 Camoufox proxy: /nextjs-api/sign-up status {status}")

                # Some sign-up responses return the Supabase session JSON in the body instead of setting a cookie.
                # When that happens, encode it into the `arena-auth-prod-v1` cookie format and inject it.
                try:
                    body_text = str((resp or {}).get("body") or "") if isinstance(resp, dict) else ""
                except Exception:
                    body_text = ""
                if status >= 400:
                    preview = str(body_text or "").strip()
                    if preview:
                        debug_print(f"🦊 Camoufox proxy: /nextjs-api/sign-up body preview: {preview[:240]}")
                try:
                    derived_cookie = core.maybe_build_arena_auth_cookie_from_signup_response_body(body_text)
                except Exception:
                    derived_cookie = None
                if derived_cookie:
                    try:
                        if not is_arena_auth_token_expired(derived_cookie, skew_seconds=0):
                            await context.add_cookies(
                                [
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": derived_cookie,
                                        "domain": "lmarena.ai",
                                        "path": "/",
                                    },
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": derived_cookie,
                                        "domain": ".lmarena.ai",
                                        "path": "/",
                                    },
                                ]
                            )
                            _capture_ephemeral_arena_auth_token_from_cookies(
                                [{"name": "arena-auth-prod-v1", "value": derived_cookie}]
                            )
                            debug_print("🦊 Camoufox proxy: injected arena-auth cookie from sign-up response body.")
                    except Exception:
                        pass

                # Wait for the cookie to appear
                try:
                    for _ in range(10):
                        cookies = await context.cookies("https://lmarena.ai")
                        _capture_ephemeral_arena_auth_token_from_cookies(cookies or [])
                        found = False
                        for c in cookies or []:
                            if c.get("name") == "arena-auth-prod-v1":
                                val = str(c.get("value") or "").strip()
                                if val and not is_arena_auth_token_expired(val, skew_seconds=0):
                                    found = True
                                    break
                        if found:
                            debug_print("🦊 Camoufox proxy: acquired arena-auth-prod-v1 cookie (anonymous user).")
                            break
                        await asyncio.sleep(0.5)
                except Exception:
                    pass

            # --- 2. PROCESS JOBS ---
            try:
                job_id = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            
            job_id = str(job_id or "").strip()
            job = core._USERSCRIPT_PROXY_JOBS.get(job_id)
            if not isinstance(job, dict):
                continue
            
            # Signal that a proxy worker picked up this job (used to avoid long hangs when no worker is running).
            try:
                picked = job.get("picked_up_event")
                if isinstance(picked, asyncio.Event) and not picked.is_set():
                    picked.set()
            except Exception:
                pass
             
            # Mark the job as active immediately so server-side routing doesn't time out while we perform slow
            # pre-flight steps (anonymous signup / Turnstile) before the in-page fetch emits the real HTTP status.
            try:
                status_event = job.get("status_event")
                if isinstance(status_event, asyncio.Event) and not status_event.is_set():
                    job["status_code"] = int(job.get("status_code") or 200)
                    status_event.set()
            except Exception:
                pass

            # In-page fetch script (streams newline-delimited chunks back through console.log).
            # Mints reCAPTCHA v3 tokens on demand when the request body includes `recaptchaV3Token`.
            fetch_script = """async ({ jid, payload, sitekey, action, sitekeyV2, grecaptchaTimeoutMs, grecaptchaPollMs, timeoutMs, debug }) => {
              const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
              const w = (window.wrappedJSObject || window);
              const emit = (obj) => { try { console.log('LM_BRIDGE_PROXY|' + jid + '|' + JSON.stringify(obj)); } catch (e) {} };
              const debugEnabled = !!debug;
              const dbg = (stage, extra) => { if (!debugEnabled && !String(stage).includes('error')) return; try { emit({ debug: { stage, ...(extra || {}) } }); } catch (e) {} };
              dbg('start', { hasPayload: !!payload, hasSitekey: !!sitekey, hasAction: !!action });

              const pickG = () => {
                const ent = w?.grecaptcha?.enterprise;
                if (ent && typeof ent.execute === 'function' && typeof ent.ready === 'function') return ent;
                const g = w?.grecaptcha;
                if (g && typeof g.execute === 'function' && typeof g.ready === 'function') return g;
                return null;
              };

              const waitForG = async () => {
                const start = Date.now();
                let injected = false;
                while ((Date.now() - start) < (grecaptchaTimeoutMs || 60000)) {
                  const g = pickG();
                  if (g) return g;
                  if (!injected && sitekey && typeof sitekey === 'string' && sitekey) {
                    injected = true;
                    try {
                      // LMArena may lazy-load grecaptcha only after interaction; inject v3-capable scripts.
                      dbg('inject_grecaptcha', {});
                      const key = String(sitekey || '');
                      const h = w.document?.head;
                      if (h) {
                        const s1 = w.document.createElement('script');
                        s1.src = 'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(key);
                        s1.async = true;
                        s1.defer = true;
                        h.appendChild(s1);
                        const s2 = w.document.createElement('script');
                        s2.src = 'https://www.google.com/recaptcha/enterprise.js?render=' + encodeURIComponent(key);
                        s2.async = true;
                        s2.defer = true;
                        h.appendChild(s2);
                      }
                    } catch (e) {}
                  }
                  await sleep(grecaptchaPollMs || 250);
                }
                throw new Error('grecaptcha not ready');
              };

              const mintV3 = async (act) => {
                const g = await waitForG();
                const finalAction = String(act || action || 'chat_submit');
                // `grecaptcha.ready()` can hang indefinitely on some pages; guard it with a short timeout.
                try {
                  await Promise.race([
                    new Promise((resolve) => { try { g.ready(resolve); } catch (e) { resolve(); } }),
                    sleep(5000).then(() => {}),
                  ]);
                } catch (e) {}
                const tok = await Promise.race([
                  Promise.resolve().then(() => {
                    // Firefox Xray wrappers: build params in the page compartment.
                    const params = new w.Object();
                    params.action = finalAction;
                    return g.execute(String(sitekey || ''), params);
                  }),
                  sleep(Math.max(1000, grecaptchaTimeoutMs || 60000)).then(() => { throw new Error('grecaptcha execute timeout'); }),
                ]);
                return (typeof tok === 'string') ? tok : '';
              };
              
              const waitForV2 = async () => {
                const start = Date.now();
                while ((Date.now() - start) < 60000) {
                  const ent = w?.grecaptcha?.enterprise;
                  if (ent && typeof ent.render === 'function') return ent;
                  await sleep(250);
                }
                throw new Error('grecaptcha v2 not ready');
              };
              
              const mintV2 = async () => {
                const ent = await waitForV2();
                const key2 = String(sitekeyV2 || '');
                if (!key2) throw new Error('no sitekeyV2');
                return await new Promise((resolve, reject) => {
                  let settled = false;
                  const done = (fn, arg) => { if (settled) return; settled = true; try { fn(arg); } catch (e) {} };
                  try {
                    const el = w.document.createElement('div');
                    el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;';
                    (w.document.body || w.document.documentElement).appendChild(el);
                    const timer = w.setTimeout(() => { try { el.remove(); } catch (e) {} done(reject, 'V2_TIMEOUT'); }, 60000);
                    // Firefox Xray wrappers: build params in the page compartment.
                    const params = new w.Object();
                    params.sitekey = key2;
                    params.size = 'invisible';
                    params.callback = (tok) => { w.clearTimeout(timer); try { el.remove(); } catch (e) {} done(resolve, String(tok || '')); };
                    params['error-callback'] = () => { w.clearTimeout(timer); try { el.remove(); } catch (e) {} done(reject, 'V2_ERROR'); };
                    const wid = ent.render(el, params);
                    try { if (typeof ent.execute === 'function') ent.execute(wid); } catch (e) {}
                  } catch (e) {
                    done(reject, String(e));
                  }
                });
              };

              try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort('timeout'), timeoutMs || 120000);
                try {
                  let bodyText = payload?.body || '';
                  let parsed = null;
                  try { parsed = JSON.parse(String(bodyText || '')); } catch (e) { parsed = null; }

                  let tokenForHeaders = '';
                  if (parsed && typeof parsed === 'object' && Object.prototype.hasOwnProperty.call(parsed, 'recaptchaV3Token')) {
                    try { tokenForHeaders = String(parsed.recaptchaV3Token || ''); } catch (e) { tokenForHeaders = ''; }
                    if (!tokenForHeaders || tokenForHeaders.length < 20) {
                      try {
                        dbg('mint_v3_start', {});
                        tokenForHeaders = await mintV3(action);
                        dbg('v3_minted', { len: (tokenForHeaders || '').length });
                        if (tokenForHeaders) parsed.recaptchaV3Token = tokenForHeaders;
                      } catch (e) {
                        dbg('v3_error', { error: String(e) });
                      }
                    }
                    try { bodyText = JSON.stringify(parsed); } catch (e) { bodyText = String(payload?.body || ''); }
                  }

                  const doFetch = async (body, token) => fetch(payload.url, {
                    method: payload.method || 'POST',
                    body,
                    headers: {
                      ...(payload.headers || { 'Content-Type': 'text/plain;charset=UTF-8' }),
                      ...(token ? { 'X-Recaptcha-Token': token, ...(action ? { 'X-Recaptcha-Action': action } : {}) } : {}),
                    },
                    credentials: 'include',
                    signal: controller.signal,
                  });

                  dbg('before_fetch', { tokenLen: (tokenForHeaders || '').length });
                  let res = await doFetch(bodyText, tokenForHeaders);
                  dbg('after_fetch', { status: Number(res?.status || 0) });
                  if (debugEnabled && res && Number(res.status || 0) >= 400) {
                    let p = '';
                    try { p = await res.clone().text(); } catch (e) { p = ''; }
                    dbg('http_error_preview', { status: Number(res.status || 0), preview: String(p || '').slice(0, 200) });
                  }
                  let headers = {};
                  try { if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k] = v; }); } catch (e) {}
                  emit({ status: res.status, headers });

                  // If we get a reCAPTCHA 403, retry once with a fresh token (keep streaming semantics).
                  if (res && res.status === 403 && parsed && typeof parsed === 'object' && Object.prototype.hasOwnProperty.call(parsed, 'recaptchaV3Token')) {
                    let preview = '';
                    try { preview = await res.clone().text(); } catch (e) { preview = ''; }
                    dbg('403_preview', { preview: String(preview || '').slice(0, 200) });
                    const lower = String(preview || '').toLowerCase();
                    if (lower.includes('recaptcha')) {
                      let tok2 = '';
                      try {
                        tok2 = await mintV3(action);
                        dbg('v3_retry_minted', { len: (tok2 || '').length });
                      } catch (e) {
                        dbg('v3_retry_error', { error: String(e) });
                        tok2 = '';
                      }
                      if (tok2) {
                        try { parsed.recaptchaV3Token = tok2; } catch (e) {}
                        try { bodyText = JSON.stringify(parsed); } catch (e) {}
                        tokenForHeaders = tok2;
                        res = await doFetch(bodyText, tokenForHeaders);
                        headers = {};
                        try { if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k] = v; }); } catch (e) {}
                        emit({ status: res.status, headers });
                      }
                      // If v3 retry still fails (or retry mint failed), attempt v2 fallback (matches LMArena's UI flow).
                      if (res && res.status === 403) {
                        try {
                          const v2tok = await mintV2();
                          dbg('v2_minted', { len: (v2tok || '').length });
                          if (v2tok) {
                            parsed.recaptchaV2Token = v2tok;
                            try { delete parsed.recaptchaV3Token; } catch (e) {}
                            bodyText = JSON.stringify(parsed);
                            tokenForHeaders = '';
                            res = await doFetch(bodyText, '');
                            headers = {};
                            try { if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k] = v; }); } catch (e) {}
                            emit({ status: res.status, headers });
                          }
                        } catch (e) {
                          dbg('v2_error', { error: String(e) });
                        }
                      }
                    }
                  }

                  const reader = res.body?.getReader?.();
                  const decoder = new TextDecoder();
                  if (!reader) {
                    const text = await res.text();
                    const lines = String(text || '').split(/\\r?\\n/).filter((x) => String(x || '').trim().length > 0);
                    if (lines.length) emit({ lines, done: false });
                    emit({ lines: [], done: true });
                    return;
                  }

                  let buffer = '';
                  while (true) {
                    const { value, done } = await reader.read();
                    if (value) buffer += decoder.decode(value, { stream: true });
                    if (done) buffer += decoder.decode();
                    const parts = buffer.split(/\\r?\\n/);
                    buffer = parts.pop() || '';
                    const lines = parts.filter((x) => String(x || '').trim().length > 0);
                    if (lines.length) emit({ lines, done: false });
                    if (done) break;
                  }
                  if (buffer.trim()) emit({ lines: [buffer], done: false });
                  emit({ lines: [], done: true });
                } finally {
                  clearTimeout(timer);
                }
              } catch (e) {
                emit({ error: String(e), done: true });
              }
            }"""

            debug_print(f"🦊 Camoufox proxy: running job {job_id[:8]}...")
            
            try:
                # Use existing browser cookie if valid, to avoid clobbering fresh anonymous sessions
                browser_auth_cookie = ""
                try:
                    browser_auth_cookie = await _get_auth_cookie_value()
                except Exception:
                    pass
                
                auth_token = str(job.get("arena_auth_token") or "").strip()
                
                use_job_token = False
                if auth_token:
                    # Only use the job's token if we don't have a valid one, or if the job's token is explicitly fresher (hard to tell, so prefer browser's if valid).
                    if not browser_auth_cookie:
                        use_job_token = True
                    else:
                        try:
                            if is_arena_auth_token_expired(browser_auth_cookie, skew_seconds=60):
                                use_job_token = True
                        except Exception:
                            use_job_token = True
                
                    if use_job_token:
                        await context.add_cookies(
                            [
                                {"name": "arena-auth-prod-v1", "value": auth_token, "domain": "lmarena.ai", "path": "/"},
                                {"name": "arena-auth-prod-v1", "value": auth_token, "domain": ".lmarena.ai", "path": "/"},
                            ]
                        )
                elif browser_auth_cookie and not use_job_token:
                    debug_print("🦊 Camoufox proxy: using valid browser auth cookie (job token is empty or invalid).")
            except Exception:
                pass

            # If the job did not provide a usable auth cookie, ensure the browser session has one.
            try:
                current_cookie = await _get_auth_cookie_value()
            except Exception:
                current_cookie = ""

            # E2E/debug hook: force the cookie to look expired once (to exercise refresh paths).
            try:
                if bool(getattr(core, "_DEBUG_EXPIRE_PROXY_ARENA_AUTH_COOKIE_ONCE", False)):
                    core._DEBUG_EXPIRE_PROXY_ARENA_AUTH_COOKIE_ONCE = False
                    if current_cookie and str(current_cookie).startswith("base64-"):
                        try:
                            session = core._decode_arena_auth_session_token(current_cookie)
                        except Exception:
                            session = None
                        if isinstance(session, dict):
                            session = dict(session)
                            session["expires_at"] = 0
                            try:
                                raw = core.json.dumps(session, separators=(",", ":")).encode("utf-8")
                                b64 = core.base64.b64encode(raw).decode("utf-8").rstrip("=")
                                forced = "base64-" + b64
                            except Exception:
                                forced = ""
                            if forced:
                                await context.add_cookies(
                                    [
                                        {
                                            "name": "arena-auth-prod-v1",
                                            "value": forced,
                                            "domain": "lmarena.ai",
                                            "path": "/",
                                        },
                                        {
                                            "name": "arena-auth-prod-v1",
                                            "value": forced,
                                            "domain": ".lmarena.ai",
                                            "path": "/",
                                        },
                                    ]
                                )
                                _capture_ephemeral_arena_auth_token_from_cookies(
                                    [{"name": "arena-auth-prod-v1", "value": forced}]
                                )
                                current_cookie = forced
                                debug_print("🦊 Camoufox proxy: forced arena-auth cookie to expired (debug).")
            except Exception:
                pass

            if current_cookie:
                try:
                    expired = is_arena_auth_token_expired(current_cookie, skew_seconds=0)
                except Exception:
                    expired = False
                debug_print(f"🦊 Camoufox proxy: arena-auth cookie present (len={len(current_cookie)} expired={expired})")
            else:
                debug_print("🦊 Camoufox proxy: arena-auth cookie missing")

            # If we have an expired base64 session cookie, try to refresh it before attempting anonymous signup.
            # This avoids flaky Turnstile flows and keeps long-running installs stable.
            if current_cookie:
                try:
                    expired = is_arena_auth_token_expired(current_cookie, skew_seconds=0)
                except Exception:
                    expired = False
                refreshed = None
                if expired and str(current_cookie).startswith("base64-"):
                    # Prefer refreshing in the live browser (preserves identity for existing sessions and avoids
                    # creating a new anonymous user when a simple cookie rotation would work).
                    if page is not None:
                        try:
                            await page.reload(wait_until="domcontentloaded", timeout=45000)
                        except Exception:
                            pass
                        try:
                            candidate = await _get_auth_cookie_value()
                        except Exception:
                            candidate = ""
                        if candidate:
                            try:
                                if not is_arena_auth_token_expired(candidate, skew_seconds=0):
                                    refreshed = str(candidate)
                            except Exception:
                                refreshed = str(candidate)
                    
                    try:
                        cfg_now = get_config()
                    except Exception:
                        cfg_now = {}
                    if not isinstance(cfg_now, dict):
                        cfg_now = {}
                    # Prefer Cloudflare cookies from the live browser context (more reliable than stale config.json).
                    try:
                        browser_cookies = await context.cookies("https://lmarena.ai")
                    except Exception:
                        browser_cookies = []
                    cookie_map = {}
                    for c in browser_cookies or []:
                        try:
                            name = str(c.get("name") or "").strip()
                            value = str(c.get("value") or "").strip()
                        except Exception:
                            continue
                        if name and value:
                            cookie_map[name] = value
                    if not str(cfg_now.get("cf_clearance") or "").strip():
                        cfg_now["cf_clearance"] = cookie_map.get("cf_clearance", "")
                    if not str(cfg_now.get("cf_bm") or "").strip():
                        cfg_now["cf_bm"] = cookie_map.get("__cf_bm", "")
                    if not str(cfg_now.get("cfuvid") or "").strip():
                        cfg_now["cfuvid"] = cookie_map.get("_cfuvid", "")
                    if not str(cfg_now.get("provisional_user_id") or "").strip():
                        cfg_now["provisional_user_id"] = cookie_map.get("provisional_user_id", "")
                    if not refreshed:
                        try:
                            refreshed = await refresh_arena_auth_token_via_lmarena_http(current_cookie, cfg_now)
                        except Exception:
                            refreshed = None
                    if not refreshed:
                        try:
                            refreshed = await refresh_arena_auth_token_via_supabase(current_cookie)
                        except Exception:
                            refreshed = None
                    if not refreshed:
                        # If we don't have the Supabase anon key yet, try to discover it from the live page once.
                        try:
                            anon_key = str(getattr(core, "SUPABASE_ANON_KEY", "") or "").strip()
                        except Exception:
                            anon_key = ""
                        if (not anon_key) and page is not None:
                            discovered = None
                            try:
                                html = await page.content()
                                discovered = core.extract_supabase_anon_key_from_text(html)
                            except Exception:
                                discovered = None
                            if not discovered:
                                try:
                                    script_urls = await page.evaluate(
                                        "() => Array.from(document.scripts).map(s => s.src).filter(Boolean)"
                                    )
                                except Exception:
                                    script_urls = []
                                if not isinstance(script_urls, list):
                                    script_urls = []
                                for url in [str(u or "") for u in script_urls[:8]]:
                                    if not url:
                                        continue
                                    try:
                                        js_text = await page.evaluate(
                                            "(u) => fetch(u, { credentials: 'include' }).then(r => r.text()).catch(() => '')",
                                            url,
                                        )
                                    except Exception:
                                        js_text = ""
                                    discovered = core.extract_supabase_anon_key_from_text(js_text or "")
                                    if discovered:
                                        break
                            if (not discovered) and isinstance(script_urls, list):
                                # Fallback: fetch scripts via httpx with Cloudflare cookies from config/context.
                                try:
                                    ua = core.normalize_user_agent_value((cfg_now or {}).get("user_agent")) or (
                                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/120.0.0.0 Safari/537.36"
                                    )
                                except Exception:
                                    ua = ""
                                cookies_http = {}
                                try:
                                    cc = str((cfg_now or {}).get("cf_clearance") or "").strip()
                                    if cc:
                                        cookies_http["cf_clearance"] = cc
                                except Exception:
                                    pass
                                try:
                                    bm = str((cfg_now or {}).get("cf_bm") or "").strip()
                                    if bm:
                                        cookies_http["__cf_bm"] = bm
                                except Exception:
                                    pass
                                try:
                                    cfu = str((cfg_now or {}).get("cfuvid") or "").strip()
                                    if cfu:
                                        cookies_http["_cfuvid"] = cfu
                                except Exception:
                                    pass
                                try:
                                    prov = str((cfg_now or {}).get("provisional_user_id") or "").strip()
                                    if prov:
                                        cookies_http["provisional_user_id"] = prov
                                except Exception:
                                    pass
                                try:
                                    async with core.httpx.AsyncClient(
                                        headers={"User-Agent": ua} if ua else {},
                                        cookies=cookies_http,
                                        follow_redirects=True,
                                        timeout=core.httpx.Timeout(connect=10.0, read=20.0, write=10.0, pool=10.0),
                                    ) as client:
                                        for url in [str(u or "") for u in script_urls[:25]]:
                                            if not url:
                                                continue
                                            try:
                                                resp = await client.get(url)
                                                text = str(getattr(resp, "text", "") or "")
                                            except Exception:
                                                text = ""
                                            discovered = core.extract_supabase_anon_key_from_text(text)
                                            if discovered:
                                                break
                                except Exception:
                                    pass
                            if discovered:
                                try:
                                    core.SUPABASE_ANON_KEY = str(discovered)
                                except Exception:
                                    pass
                                debug_print(f"🦊 Camoufox proxy: discovered Supabase anon key: {str(discovered)[:16]}...")
                                try:
                                    refreshed = await refresh_arena_auth_token_via_supabase(current_cookie)
                                except Exception:
                                    refreshed = None
                if refreshed:
                    try:
                        if not is_arena_auth_token_expired(refreshed, skew_seconds=0):
                            await context.add_cookies(
                                [
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": str(refreshed),
                                        "domain": "lmarena.ai",
                                        "path": "/",
                                    },
                                    {
                                        "name": "arena-auth-prod-v1",
                                        "value": str(refreshed),
                                        "domain": ".lmarena.ai",
                                        "path": "/",
                                    },
                                ]
                            )
                            _capture_ephemeral_arena_auth_token_from_cookies(
                                [{"name": "arena-auth-prod-v1", "value": str(refreshed)}]
                            )
                            current_cookie = str(refreshed)
                            debug_print("🦊 Camoufox proxy: refreshed expired arena-auth-prod-v1 cookie.")
                    except Exception:
                        pass
            job_url = ""
            try:
                job_url = str(job.get("url") or "")
            except Exception:
                job_url = ""

            cookie_expired = False
            if current_cookie:
                try:
                    cookie_expired = bool(is_arena_auth_token_expired(current_cookie, skew_seconds=0))
                except Exception:
                    cookie_expired = False

            # Only create a new anonymous user when starting a new evaluation session. For follow-up messages,
            # signing up would switch identities and break access to the existing session ID.
            is_create_evaluation = "/nextjs-api/stream/create-evaluation" in job_url
            needs_signup = (not current_cookie) or (cookie_expired and is_create_evaluation)
            # Unit tests stub out the browser; avoid slow/interactive signup flows there.
            if needs_signup and not os.environ.get("PYTEST_CURRENT_TEST"):
                await _attempt_anonymous_signup(min_interval_seconds=20.0)
            
            try:
                await asyncio.wait_for(
                    page.evaluate(
                        fetch_script,
                        {
                            "jid": job_id,
                            "payload": job.get("payload") or {},
                            "sitekey": proxy_recaptcha_sitekey,
                            "action": proxy_recaptcha_action,
                            "sitekeyV2": core.RECAPTCHA_V2_SITEKEY,
                            "grecaptchaTimeoutMs": 60000,
                            "grecaptchaPollMs": 250,
                            "timeoutMs": 180000,
                            "debug": bool(os.environ.get("LM_BRIDGE_PROXY_DEBUG")),
                        }
                    ),
                    timeout=200.0
                )
            except asyncio.TimeoutError:
                await push_proxy_chunk(job_id, {"error": "camoufox proxy evaluate timeout", "done": True})
            except Exception as e:
                await push_proxy_chunk(job_id, {"error": str(e), "done": True})

        except asyncio.CancelledError:
            debug_print("🦊 Camoufox proxy worker cancelled.")
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except Exception:
                    pass
            if browser_cm:
                try:
                    await browser_cm.__aexit__(None, None, None)
                except Exception:
                    pass
            return
        except Exception as e:
            debug_print(f"⚠️ Camoufox proxy worker exception: {e}")
            await asyncio.sleep(5.0)
            # Mark for relaunch
            browser = None
            page = None
