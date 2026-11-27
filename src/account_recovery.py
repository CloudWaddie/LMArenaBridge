"""Automated email login and signup recovery for Arena (arena.ai).

Arena enforces `401 LOGIN_GATE` on anonymous sessions for `/nextjs-api/stream/create-evaluation`,
so anonymous `/nextjs-api/sign-up` cookies cannot complete chats. This module automates
email-based login (using saved `managed_account` or `LM_ARENA_EMAIL`/`LM_ARENA_PASSWORD`)
and email-verified signup via Playwright Chrome, then captures and persists the signed-in
`arena-auth-prod-v1` session (including split `.0`/`.1` cookie chunks), Cloudflare cookies,
User-Agent, and `data-dpl-id`.
"""

from __future__ import annotations

import asyncio
import email as email_lib
import html
import imaplib
import os
import re
import secrets
import time
from typing import Any, Callable, Optional

from playwright.async_api import async_playwright

from .auth import (
    _combine_split_arena_auth_cookies,
    _decode_arena_auth_session_token,
    _persist_refreshed_auth_token,
    _upsert_browser_session_into_config,
    is_arena_auth_token_expired,
)
from .recaptcha import find_chrome_executable

_ACCOUNT_RECOVERY_LOCK: asyncio.Lock = asyncio.Lock()

_EMAIL_BLOCKED_MARKERS = (
    "email domain is not permitted",
    "email address cannot be used to sign up",
)


def is_anonymous_arena_auth_token(token: str) -> bool:
    """Return True if `token` decodes to an anonymous Supabase session."""
    session = _decode_arena_auth_session_token(token)
    if not isinstance(session, dict):
        return False
    user = session.get("user")
    if isinstance(user, dict):
        if user.get("is_anonymous") is True:
            return True
        if user.get("is_anonymous") is False:
            return False
    return False


def is_signed_in_arena_auth_token(token: str) -> bool:
    """Return True if `token` is a non-expired, non-anonymous base64 session."""
    session = _decode_arena_auth_session_token(token)
    if not isinstance(session, dict):
        return False
    access = str(session.get("access_token") or "").strip()
    if access.count(".") < 2:
        return False
    if is_arena_auth_token_expired(token):
        return False
    return not is_anonymous_arena_auth_token(token)


def extract_arena_verification_url(*parts: str) -> Optional[str]:
    """Extract Arena's email verification callback URL from raw text/HTML email bodies."""
    content = html.unescape("\n".join(str(p or "") for p in parts))
    urls = [u.rstrip(".,);]}") for u in re.findall(r"https?://[^\s\"'<>]+", content)]
    for marker in (
        "arena.ai/nextjs-api/callback/email",
        "arena.ai/auth/set-password",
    ):
        for url in urls:
            if marker in url:
                return url
    return None


def _extract_arena_auth_from_cookies(cookies: list[dict[str, Any]]) -> str:
    """Extract combined `arena-auth-prod-v1` (preferring non-empty split chunks over empty base cookie)."""
    combined = _combine_split_arena_auth_cookies(cookies)
    if combined:
        return combined
    for c in cookies or []:
        if str(c.get("name") or "") == "arena-auth-prod-v1":
            val = str(c.get("value") or "").strip()
            if val:
                return val
    return ""


async def _open_arena_login_dialog(page) -> None:
    """Navigate to arena.ai and open the Log In / Create Account email form."""
    await page.goto("https://arena.ai/", wait_until="domcontentloaded", timeout=90000)
    login_btn = page.get_by_role("button", name=re.compile(r"^log in$", re.I)).first
    await login_btn.wait_for(state="visible", timeout=20000)
    await login_btn.click(timeout=15000)
    email_input = page.get_by_placeholder("Your email")
    await email_input.wait_for(state="visible", timeout=20000)


async def _capture_session_from_page(page, context, cfg: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Read signed-in cookies, UA, and deployment ID from the live browser page."""
    cookies = [dict(c) for c in await context.cookies(["https://arena.ai/"])]
    token = _extract_arena_auth_from_cookies(cookies)
    try:
        ua = str(await page.evaluate("() => navigator.userAgent") or "").strip()
    except Exception:
        ua = ""
    try:
        dpl = str(
            await page.evaluate("() => document.documentElement.getAttribute('data-dpl-id') || ''")
            or ""
        ).strip()
    except Exception:
        dpl = ""
    _upsert_browser_session_into_config(cfg, cookies, user_agent=ua or None)
    if dpl:
        cfg["arena_web_deployment"] = dpl
    return token, cookies


def _poll_imap_for_verification_url(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    target_address: str,
    since_epoch: float,
    timeout_seconds: float = 120.0,
) -> Optional[str]:
    """Poll an IMAP mailbox for Arena's signup verification link."""
    deadline = time.monotonic() + max(5.0, float(timeout_seconds))
    seen_ids: set[bytes] = set()
    while time.monotonic() < deadline:
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(host, int(port))
            conn.login(user, password)
            conn.select("INBOX")
            status, data = conn.search(None, '(FROM "arena")')
            ids = (data[0].split() if status == "OK" and data and data[0] else [])
            for msg_id in reversed(ids[-10:]):
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
                st, msg_data = conn.fetch(msg_id, "(RFC822)")
                if st != "OK" or not msg_data:
                    continue
                raw = msg_data[0][1] if isinstance(msg_data[0], tuple) else b""
                msg = email_lib.message_from_bytes(raw)
                to_hdr = str(msg.get("To") or "").lower()
                if target_address and target_address.lower() not in to_hdr:
                    continue
                parts: list[str] = []
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        if ctype in ("text/plain", "text/html"):
                            payload = part.get_payload(decode=True) or b""
                            parts.append(payload.decode("utf-8", errors="replace"))
                else:
                    payload = msg.get_payload(decode=True) or b""
                    parts.append(payload.decode("utf-8", errors="replace"))
                url = extract_arena_verification_url(*parts)
                if url:
                    return url
        except Exception:
            pass
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:
                    pass
        time.sleep(3.0)
    return None


async def login_arena_email_account(
    address: str,
    password: str,
    *,
    config: Optional[dict[str, Any]] = None,
    headless: bool = False,
) -> Optional[str]:
    """Log into an existing Arena email/password account via Playwright Chrome."""
    address = str(address or "").strip()
    password = str(password or "").strip()
    if not address or not password:
        return None

    chrome_exe = find_chrome_executable()
    launch_kwargs: dict[str, Any] = {
        "headless": bool(headless),
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--window-position=-2400,-2400",
        ],
    }
    if chrome_exe:
        launch_kwargs["executable_path"] = chrome_exe

    cfg = dict(config) if isinstance(config, dict) else {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await _open_arena_login_dialog(page)
            await page.get_by_placeholder("Your email").fill(address)
            await page.get_by_role("button", name="Continue with email").click()

            pw_heading = page.get_by_role("heading", name=re.compile(r"Log In to your account", re.I))
            await pw_heading.wait_for(state="visible", timeout=20000)

            pw_input = page.locator("input[type='password']").first
            await pw_input.fill(password)
            submit = page.locator("[role='dialog']").get_by_role("button", name=re.compile(r"^log in$", re.I)).first
            await submit.click()
            await page.wait_for_timeout(5000)

            token, _ = await _capture_session_from_page(page, context, cfg)
            if token and is_signed_in_arena_auth_token(token):
                return token
            return None
        finally:
            await browser.close()


async def signup_arena_email_account(
    address: str,
    *,
    password: Optional[str] = None,
    wait_for_verification_url: Callable[[str, float], Any],
    config: Optional[dict[str, Any]] = None,
    headless: bool = False,
) -> tuple[Optional[str], str]:
    """Sign up a new Arena account with a permitted email address and verification callback."""
    address = str(address or "").strip()
    pw = str(password or "").strip() or ("Lmab_" + secrets.token_hex(10) + "A1!")
    if not address:
        return None, pw

    chrome_exe = find_chrome_executable()
    launch_kwargs: dict[str, Any] = {
        "headless": bool(headless),
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--window-position=-2400,-2400",
        ],
    }
    if chrome_exe:
        launch_kwargs["executable_path"] = chrome_exe

    cfg = dict(config) if isinstance(config, dict) else {}
    started_at = time.time()

    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await _open_arena_login_dialog(page)
            await page.get_by_placeholder("Your email").fill(address)
            await page.get_by_role("button", name="Continue with email").click()
            await page.wait_for_timeout(2500)

            dialog_text = (await page.locator("[role='dialog']").inner_text()).lower()
            for marker in _EMAIL_BLOCKED_MARKERS:
                if marker in dialog_text:
                    raise ValueError(f"Arena rejected email domain for {address}: {marker}")

            create_btn = page.get_by_role("button", name="Create Account", exact=True)
            await create_btn.wait_for(state="visible", timeout=20000)
            name_field = page.get_by_role("textbox", name=re.compile(r"Full Name", re.I))
            if await name_field.count():
                await name_field.fill("Bridge User")
            await create_btn.click()

            await page.get_by_role(
                "heading", name=re.compile(r"Verify your email address", re.I)
            ).wait_for(state="visible", timeout=30000)

            verif_url = wait_for_verification_url(address, started_at)
            if asyncio.iscoroutine(verif_url):
                verif_url = await verif_url
            if not verif_url:
                return None, pw

            await page.goto(str(verif_url), wait_until="domcontentloaded", timeout=90000)
            pw_fields = page.locator("input[type='password']")
            await pw_fields.first.wait_for(state="visible", timeout=30000)
            await pw_fields.nth(0).fill(pw)
            if await pw_fields.count() >= 2:
                await pw_fields.nth(1).fill(pw)
            finish_btn = page.get_by_role("button", name=re.compile(r"^finish$", re.I)).first
            await finish_btn.click()
            await page.wait_for_timeout(6000)

            token, _ = await _capture_session_from_page(page, context, cfg)
            if token and is_signed_in_arena_auth_token(token):
                return token, pw
            return None, pw
        finally:
            await browser.close()


async def recover_arena_auth_session(
    old_token: str = "",
    config: Optional[dict[str, Any]] = None,
) -> Optional[str]:
    """
    Attempt automated browser-backed account recovery (login with saved managed_account
    or env credentials, or IMAP-backed email signup) when HTTP/Supabase token refresh fails.
    """
    from . import main as _main

    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("LM_ALLOW_RECOVERY_IN_TESTS"):
        return None

    async with _ACCOUNT_RECOVERY_LOCK:
        cfg = config if isinstance(config, dict) else _main.get_config()
        if not isinstance(cfg, dict):
            cfg = {}

        account = cfg.get("managed_account") if isinstance(cfg.get("managed_account"), dict) else {}
        email_addr = str(account.get("address") or os.environ.get("LM_ARENA_EMAIL") or "").strip()
        email_pw = str(account.get("password") or os.environ.get("LM_ARENA_PASSWORD") or "").strip()

        token: Optional[str] = None
        if email_addr and email_pw:
            try:
                _main.debug_print(f"🔐 Attempting Arena email re-login for {email_addr}...")
                token = await login_arena_email_account(email_addr, email_pw, config=cfg)
            except Exception as exc:
                _main.debug_print(f"⚠️ Arena email re-login failed: {type(exc).__name__}: {exc}")
                token = None

        if not token:
            imap_host = str(os.environ.get("LM_IMAP_HOST") or cfg.get("imap_host") or "").strip()
            imap_user = str(os.environ.get("LM_IMAP_USER") or cfg.get("imap_user") or "").strip()
            imap_pass = str(os.environ.get("LM_IMAP_PASSWORD") or cfg.get("imap_password") or "").strip()
            imap_port = int(os.environ.get("LM_IMAP_PORT") or cfg.get("imap_port") or 993)
            signup_email = str(
                os.environ.get("LM_SIGNUP_EMAIL") or cfg.get("signup_email") or imap_user
            ).strip()
            if imap_host and imap_user and imap_pass and signup_email:
                try:
                    _main.debug_print(f"🆕 Attempting Arena email auto-signup for {signup_email}...")

                    async def _wait_verif(addr: str, since: float) -> Optional[str]:
                        return await asyncio.to_thread(
                            _poll_imap_for_verification_url,
                            host=imap_host,
                            port=imap_port,
                            user=imap_user,
                            password=imap_pass,
                            target_address=addr,
                            since_epoch=since,
                        )

                    token, used_pw = await signup_arena_email_account(
                        signup_email,
                        wait_for_verification_url=_wait_verif,
                        config=cfg,
                    )
                    if token:
                        cfg["managed_account"] = {
                            "provider": "email",
                            "address": signup_email,
                            "password": used_pw,
                            "created_at": int(time.time()),
                            "status": "active",
                        }
                except Exception as exc:
                    _main.debug_print(f"⚠️ Arena email auto-signup failed: {type(exc).__name__}: {exc}")
                    token = None

        if token and is_signed_in_arena_auth_token(token):
            _main.EPHEMERAL_ARENA_AUTH_TOKEN = token
            _persist_refreshed_auth_token(cfg, old_token, token)
            _main.debug_print("✅ Recovered signed-in arena-auth-prod-v1 session.")
            return token

        return None
